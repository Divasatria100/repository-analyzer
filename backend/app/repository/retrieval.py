"""Safe repository retrieval at a resolved immutable commit (TASK-046–050).

Mechanism: ``git clone --no-checkout`` into a workspace-local metadata dir,
then ``git archive <sha>`` streamed through a containment-checked extractor.
No worktree checkout ever runs, so repository-controlled checkout-time
behavior has no execution path (see ``git_security`` notes below).

Security properties (docs/15 §5–6):
- argv lists only, never shell; ``shell=True`` is never used;
- safe environment: blanked git config files, no hooks/filters/credential
  helpers, no submodule recursion, no prompts, file protocol denied;
- content treated as data: archive bytes are extracted with path containment,
  symlink/special-file rejection, and incremental size/count/depth caps;
- timeouts from net.retrieval_total_s; retries (net.retries_retrieval) apply
  to transient transport failures only — never to validation, size, or
  security failures;
- partial content is never presented as complete: any failure raises, and the
  caller must clean up the workspace (orchestrator owns cleanup).
"""

from __future__ import annotations

import os
import re
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, cast

from app.core.config import Settings
from app.core.logging import get_logger, log_event
from app.repository.errors import (
    RetrievalError,
    RetrievalIncompleteError,
    RetrievalSecurityError,
    RetrievalSizeLimitError,
    RetrievalTimeoutError,
    RetrievalTransportError,
)
from app.repository.identity import RepositoryIdentity
from app.repository.workspace import remove_tree

_logger = get_logger("retrieval")

_GIT_BINARY = "git"
_CLONE_DIR_NAME = ".repolens-git"
_HOOKS_DIR_NAME = ".repolens-no-hooks"
_EMPTY_CONFIG_NAME = ".repolens-empty-config"
_READ_CHUNK_BYTES = 64 * 1024

# stderr fragments indicating a transient transport problem (safe to retry).
_TRANSIENT_MARKERS = (
    "could not resolve host",
    "unable to connect",
    "connection timed out",
    "connection reset",
    "network is unreachable",
    "the remote end hung up unexpectedly",
    "timed out",
    "connection refused",
)

# stderr fragments indicating a deterministic failure (never retried).
_NOT_FOUND_MARKERS = ("repository not found", "not found", "could not read from remote")
_AUTH_MARKERS = ("authentication failed", "invalid username", "permission denied", "401", "403")


class RetrievalStatus(StrEnum):
    """Lifecycle of one retrieval attempt (docs/10 §7.1 surrounding states)."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ExtractionLimits:
    """Incremental enforcement caps (values from centralized settings)."""

    max_total_bytes: int
    max_file_bytes: int
    max_files: int
    max_depth: int


@dataclass
class ExtractionReport:
    """Outcome of one archive extraction (data only, no analysis)."""

    files_extracted: int = 0
    bytes_extracted: int = 0
    skipped_entries: list[str] = field(default_factory=list)
    submodules_present: bool = False


@dataclass
class RetrievalResult:
    """Completed retrieval snapshot pointer (content lives in the workspace)."""

    status: RetrievalStatus
    identity: RepositoryIdentity
    commit_sha: str
    workspace: Path
    files_extracted: int = 0
    bytes_extracted: int = 0
    skipped_entries: list[str] = field(default_factory=list)
    submodules_present: bool = False
    duration_s: float = 0.0


def build_safe_git_env(
    *,
    path_value: str,
    home_dir: Path,
    xdg_config_dir: Path,
    empty_config_file: Path,
    ceiling_dir: Path,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Minimal environment neutralizing repository-controlled git behavior.

    Blank user/system config files, disable prompts, and confine repository
    discovery. Only PATH-like inheritance the caller explicitly passes is
    kept — no ambient GIT_* variables ever propagate.
    """
    env: dict[str, str] = {"PATH": path_value}
    if extra:
        env.update(extra)
    env.update(
        {
            "HOME": str(home_dir),
            "XDG_CONFIG_HOME": str(xdg_config_dir),
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(empty_config_file),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CEILING_DIRECTORIES": str(ceiling_dir),
        }
    )
    return env


def build_clone_command(
    remote_url: str,
    dest_dir: Path,
    hooks_dir: Path,
    *,
    allow_local_paths: bool = False,
) -> list[str]:
    """argv for a non-checkout, non-recursive clone (no shell, no hooks).

    ``allow_local_paths`` exists ONLY so tests can clone local fixture repos;
    production calls must leave it False (protocol.file.allow=never).
    """
    file_policy = "always" if allow_local_paths else "never"
    return [
        _GIT_BINARY,
        "-c",
        f"core.hooksPath={hooks_dir}",
        "-c",
        "credential.helper=",
        "-c",
        f"protocol.file.allow={file_policy}",
        "clone",
        "--no-checkout",
        "--no-recurse-submodules",
        remote_url,
        str(dest_dir),
    ]


def build_rev_parse_command(repo_dir: Path, sha: str) -> list[str]:
    """argv verifying the exact commit object exists locally."""
    return [_GIT_BINARY, "-C", str(repo_dir), "cat-file", "-e", f"{sha}^{{commit}}"]


def build_archive_command(repo_dir: Path, sha: str) -> list[str]:
    """argv streaming ``git archive`` tar bytes for the exact SHA."""
    return [_GIT_BINARY, "-C", str(repo_dir), "archive", "--format=tar", sha]


def classify_git_failure(stderr: str) -> RetrievalError:
    """Map git stderr to a retryable or deterministic retrieval error."""
    lowered = stderr.lower()
    if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
        return RetrievalIncompleteError(
            "The repository content could not be found and was not analyzed."
        )
    if any(marker in lowered for marker in _AUTH_MARKERS):
        return RetrievalIncompleteError(
            "The repository content is not accessible and was not analyzed."
        )
    if any(marker in lowered for marker in _TRANSIENT_MARKERS):
        return RetrievalTransportError()
    return RetrievalIncompleteError("The repository could not be downloaded and was not analyzed.")


def check_remote_size(size_bytes: int | None, max_bytes: int) -> None:
    """Early size evaluation before any retrieval (NFR-042, SECISO-903)."""
    if size_bytes is not None and size_bytes > max_bytes:
        raise RetrievalSizeLimitError()


def _is_unsafe_member_name(name: str) -> bool:
    if not name or name in {".", "/"}:
        return True
    if name.startswith(("/", "\\")):
        return True
    if re.match(r"^[A-Za-z]:", name):
        return True
    if name.startswith("\\\\"):
        return True
    return False


def extract_tar_stream(stream: BinaryIO, dest: Path, limits: ExtractionLimits) -> ExtractionReport:
    """Extract tar bytes with containment + incremental caps (content as data).

    Rejects absolute/drive/UNC/escaping paths, never creates symlinks,
    hardlinks, or special files (records them as skipped), and enforces
    per-file, total-bytes, file-count, and depth limits as data arrives —
    never truncating silently into a complete-looking result.
    """
    report = ExtractionReport()
    resolved_dest = dest.resolve()
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            _extract_member(archive, member, resolved_dest, limits, report)
    return report


def _extract_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    resolved_dest: Path,
    limits: ExtractionLimits,
    report: ExtractionReport,
) -> None:
    name = member.name
    if _is_unsafe_member_name(name):
        report.skipped_entries.append(name)
        return
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if not parts or len(parts) > limits.max_depth:
        report.skipped_entries.append(name)
        return
    target = resolved_dest.joinpath(*parts)
    try:
        target.resolve().relative_to(resolved_dest)
    except (ValueError, RuntimeError, OSError):
        report.skipped_entries.append(name)
        return
    if name == ".gitmodules" or name.endswith("/.gitmodules"):
        report.submodules_present = True
    if member.isdir():
        target.mkdir(parents=True, exist_ok=True)
        return
    if not member.isfile():
        # Symlinks, hardlinks, devices, FIFOs, sockets: recorded, never created.
        report.skipped_entries.append(name)
        return
    if member.size > limits.max_file_bytes:
        raise RetrievalSizeLimitError()
    report.files_extracted += 1
    if report.files_extracted > limits.max_files:
        raise RetrievalSizeLimitError()
    target.parent.mkdir(parents=True, exist_ok=True)
    extracted = archive.extractfile(member)
    if extracted is None:
        report.skipped_entries.append(name)
        report.files_extracted -= 1
        return
    with target.open("wb") as handle:
        while True:
            chunk = extracted.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            report.bytes_extracted += len(chunk)
            if report.bytes_extracted > limits.max_total_bytes:
                raise RetrievalSizeLimitError()
            handle.write(chunk)


def _run_git(
    argv: list[str], env: dict[str, str], timeout_s: float
) -> subprocess.CompletedProcess[str]:
    """Run one git argv list: no shell, captured output, enforced timeout."""
    try:
        return subprocess.run(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RetrievalTimeoutError() from exc
    except OSError as exc:
        raise RetrievalTransportError() from exc


class RetrievalService:
    """Clone-at-SHA + archive extraction with limits (infrastructure)."""

    def __init__(
        self,
        *,
        repo_max_bytes: int,
        file_max_bytes: int,
        max_files: int,
        max_depth: int,
        storage_max_bytes: int,
        retrieval_timeout_s: float,
        max_retries: int,
    ) -> None:
        self._repo_max_bytes = repo_max_bytes
        self._file_max_bytes = file_max_bytes
        self._max_files = max_files
        self._max_depth = max_depth
        self._storage_max_bytes = storage_max_bytes
        self._retrieval_timeout_s = retrieval_timeout_s
        self._max_retries = max_retries

    @classmethod
    def from_settings(cls, settings: Settings) -> RetrievalService:
        """Build from the centralized operational/network values (no literals)."""
        operational = settings.operational
        network = settings.network
        return cls(
            repo_max_bytes=operational.repo_max_size_bytes,
            file_max_bytes=operational.file_max_size_bytes,
            max_files=operational.index_max_files,
            max_depth=operational.index_max_depth,
            storage_max_bytes=operational.analysis_storage_max_mb * 1024 * 1024,
            retrieval_timeout_s=network.retrieval_total_s,
            max_retries=network.retries_retrieval,
        )

    def _limits(self) -> ExtractionLimits:
        return ExtractionLimits(
            max_total_bytes=min(self._repo_max_bytes, self._storage_max_bytes),
            max_file_bytes=self._file_max_bytes,
            max_files=self._max_files,
            max_depth=self._max_depth,
        )

    def _base_env(self, workspace: Path) -> dict[str, str]:
        path_value = os.environ.get("PATH", "")
        extra: dict[str, str] = {}
        if "SYSTEMROOT" in os.environ:
            extra["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        for key in ("TEMP", "TMP", "TMPDIR"):
            if key in os.environ:
                extra[key] = os.environ[key]
        control_dir = workspace / ".repolens-git-control"
        control_dir.mkdir(parents=True, exist_ok=True)
        hooks_dir = control_dir / _HOOKS_DIR_NAME
        hooks_dir.mkdir(exist_ok=True)
        empty_config = control_dir / _EMPTY_CONFIG_NAME
        empty_config.write_text("", encoding="utf-8")
        return build_safe_git_env(
            path_value=path_value,
            home_dir=control_dir,
            xdg_config_dir=control_dir,
            empty_config_file=empty_config,
            ceiling_dir=workspace,
            extra=extra,
        )

    def retrieve(
        self,
        *,
        identity: RepositoryIdentity,
        commit_sha: str,
        workspace: Path,
        remote_url: str | None = None,
        allow_local_paths: bool = False,
    ) -> RetrievalResult:
        """Retrieve exactly ``commit_sha`` into ``workspace`` (data only).

        ``remote_url`` defaults to the identity-derived clone URL; tests pass a
        local fixture path (requires ``allow_local_paths=True``). Raises a
        RetrievalError subclass on any failure; partial content is never
        returned as complete.
        """
        started = time.monotonic()
        deadline = started + self._retrieval_timeout_s
        remote = remote_url or identity.clone_url
        log_event(
            _logger,
            20,
            "repository.retrieval.started",
            "Retrieving repository snapshot",
            repository=identity.full_name,
        )
        clone_dir = workspace / _CLONE_DIR_NAME
        hooks_dir = workspace / ".repolens-git-control" / _HOOKS_DIR_NAME
        env = self._base_env(workspace)
        attempts = 1 + max(0, self._max_retries)
        last_error: RetrievalError | None = None
        for attempt in range(attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RetrievalTimeoutError()
            try:
                return self._attempt(
                    identity,
                    commit_sha,
                    workspace,
                    remote,
                    clone_dir,
                    hooks_dir,
                    env,
                    remaining,
                    allow_local_paths,
                )
            except RetrievalError as exc:
                if not exc.retryable or attempt >= attempts - 1:
                    self._cleanup_clone_dir(clone_dir)
                    self._log_failed(identity, exc)
                    raise
                last_error = exc
        assert last_error is not None
        self._cleanup_clone_dir(clone_dir)
        self._log_failed(identity, last_error)
        raise last_error

    def _attempt(
        self,
        identity: RepositoryIdentity,
        commit_sha: str,
        workspace: Path,
        remote: str,
        clone_dir: Path,
        hooks_dir: Path,
        env: dict[str, str],
        timeout_s: float,
        allow_local_paths: bool,
    ) -> RetrievalResult:
        started = time.monotonic()
        self._cleanup_clone_dir(clone_dir)
        clone = _run_git(
            build_clone_command(remote, clone_dir, hooks_dir, allow_local_paths=allow_local_paths),
            env,
            timeout_s,
        )
        if clone.returncode != 0:
            raise classify_git_failure(clone.stderr)
        remaining = timeout_s - (time.monotonic() - started)
        if remaining <= 0:
            raise RetrievalTimeoutError()
        verify = _run_git(build_rev_parse_command(clone_dir, commit_sha), env, remaining)
        if verify.returncode != 0:
            raise RetrievalSecurityError(
                "The resolved commit is not present in the retrieved repository."
            )
        remaining = timeout_s - (time.monotonic() - started)
        if remaining <= 0:
            raise RetrievalTimeoutError()
        try:
            archive = subprocess.Popen(
                build_archive_command(clone_dir, commit_sha),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )
        except OSError as exc:
            raise RetrievalTransportError() from exc
        try:
            assert archive.stdout is not None
            report = extract_tar_stream(cast(BinaryIO, archive.stdout), workspace, self._limits())
            _, stderr = archive.communicate(timeout=remaining)
        except RetrievalError:
            archive.kill()
            archive.wait()
            raise
        except (subprocess.TimeoutExpired, OSError) as exc:
            archive.kill()
            archive.wait()
            raise RetrievalTimeoutError() from exc
        if archive.returncode != 0:
            raise classify_git_failure((stderr or b"").decode("utf-8", "replace"))
        self._cleanup_clone_dir(clone_dir)
        duration = time.monotonic() - started
        log_event(
            _logger,
            20,
            "repository.retrieval.completed",
            "Repository snapshot retrieved",
            repository=identity.full_name,
            files=report.files_extracted,
        )
        return RetrievalResult(
            status=RetrievalStatus.COMPLETED,
            identity=identity,
            commit_sha=commit_sha,
            workspace=workspace,
            files_extracted=report.files_extracted,
            bytes_extracted=report.bytes_extracted,
            skipped_entries=report.skipped_entries,
            submodules_present=report.submodules_present,
            duration_s=duration,
        )

    def _cleanup_clone_dir(self, clone_dir: Path) -> None:
        if clone_dir.exists() or clone_dir.is_symlink():
            remove_tree(clone_dir)

    def _log_failed(self, identity: RepositoryIdentity, exc: RetrievalError) -> None:
        log_event(
            _logger,
            40,
            "repository.retrieval.failed",
            "Repository retrieval failed",
            repository=identity.full_name,
            reason=type(exc).__name__,
        )
