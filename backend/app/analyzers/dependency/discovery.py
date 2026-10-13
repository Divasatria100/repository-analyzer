"""Dependency manifest discovery (TASK-112).

Finds the six V1.0 formats (plus ``requirements*.txt`` variants per
docs/09 §11.2) from the Phase 4 file index, resolved against the analysis
workspace. GitHub is never re-fetched; symlinks are never followed;
traversal never leaves the workspace.
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.analyzers.dependency.models import ManifestKind, ManifestRef
from app.core.logging import get_logger, log_event

_logger = get_logger("analyzers.dependency.discovery")

#: Canonical discovery table: basename (lowercase) -> (kind, format, ecosystem).
_MANIFEST_TABLE: dict[str, tuple[ManifestKind, str, str]] = {
    "requirements.txt": (ManifestKind.MANIFEST, "requirements_txt", "pypi"),
    "pyproject.toml": (ManifestKind.MANIFEST, "pyproject_toml", "pypi"),
    "poetry.lock": (ManifestKind.LOCKFILE, "poetry_lock", "pypi"),
    "pipfile.lock": (ManifestKind.LOCKFILE, "pipfile_lock", "pypi"),
    "package.json": (ManifestKind.MANIFEST, "package_json", "npm"),
    "package-lock.json": (ManifestKind.LOCKFILE, "package_lock_json", "npm"),
}


def classify_manifest_name(basename: str) -> tuple[ManifestKind, str, str] | None:
    """Classify a file basename; ``requirements*.txt`` variants are manifests."""
    lowered = basename.lower()
    if lowered in _MANIFEST_TABLE:
        return _MANIFEST_TABLE[lowered]
    if lowered.startswith("requirements") and lowered.endswith(".txt"):
        return (ManifestKind.MANIFEST, "requirements_txt", "pypi")
    return None


def project_context_for(path: str) -> str:
    """Parent directory of a repository-relative path ("" for root)."""
    parent = str(PurePosixPath(path).parent)
    return "" if parent in (".", "/") else parent


@dataclass
class DiscoveryResult:
    """Discovered manifests plus explicit limitations (never silent drops)."""

    manifests: list[ManifestRef] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def discover_from_index(
    indexed_paths: list[str],
    *,
    workspace: Path | None = None,
    workspaces: object | None = None,
    file_max_bytes: int | None = None,
) -> DiscoveryResult:
    """Discover manifests from file-index paths (deterministic, safe).

    ``indexed_paths`` are repository-relative paths from the Phase 4 index.
    When ``workspace``/``workspaces`` are given, each candidate is verified
    against the workspace: containment is enforced via the manager's
    ``resolve``, symlinks and non-regular files are rejected via ``lstat``
    (never followed), binary files are skipped, and oversized files are
    recorded as limitations (never silently dropped).
    """
    result = DiscoveryResult()
    seen: set[str] = set()
    for raw in sorted(set(indexed_paths)):
        normalized = raw.replace("\\", "/").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        classification = classify_manifest_name(PurePosixPath(normalized).name)
        if classification is None:
            continue
        kind, format_name, ecosystem = classification
        if workspace is not None and workspaces is not None:
            check = _workspace_check(workspace, workspaces, normalized, file_max_bytes)
            if check is not None:
                reason, skip = check
                if skip:
                    result.skipped.append(normalized)
                result.limitations.append(f"{normalized}: {reason}")
                continue
        result.manifests.append(
            ManifestRef(
                path=normalized,
                kind=kind,
                format=format_name,
                ecosystem=ecosystem,
                project_context=project_context_for(normalized),
            )
        )
    result.manifests.sort(key=lambda ref: ref.path)
    log_event(
        _logger,
        logging.INFO,
        "dependency.discovery.completed",
        "Dependency manifest discovery completed",
        manifests=len(result.manifests),
        limitations=len(result.limitations),
    )
    return result


def _workspace_check(
    workspace: Path,
    workspaces: object,
    relpath: str,
    file_max_bytes: int | None,
) -> tuple[str, bool] | None:
    """Verify one candidate against the workspace; None means acceptable."""
    resolve = getattr(workspaces, "resolve", None)
    if resolve is None:
        return ("workspace resolution unavailable; recorded as not analyzed", False)
    try:
        resolve(workspace, relpath)
    except Exception:
        return ("path escapes the workspace; rejected, not followed", True)
    try:
        entry_stat = os.lstat(workspace / relpath)
    except OSError:
        return ("file could not be inspected; recorded as not analyzed", False)
    if stat.S_ISLNK(entry_stat.st_mode):
        return ("symbolic link recorded as link; not followed", True)
    if not stat.S_ISREG(entry_stat.st_mode):
        return ("special file recorded as not analyzed; not opened", True)
    if file_max_bytes is not None and entry_stat.st_size > file_max_bytes:
        return (
            f"exceeds file.max_size_bytes ({file_max_bytes} bytes); "
            "content not read, recorded as not analyzed",
            False,
        )
    try:
        with open(workspace / relpath, "rb") as handle:
            if b"\x00" in handle.read(8192):
                return ("binary file recorded as not analyzed", True)
    except OSError:
        return ("file could not be inspected; recorded as not analyzed", False)
    return None


def index_paths_from_ncm(ncm: object) -> list[str]:
    """Extract repository-relative paths from an NCM repository snapshot."""
    files = getattr(ncm, "files", [])
    return [entry.path for entry in files if getattr(entry, "path", None)]
