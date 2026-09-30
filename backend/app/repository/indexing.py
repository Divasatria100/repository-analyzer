"""Safe repository tree traversal + file metadata indexing (TASK-056–060).

Reads the Phase 3 workspace snapshot as untrusted data: every entry is
classified from its own filesystem metadata before any decision is made,
nothing is followed, executed, or trusted by name. No network, no parsers,
no analyzers — output is an explicit indexed representation for later phases.

Key definitions (documented here because requirements leave them open):
- depth = number of ``/``-separated components in the repo-relative path
  (root-level ``a.py`` has depth 1); entries with depth > max_depth are
  not descended into / not indexed (SECISO-806);
- traversal order is name-sorted per directory (deterministic);
- binary = NUL byte in the first 8 KiB (extension never decides);
- only ``.repolens-git-control`` at the workspace root is skipped as
  RepoLens-owned infrastructure; every other dotfile is indexed normally;
- a ``.git`` entry anywhere is unexpected post-retrieval: skipped and
  recorded as a limitation (never traversed).
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger, log_event
from app.repositories import indexing as persistence
from app.repository.errors import IndexingError
from app.repository.index_types import IndexedFile, IndexResult, LimitationRecord

_logger = get_logger("indexing")

# Reparse-point flag (Windows st_file_attributes); junctions carry it.
_REPARSE_POINT = 0x400
# Bytes inspected for binary classification (bounded read, never persisted).
_SNIFF_BYTES = 8192
# RepoLens-owned control dir at the workspace root (not repository content).
_CONTROL_DIR_NAME = ".repolens-git-control"

# Extensions mapped to a detected language (lowercase, no dot). Detection is
# recognition only: every language except SUPPORTED_LANGUAGES is recorded as
# unsupported (docs/09 §10 — parser availability is not support).
_EXTENSION_LANGUAGES = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "java": "java",
    "php": "php",
    "go": "go",
    "rs": "rust",
    "rb": "ruby",
    "dart": "dart",
    "c": "c",
    "h": "c",  # documented choice: C/C++/ObjC headers detected as C
    "hpp": "cpp",
    "cpp": "cpp",
    "cc": "cpp",
    "cs": "csharp",
    "swift": "swift",
    "kt": "kotlin",
    "scala": "scala",
    "sh": "shell",
    "bash": "shell",
    "ps1": "powershell",
    "sql": "sql",
    "xml": "xml",
    "css": "css",
    "html": "html",
    "htm": "html",
    "json": "json",
    "yaml": "yaml",
    "yml": "yaml",
    "toml": "toml",
    "ini": "ini",
    "cfg": "ini",  # documented choice: treated as ini-style config
    "conf": "ini",  # documented choice: treated as ini-style config
    "md": "markdown",
    "markdown": "markdown",
    "rst": "rst",
}

# Extensions whose files are source code (vs data/config/docs).
_SOURCE_EXTENSIONS = frozenset(
    {
        "py",
        "js",
        "jsx",
        "ts",
        "tsx",
        "java",
        "php",
        "go",
        "rs",
        "rb",
        "dart",
        "c",
        "h",
        "hpp",
        "cpp",
        "cc",
        "cs",
        "swift",
        "kt",
        "scala",
        "sh",
        "bash",
        "ps1",
        "sql",
    }
)

# Exact basenames (lowercase) identifying dependency manifests (docs/09 §11.2).
_MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pyproject.toml",
        "poetry.lock",
        "pipfile.lock",
    }
)

# Exact basenames (lowercase) identifying configuration-like files.
_CONFIG_NAMES = frozenset({"dockerfile", "makefile", "gemfile", "rakefile", ".env"})

# Documentation extensions (language None; recognized kind, not source).
_DOCUMENTATION_EXTENSIONS = frozenset({"md", "markdown", "rst", "txt"})

# Generated-file markers (name heuristic, documented; flag only — the
# default treatment keeps the file included and records the choice).
_GENERATED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".bundle.css")
_GENERATED_SUBSTRING = "generated"

# The only V1.0 source-analysis support set (docs/09 §10.2: Python only).
SUPPORTED_LANGUAGES = frozenset({"python"})


class EntryKind(StrEnum):
    """Filesystem entry kinds distinguished before any traversal decision."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    JUNCTION = "junction"
    SPECIAL = "special"


class Scannable(Protocol):
    """Minimal surface used for classification (os.DirEntry satisfies it)."""

    @property
    def name(self) -> str: ...
    @property
    def path(self) -> str: ...
    def is_symlink(self) -> bool: ...
    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result: ...


@dataclass(frozen=True)
class RawEntry:
    """One classified workspace entry (metadata only, content untouched)."""

    relative_path: str  # posix, relative to workspace root
    kind: EntryKind
    size: int | None  # regular files only, from stat (no content read)
    link_target: str | None  # symlinks only, via readlink (never followed)
    depth: int  # number of '/' components; root-level file has depth 1


def _is_reparse_point(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def classify_entry(entry: Scannable) -> EntryKind:
    """Classify from the entry's own metadata; never follows anything."""
    try:
        if entry.is_symlink():
            return EntryKind.SYMLINK
    except OSError:
        return EntryKind.SPECIAL
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        # Cannot stat: cannot handle safely → special (skipped with reason).
        return EntryKind.SPECIAL
    if stat.S_ISDIR(st.st_mode):
        if _is_reparse_point(st):
            return EntryKind.JUNCTION
        return EntryKind.DIRECTORY
    if stat.S_ISREG(st.st_mode):
        return EntryKind.FILE
    return EntryKind.SPECIAL


def _extension_of(name: str) -> str:
    suffix = PurePosixPath(name.lower()).suffix
    return suffix[1:] if suffix.startswith(".") else ""


def detect_language(relative_path: str) -> str | None:
    """Static extension-based language recognition (never executes/imports)."""
    return _EXTENSION_LANGUAGES.get(_extension_of(PurePosixPath(relative_path).name))


def _is_manifest(basename: str) -> bool:
    lowered = basename.lower()
    if lowered in _MANIFEST_NAMES:
        return True
    return lowered == "requirements.txt" or (
        lowered.startswith("requirements") and lowered.endswith(".txt")
    )


def _classify_role(relative_path: str, extension: str) -> str:
    """Assign the file-type role (manifest/configuration/docs/source/other)."""
    basename = PurePosixPath(relative_path).name.lower()
    if _is_manifest(basename):
        return "manifest"
    if basename in _CONFIG_NAMES:
        return "configuration"
    language = _EXTENSION_LANGUAGES.get(extension)
    if language is not None:
        if extension in _SOURCE_EXTENSIONS:
            return "source"
        if extension in _DOCUMENTATION_EXTENSIONS:
            return "documentation"
        return "configuration"
    if extension in _DOCUMENTATION_EXTENSIONS:
        return "documentation"
    return "other"


def _is_generated(basename: str) -> bool:
    lowered = basename.lower()
    return lowered.endswith(_GENERATED_SUFFIXES) or _GENERATED_SUBSTRING in lowered


def is_binary_content(path: Path, size: int) -> bool:
    """NUL-byte heuristic over a bounded prefix (content as data only)."""
    if size <= 0:
        return False
    with path.open("rb") as handle:
        return b"\x00" in handle.read(_SNIFF_BYTES)


def walk_workspace(
    root: Path, *, max_files: int, max_depth: int
) -> tuple[list[RawEntry], list[LimitationRecord], bool]:
    """Enumerate the workspace deterministically (name-sorted, no follows).

    Returns (entries, limitations, complete). Stops at the file-count limit
    instead of continuing indefinitely; skipped subtrees/entries are recorded,
    never silently dropped. Counts every entry that becomes a File record
    (regular files + recorded links) against max_files.
    """
    entries: list[RawEntry] = []
    limitations: list[LimitationRecord] = []
    complete = True
    record_count = 0
    try:
        resolved_root = root.resolve()
    except (ValueError, RuntimeError, OSError):
        return entries, limitations, False

    def exceeded() -> bool:
        return record_count >= max_files

    def stop_incomplete() -> tuple[list[RawEntry], list[LimitationRecord], bool]:
        limitations.append(
            LimitationRecord(
                scope_kind="index",
                file_path=None,
                reason=("index.max_files limit reached; indexing stopped, index incomplete"),
            )
        )
        entries.sort(key=lambda entry: entry.relative_path)
        return entries, limitations, False

    def within_root(candidate: Path) -> bool:
        """Defense in depth: containment via resolved paths (aliases included).

        Traversal joins single-component names, which cannot escape by
        construction; this check additionally defeats alias tricks such as
        Windows 8.3 short names.
        """
        try:
            candidate.resolve().relative_to(resolved_root)
        except (ValueError, RuntimeError, OSError):
            return False
        return True

    # Iterative stack; children pushed in reverse so pop() yields sorted order.
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]
    while stack:
        directory, rel_prefix, dir_depth = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            limitations.append(
                LimitationRecord(
                    scope_kind="index",
                    file_path=rel_prefix or None,
                    reason="directory could not be listed; subtree skipped",
                )
            )
            complete = False
            continue
        for child in children:
            name = child.name
            relpath = f"{rel_prefix}/{name}" if rel_prefix else name
            depth = dir_depth + 1
            if depth > max_depth:
                limitations.append(
                    LimitationRecord(
                        scope_kind="index",
                        file_path=relpath,
                        reason=(
                            "content beyond index.max_depth "
                            f"({max_depth} levels); recorded as not analyzed"
                        ),
                    )
                )
                complete = False
                continue
            kind = classify_entry(child)
            if kind in (EntryKind.FILE, EntryKind.DIRECTORY) and not within_root(Path(child.path)):
                limitations.append(
                    LimitationRecord(
                        scope_kind="index",
                        file_path=relpath,
                        reason="entry outside workspace root; rejected, not followed",
                    )
                )
                complete = False
                continue
            if kind is EntryKind.DIRECTORY:
                if name == ".git":
                    limitations.append(
                        LimitationRecord(
                            scope_kind="index",
                            file_path=relpath,
                            reason="unexpected git metadata skipped; not traversed",
                        )
                    )
                    complete = False
                    continue
                if dir_depth == 0 and name == _CONTROL_DIR_NAME:
                    # RepoLens-owned control dir (retrieval scaffolding), not
                    # repository content: skipped without a limitation record.
                    continue
                stack.append((Path(child.path), relpath, depth))
                continue
            if kind is EntryKind.SYMLINK:
                if exceeded():
                    return stop_incomplete()
                try:
                    target = os.readlink(child.path)
                except OSError:
                    target = ""
                entries.append(
                    RawEntry(
                        relative_path=relpath,
                        kind=kind,
                        size=None,
                        link_target=target,
                        depth=depth,
                    )
                )
                record_count += 1
                continue
            if kind is EntryKind.JUNCTION:
                if exceeded():
                    return stop_incomplete()
                entries.append(
                    RawEntry(
                        relative_path=relpath,
                        kind=kind,
                        size=None,
                        link_target=None,
                        depth=depth,
                    )
                )
                record_count += 1
                continue
            if kind is EntryKind.SPECIAL:
                limitations.append(
                    LimitationRecord(
                        scope_kind="file",
                        file_path=relpath,
                        reason="special file recorded as not analyzed; not opened",
                    )
                )
                continue
            # Regular file.
            if exceeded():
                return stop_incomplete()
            try:
                size = child.stat(follow_symlinks=False).st_size
            except OSError:
                limitations.append(
                    LimitationRecord(
                        scope_kind="file",
                        file_path=relpath,
                        reason="file could not be inspected during indexing",
                    )
                )
                complete = False
                continue
            entries.append(
                RawEntry(relative_path=relpath, kind=kind, size=size, link_target=None, depth=depth)
            )
            record_count += 1
    # Globally sorted output: stable across runs regardless of traversal shape.
    entries.sort(key=lambda entry: entry.relative_path)
    return entries, limitations, complete


def classify_file(workspace: Path, entry: RawEntry, *, file_max_bytes: int) -> IndexedFile:
    """Build the IndexedFile for one entry (bounded content sniff only)."""
    basename = PurePosixPath(entry.relative_path).name
    extension = _extension_of(basename)

    if entry.kind is EntryKind.SYMLINK:
        return IndexedFile(
            relative_path=entry.relative_path,
            file_type="link",
            extension=extension,
            size=0,
            language=None,
            support_status="unsupported",
            is_binary=False,
            is_generated=False,
            excluded=False,
            exclusion_reason=None,
            eligibility="not_eligible",
            eligibility_reason="symbolic link recorded as link; not followed",
            indexing_limitation=None,
        )

    if entry.kind is EntryKind.JUNCTION:
        return IndexedFile(
            relative_path=entry.relative_path,
            file_type="link",
            extension=extension,
            size=0,
            language=None,
            support_status="unsupported",
            is_binary=False,
            is_generated=False,
            excluded=False,
            exclusion_reason=None,
            eligibility="not_eligible",
            eligibility_reason="junction/reparse point recorded as link; not followed",
            indexing_limitation=None,
        )

    assert entry.size is not None  # regular files always carry stat size
    role = _classify_role(entry.relative_path, extension)
    generated = _is_generated(basename)
    language = detect_language(entry.relative_path)

    if language in SUPPORTED_LANGUAGES:
        support_status = "supported"
    elif language is not None or role in ("manifest", "configuration", "documentation"):
        # Recognized kind/format without a source-analysis path.
        support_status = "unsupported"
    else:
        support_status = "unrecognized"

    if entry.size > file_max_bytes:
        return IndexedFile(
            relative_path=entry.relative_path,
            file_type=role,
            extension=extension,
            size=entry.size,
            language=language,
            support_status=support_status,
            is_binary=False,
            is_generated=generated,
            excluded=False,
            exclusion_reason=None,
            eligibility="not_eligible",
            eligibility_reason=(
                f"exceeds file.max_size_bytes ({file_max_bytes} bytes); "
                "content not read, recorded as not analyzed"
            ),
            indexing_limitation="content not read: file exceeds size limit",
        )

    try:
        binary = is_binary_content(workspace / entry.relative_path, entry.size)
    except OSError:
        return IndexedFile(
            relative_path=entry.relative_path,
            file_type=role,
            extension=extension,
            size=entry.size,
            language=language,
            support_status=support_status,
            is_binary=False,
            is_generated=generated,
            excluded=False,
            exclusion_reason=None,
            eligibility="not_eligible",
            eligibility_reason="content unreadable; recorded as not analyzed",
            indexing_limitation="file could not be inspected during indexing",
        )

    if binary:
        return IndexedFile(
            relative_path=entry.relative_path,
            file_type=role,
            extension=extension,
            size=entry.size,
            language=language,
            support_status="binary",
            is_binary=True,
            is_generated=generated,
            excluded=False,
            exclusion_reason=None,
            eligibility="not_eligible",
            eligibility_reason="binary file recorded as not analyzed",
            indexing_limitation=None,
        )

    if support_status == "supported":
        reason = "supported source file; parser may consider"
        if generated:
            reason += "; generated file included per default treatment"
        return IndexedFile(
            relative_path=entry.relative_path,
            file_type=role,
            extension=extension,
            size=entry.size,
            language=language,
            support_status=support_status,
            is_binary=False,
            is_generated=generated,
            excluded=False,
            exclusion_reason=None,
            eligibility="eligible",
            eligibility_reason=reason,
            indexing_limitation=None,
        )

    if role == "manifest":
        reason = "dependency manifest; reserved for dependency analysis, not source parsing"
    elif role == "configuration":
        reason = "configuration file; reserved for configuration/text rules, not source parsing"
    elif role == "documentation":
        reason = "documentation; not analyzed as source"
    elif language is not None:
        reason = f"language {language} not supported for source analysis; recorded as not analyzed"
    else:
        reason = "unrecognized language/format; recorded as not analyzed"
    return IndexedFile(
        relative_path=entry.relative_path,
        file_type=role,
        extension=extension,
        size=entry.size,
        language=language,
        support_status=support_status,
        is_binary=False,
        is_generated=generated,
        excluded=False,
        exclusion_reason=None,
        eligibility="not_eligible",
        eligibility_reason=reason,
        indexing_limitation=None,
    )


def index_workspace(
    *,
    workspace: Path,
    analysis_id: str,
    settings: Settings,
    session: Session,
) -> IndexResult:
    """Index one retrieved workspace and persist File + Limitation rows.

    Traversal, classification, language detection, and eligibility run in one
    pass; all rows persist atomically. Raises IndexingError (workspace
    missing/inaccessible/unexpected failure) — never a partial success.
    Limit-driven incompleteness is recorded, not raised: the result carries
    complete=False and the analysis continues toward parsing with explicit
    limitations.
    """
    if not workspace.is_dir():
        raise IndexingError("The analysis workspace is unavailable for indexing.")
    operational = settings.operational
    log_event(
        _logger,
        logging.INFO,
        "indexing.started",
        "File indexing started",
        analysis_id=analysis_id,
    )
    try:
        entries, limitations, complete = walk_workspace(
            workspace,
            max_files=operational.index_max_files,
            max_depth=operational.index_max_depth,
        )
        files = [
            classify_file(workspace, entry, file_max_bytes=operational.file_max_size_bytes)
            for entry in entries
        ]
        total_bytes = sum(item.size for item in files)
        if total_bytes > operational.repo_max_size_bytes:
            limitations.append(
                LimitationRecord(
                    scope_kind="index",
                    file_path=None,
                    reason=("repository content exceeds repo.max_size_bytes; index incomplete"),
                )
            )
            complete = False
        result = IndexResult(
            files=files, limitations=limitations, complete=complete, total_bytes=total_bytes
        )
        persistence.save_index(session, analysis_id, files, limitations)
    except IndexingError:
        raise
    except Exception as exc:
        log_event(
            _logger,
            logging.ERROR,
            "indexing.failed",
            "File indexing failed",
            analysis_id=analysis_id,
            reason=type(exc).__name__,
        )
        raise IndexingError("The repository index could not be built.") from exc
    if not complete:
        log_event(
            _logger,
            logging.WARNING,
            "indexing.limit_reached",
            "File indexing incomplete: a repository limit was reached",
            analysis_id=analysis_id,
        )
    log_event(
        _logger,
        logging.INFO,
        "indexing.completed",
        "File indexing completed",
        analysis_id=analysis_id,
        files=len(files),
        limitations=len(limitations),
        complete=complete,
    )
    return result
