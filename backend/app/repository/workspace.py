"""Disposable per-analysis workspace management (TASK-051–054).

Workspaces are unique, unpredictable, and scoped to one analysis
(SECISO-701/702/704). Paths are never derived from repository-controlled
data. Cleanup is lifecycle-safe and strictly confined to the workspace
root; the stale sweep only touches own-prefix directories older than the
configured threshold and never active workspaces.
"""

from __future__ import annotations

import logging
import shutil
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger, log_event
from app.repository.errors import WorkspaceError

_logger = get_logger("workspace")

WORKSPACE_PREFIX = "ws-"


@dataclass
class CleanupReport:
    """Outcome of one workspace cleanup (best-effort, never raises)."""

    workspace: Path
    removed: bool = False
    reason: str = ""


@dataclass
class SweepReport:
    """Outcome of one stale-workspace sweep (idempotent, best-effort)."""

    examined: int = 0
    removed: list[str] = field(default_factory=list)
    kept_active: int = 0
    skipped_unknown: int = 0
    errors: list[str] = field(default_factory=list)


def _make_writable(function: object, path: str, excinfo: object) -> None:
    """shutil.rmtree error handler: clear read-only bits (git objects) and retry."""
    try:
        import os

        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        import pathlib

        target = pathlib.Path(path)
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(path, onerror=_make_writable)
        else:
            target.unlink(missing_ok=True)
    except OSError:
        pass


def remove_tree(path: Path) -> bool:
    """Best-effort recursive removal (read-only aware); True when gone."""
    try:
        shutil.rmtree(path, onerror=_make_writable)
    except OSError:
        return False
    return not path.exists()


class WorkspaceManager:
    """Create, contain, clean, and sweep analysis workspaces under one root."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        """Workspace root (owned by RepoLens, never the project tree)."""
        return self._root

    def create(self, analysis_id: str) -> Path:
        """Create a fresh unique workspace dir (name is a random id, not repo data)."""
        workspace = self._root / f"{WORKSPACE_PREFIX}{uuid.uuid4().hex}"
        workspace.mkdir(parents=True, exist_ok=False)
        log_event(
            _logger,
            logging.INFO,
            "workspace.created",
            "Analysis workspace created",
            analysis_id=analysis_id,
        )
        return workspace

    def resolve(self, workspace: Path, relpath: str) -> Path:
        """Resolve a repository-controlled relative path inside the workspace.

        Raises WorkspaceError on absolute paths, drive/UNC prefixes, or any
        resolved location outside the workspace (SECISO-802). String prefix
        checks alone are not used.
        """
        candidate = workspace / relpath
        try:
            resolved = candidate.resolve()
        except (ValueError, RuntimeError, OSError) as exc:
            raise WorkspaceError("Repository path could not be resolved safely.") from exc
        try:
            resolved.relative_to(workspace.resolve())
        except ValueError as exc:
            raise WorkspaceError("Repository path escapes the analysis workspace.") from exc
        return resolved

    def contains(self, workspace: Path, path: Path) -> bool:
        """True when ``path`` resolves inside ``workspace`` (no exception)."""
        try:
            path.resolve().relative_to(workspace.resolve())
        except (ValueError, RuntimeError, OSError):
            return False
        return True

    def cleanup(self, workspace: Path, analysis_id: str = "-") -> CleanupReport:
        """Remove one workspace; confined to the root, never raises.

        Refuses paths outside the root or not matching the workspace prefix,
        so cleanup can never delete unrelated directories.
        """
        report = CleanupReport(workspace=workspace)
        try:
            resolved = workspace.resolve()
        except (ValueError, RuntimeError, OSError):
            report.reason = "unresolvable path"
            self._log_cleanup(report, analysis_id, failed=True)
            return report
        if resolved == self._root:
            report.reason = "workspace root itself"
            self._log_cleanup(report, analysis_id, failed=True)
            return report
        # Only own-prefix directories directly under the root are ever removed.
        if resolved.parent != self._root or not resolved.name.startswith(WORKSPACE_PREFIX):
            report.reason = "not a managed workspace"
            self._log_cleanup(report, analysis_id, failed=True)
            return report
        try:
            shutil.rmtree(resolved, onerror=_make_writable)
            report.removed = not resolved.exists()
            report.reason = "" if report.removed else "partial removal"
        except OSError as exc:
            report.reason = f"removal failed: {type(exc).__name__}"
        self._log_cleanup(report, analysis_id, failed=not report.removed)
        return report

    def _log_cleanup(self, report: CleanupReport, analysis_id: str, failed: bool) -> None:
        log_event(
            _logger,
            logging.ERROR if failed else logging.INFO,
            "workspace.cleanup.failed" if failed else "workspace.cleanup.completed",
            "Workspace cleanup finished",
            analysis_id=analysis_id,
            removed=report.removed,
            reason=report.reason or "ok",
        )

    def sweep(
        self,
        active_paths: set[Path],
        stale_after_s: float,
        now_s: float | None = None,
    ) -> SweepReport:
        """Remove stale own-prefix workspaces (SECISO-1603); idempotent.

        Skips active workspaces, unknown names, and unreadable entries.
        Tolerates missing/partial/permission-failed removals without raising.
        """
        report = SweepReport()
        now = time.time() if now_s is None else now_s
        try:
            entries = list(self._root.iterdir())
        except OSError:
            return report
        active = set()
        for path in active_paths:
            try:
                active.add(path.resolve())
            except (ValueError, RuntimeError, OSError):
                continue
        for entry in entries:
            if not entry.name.startswith(WORKSPACE_PREFIX):
                report.skipped_unknown += 1
                continue
            report.examined += 1
            try:
                resolved = entry.resolve()
            except (ValueError, RuntimeError, OSError):
                report.errors.append(f"unresolvable: {entry.name}")
                continue
            if resolved in active:
                report.kept_active += 1
                continue
            try:
                age_s = now - entry.stat().st_mtime
            except OSError:
                report.errors.append(f"unstatable: {entry.name}")
                continue
            if age_s < stale_after_s:
                continue
            try:
                shutil.rmtree(resolved, onerror=_make_writable)
            except OSError as exc:
                report.errors.append(f"removal failed: {entry.name} ({type(exc).__name__})")
                continue
            if resolved.exists():
                report.errors.append(f"partial removal: {entry.name}")
            else:
                report.removed.append(entry.name)
        log_event(
            _logger,
            logging.INFO,
            "workspace.sweep.completed",
            "Workspace sweep finished",
            examined=report.examined,
            removed=len(report.removed),
            kept_active=report.kept_active,
        )
        return report
