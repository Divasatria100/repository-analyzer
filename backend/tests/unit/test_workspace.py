"""Workspace tests: isolation, containment, cleanup, sweep (TASK-051–054)."""

import os
import time
from pathlib import Path

import pytest

from app.repository.errors import WorkspaceError
from app.repository.workspace import WORKSPACE_PREFIX, WorkspaceManager

pytestmark = pytest.mark.security


def _manager(tmp_path: Path) -> WorkspaceManager:
    return WorkspaceManager(tmp_path / "workspaces")


def test_create_unique_unpredictable_not_derived(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    first = manager.create("analysis-1")
    second = manager.create("analysis-1")
    assert first != second
    assert first.parent == manager.root
    assert "acme" not in first.name and "analysis-1" not in first.name


def test_resolve_containment(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    workspace = manager.create("a")
    assert manager.resolve(workspace, "pkg/mod.py") == workspace / "pkg" / "mod.py"
    assert manager.contains(workspace, workspace / "x.py") is True
    for hostile in ("../evil.py", "/absolute.py", "C:/win.py", "\\\\unc\\s.py", "a/../../b.py"):
        with pytest.raises(WorkspaceError):
            manager.resolve(workspace, hostile)
        assert manager.contains(workspace, Path(hostile)) is False


def test_cleanup_success_and_refusals(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    workspace = manager.create("a")
    (workspace / "f.py").write_text("x", encoding="utf-8")
    report = manager.cleanup(workspace, "a")
    assert report.removed is True and workspace.exists() is False

    outside = tmp_path / "outside"
    outside.mkdir()
    refused = manager.cleanup(outside, "a")
    assert refused.removed is False and outside.exists() is True

    refused_root = manager.cleanup(manager.root, "a")
    assert refused_root.removed is False and manager.root.exists() is True


def test_cleanup_failure_still_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil

    manager = _manager(tmp_path)
    workspace = manager.create("a")
    monkeypatch.setattr(shutil, "rmtree", lambda *a, **k: (_ for _ in ()).throw(OSError("denied")))
    report = manager.cleanup(workspace, "a")
    assert report.removed is False
    assert "denied" in report.reason or "removal failed" in report.reason


def _touch(path: Path, age_s: float) -> None:
    path.mkdir(parents=True, exist_ok=True)
    stamp = time.time() - age_s
    os.utime(path, (stamp, stamp))


def test_sweep_removes_only_stale_managed(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    stale = manager.root / f"{WORKSPACE_PREFIX}stale"
    fresh = manager.root / f"{WORKSPACE_PREFIX}fresh"
    active = manager.root / f"{WORKSPACE_PREFIX}active"
    unknown = manager.root / "other-dir"
    for path in (stale, fresh, active, unknown):
        _touch(path, 100_000 if path == stale else 0)
    report = manager.sweep(active_paths={active}, stale_after_s=3_600.0)
    assert stale.exists() is False
    assert report.removed == [stale.name]
    assert fresh.exists() is True and active.exists() is True
    assert unknown.exists() is True
    assert report.kept_active == 1
    assert report.skipped_unknown == 1
    assert report.errors == []


def test_sweep_idempotent_and_tolerant(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    first = manager.sweep(active_paths=set(), stale_after_s=3_600.0)
    second = manager.sweep(active_paths=set(), stale_after_s=3_600.0)
    assert first.removed == [] and second.removed == []
    ghost = manager.root / f"{WORKSPACE_PREFIX}ghost"
    report = manager.sweep(active_paths=set(), stale_after_s=3_600.0)
    assert ghost.exists() is False
    assert report.errors == []
