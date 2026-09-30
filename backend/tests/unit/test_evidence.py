"""Evidence tests (TASK-089): frozen window, truncation, safe paths."""

from pathlib import Path

import pytest

from app.analyzers.errors import EvidenceUnavailableError
from app.analyzers.evidence import build_evidence
from app.repository.workspace import WorkspaceManager
from tests.fixtures.helpers.analyzer_helpers import make_workspace

pytestmark = pytest.mark.security


def _manager(tmp_path: Path) -> WorkspaceManager:
    return WorkspaceManager(tmp_path / "roots")


def _numbered(count: int) -> dict[str, str]:
    return {"src/app.py": "".join(f"line {number}\n" for number in range(1, count + 1))}


def test_relative_path_and_line_boundaries(tmp_path: Path) -> None:
    """Excerpt carries repo-relative path with exact line bounds."""
    root = make_workspace(tmp_path, _numbered(30))
    manager = _manager(tmp_path)
    evidence = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=10,
        focus_end_line=10,
        context_each_side=10,
        max_excerpt_lines=40,
    )
    assert evidence.path == "src/app.py"
    assert evidence.start_line == 1
    assert evidence.end_line == 20
    assert evidence.lines[0] == "line 1"
    assert evidence.lines[9] == "line 10"
    assert evidence.truncated is False
    assert evidence.redacted is False


def test_ten_before_window_at_file_start(tmp_path: Path) -> None:
    """Window clamps at file boundaries (finding lines always included)."""
    root = make_workspace(tmp_path, _numbered(30))
    manager = _manager(tmp_path)
    evidence = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=3,
        focus_end_line=3,
        context_each_side=10,
        max_excerpt_lines=40,
    )
    assert evidence.start_line == 1
    assert evidence.end_line == 13
    assert len(evidence.lines) == 13


def test_forty_line_cap_truncates_with_marker(tmp_path: Path) -> None:
    """Whole excerpt capped at 40 lines; finding lines survive truncation."""
    root = make_workspace(tmp_path, _numbered(100))
    manager = _manager(tmp_path)
    evidence = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=40,
        focus_end_line=65,
        context_each_side=10,
        max_excerpt_lines=40,
    )
    assert len(evidence.lines) == 40
    assert evidence.truncated is True
    text = "\n".join(evidence.lines)
    assert "line 40" in text and "line 65" in text


def test_exact_boundary_behavior(tmp_path: Path) -> None:
    """A 40-line window is kept whole; 41 lines truncate to 40."""
    root = make_workspace(tmp_path, _numbered(100))
    manager = _manager(tmp_path)
    fitting = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=20,
        focus_end_line=20,
        context_each_side=10,
        max_excerpt_lines=40,
    )
    assert len(fitting.lines) == 21
    assert fitting.truncated is False
    wide = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=50,
        focus_end_line=50,
        context_each_side=30,
        max_excerpt_lines=40,
    )
    assert len(wide.lines) == 40
    assert wide.truncated is True


def test_no_absolute_workspace_path(tmp_path: Path) -> None:
    """Evidence never exposes absolute or workspace paths."""
    root = make_workspace(tmp_path, _numbered(30))
    manager = _manager(tmp_path)
    evidence = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=10,
        focus_end_line=10,
        context_each_side=10,
        max_excerpt_lines=40,
    )
    assert evidence.path == "src/app.py"
    assert str(tmp_path) not in repr(evidence)


def test_no_unbounded_source_content(tmp_path: Path) -> None:
    """A 10k-line file yields at most the capped window, never the file."""
    root = make_workspace(tmp_path, _numbered(10_000))
    manager = _manager(tmp_path)
    evidence = build_evidence(
        workspaces=manager,
        workspace=root,
        relpath="src/app.py",
        focus_start_line=5000,
        focus_end_line=5000,
        context_each_side=10,
        max_excerpt_lines=40,
    )
    assert len(evidence.lines) <= 40


def test_unreadable_or_escaping_paths_raise(tmp_path: Path) -> None:
    """Missing files, symlinks, and escapes become limitations, not crashes."""
    import os

    root = make_workspace(tmp_path, _numbered(30))
    manager = _manager(tmp_path)
    with pytest.raises(EvidenceUnavailableError):
        build_evidence(
            workspaces=manager,
            workspace=root,
            relpath="src/missing.py",
            focus_start_line=1,
            focus_end_line=1,
            context_each_side=10,
            max_excerpt_lines=40,
        )
    with pytest.raises(EvidenceUnavailableError):
        build_evidence(
            workspaces=manager,
            workspace=root,
            relpath="../outside.py",
            focus_start_line=1,
            focus_end_line=1,
            context_each_side=10,
            max_excerpt_lines=40,
        )
    link = root / "link.py"
    try:
        os.symlink(root / "src" / "app.py", link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    with pytest.raises(EvidenceUnavailableError):
        build_evidence(
            workspaces=manager,
            workspace=root,
            relpath="link.py",
            focus_start_line=1,
            focus_end_line=1,
            context_each_side=10,
            max_excerpt_lines=40,
        )


def test_invalid_ranges_raise(tmp_path: Path) -> None:
    """Nonsense ranges fail fast instead of producing empty evidence."""
    root = make_workspace(tmp_path, _numbered(10))
    manager = _manager(tmp_path)
    with pytest.raises(EvidenceUnavailableError):
        build_evidence(
            workspaces=manager,
            workspace=root,
            relpath="src/app.py",
            focus_start_line=0,
            focus_end_line=1,
            context_each_side=10,
            max_excerpt_lines=40,
        )
    with pytest.raises(EvidenceUnavailableError):
        build_evidence(
            workspaces=manager,
            workspace=root,
            relpath="src/app.py",
            focus_start_line=5,
            focus_end_line=500,
            context_each_side=10,
            max_excerpt_lines=40,
        )
