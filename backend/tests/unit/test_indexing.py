"""File indexing tests: traversal, metadata, containment, limits (TASK-056–060).

Tree content is generated in-test as data; nothing is executed or imported.
"""

import os
from pathlib import Path
from typing import Any

import pytest

from app.repository.errors import IndexingError
from app.repository.indexing import (
    EntryKind,
    classify_entry,
    classify_file,
    index_workspace,
    walk_workspace,
)
from tests.fixtures.helpers.canary import assert_canary_absent, fixture_contains_canary_payload
from tests.fixtures.helpers.config_helpers import override_env
from tests.fixtures.helpers.paths import read_fixture_text

pytestmark = pytest.mark.security

CANARY_TOKEN = "REPOLENS_CANARY_PY01_PAYLOAD"


def _write(root: Path, files: dict[str, bytes | str]) -> Path:
    for relpath, content in files.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return root


def _try_symlink(target: Path, link: Path) -> bool:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return False
    return True


def test_empty_repository_indexes_complete(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    entries, limitations, complete = walk_workspace(root, max_files=20000, max_depth=32)
    assert entries == [] and limitations == [] and complete is True


def test_traversal_is_deterministic(tmp_path: Path) -> None:
    root = _write(
        tmp_path / "ws",
        {
            "z.py": "x = 1\n",
            "a.py": "y = 2\n",
            "pkg/mod.py": "z = 3\n",
            "pkg/sub/deep.py": "w = 4\n",
            "README.md": "hi\n",
        },
    )
    first, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    second, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    assert [e.relative_path for e in first] == [e.relative_path for e in second]
    # Globally sorted regardless of traversal shape.
    assert [e.relative_path for e in first] == [
        "README.md",
        "a.py",
        "pkg/mod.py",
        "pkg/sub/deep.py",
        "z.py",
    ]


def test_missing_workspace_raises(tmp_path: Path) -> None:
    from app.core.config import load_settings
    from app.models import repository as _repository_models  # noqa: F401 (register tables)
    from tests.fixtures.helpers.db_helpers import make_sqlite_factory

    engine, factory = make_sqlite_factory()
    try:
        with pytest.raises(IndexingError):
            with factory() as session:
                index_workspace(
                    workspace=tmp_path / "absent",
                    analysis_id="a",
                    settings=load_settings(),
                    session=session,
                )
    finally:
        engine.dispose()


def test_metadata_records_relative_posix_paths_and_sizes(tmp_path: Path) -> None:
    root = _write(tmp_path / "ws", {"pkg/mod.py": "x = 1\n", "empty.py": ""})
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    by_path = {e.relative_path: e for e in entries}
    # Sizes come from filesystem metadata (text-mode newline translation applies).
    assert by_path["pkg/mod.py"].size == (root / "pkg" / "mod.py").stat().st_size
    assert by_path["empty.py"].size == 0
    assert "\\" not in by_path["pkg/mod.py"].relative_path
    assert by_path["pkg/mod.py"].depth == 2
    assert by_path["empty.py"].depth == 1


def test_zero_byte_and_extensionless_files(tmp_path: Path) -> None:
    root = _write(tmp_path / "ws", {"empty.py": "", "LICENSE": "MIT\n"})
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    record_by_path = {
        entry.relative_path: classify_file(root, entry, file_max_bytes=1_000_000)
        for entry in entries
    }
    assert record_by_path["empty.py"].eligibility == "eligible"
    assert record_by_path["empty.py"].is_binary is False
    assert record_by_path["LICENSE"].support_status == "unrecognized"


def test_outside_marker_never_read(tmp_path: Path) -> None:
    marker = tmp_path / "outside.txt"
    marker.write_text(f"token={CANARY_TOKEN}-outside\n", encoding="utf-8")
    root = _write(tmp_path / "ws", {"ok.py": "x = 1\n"})
    link = root / "evil.py"
    if not _try_symlink(marker, link):
        pytest.skip("symlinks unavailable on this platform")
    entries, limitations, complete = walk_workspace(root, max_files=20000, max_depth=32)
    assert complete is True
    links = [e for e in entries if e.kind is EntryKind.SYMLINK]
    assert [e.relative_path for e in links] == ["evil.py"]
    records = [classify_file(root, e, file_max_bytes=1_000_000) for e in entries]
    assert all(CANARY_TOKEN not in (r.relative_path + r.eligibility_reason) for r in records)
    assert marker.read_text(encoding="utf-8").startswith("token=")


def test_symlink_directory_not_descended(tmp_path: Path) -> None:
    outside = _write(tmp_path / "outside", {"secret.py": f"x = {CANARY_TOKEN}\n"})
    root = _write(tmp_path / "ws", {"ok.py": "x = 1\n"})
    if not _try_symlink(outside, root / "linked"):
        pytest.skip("symlinks unavailable on this platform")
    entries, _, complete = walk_workspace(root, max_files=20000, max_depth=32)
    assert complete is True
    assert sorted(e.relative_path for e in entries) == ["linked", "ok.py"]
    assert all("secret.py" not in e.relative_path for e in entries)


def test_file_exactly_at_size_limit_is_eligible(tmp_path: Path) -> None:
    root = _write(tmp_path / "ws", {"a.py": "x = 1\n"})
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    actual = (root / "a.py").stat().st_size
    record = classify_file(root, entries[0], file_max_bytes=actual)
    assert record.eligibility == "eligible"
    assert record.indexing_limitation is None


def test_file_one_byte_over_is_recorded_not_analyzed(tmp_path: Path) -> None:
    root = _write(tmp_path / "ws", {"a.py": "x = 1\n"})
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    actual = (root / "a.py").stat().st_size
    record = classify_file(root, entries[0], file_max_bytes=actual - 1)
    assert record.eligibility == "not_eligible"
    assert record.size == actual
    assert record.indexing_limitation is not None
    assert "recorded as not analyzed" in record.eligibility_reason


def test_count_exactly_at_max_is_complete(tmp_path: Path) -> None:
    root = _write(tmp_path / "ws", {f"f{i}.py": "x\n" for i in range(3)})
    _, _, complete = walk_workspace(root, max_files=3, max_depth=32)
    assert complete is True


def test_count_one_over_is_incomplete(tmp_path: Path) -> None:
    root = _write(tmp_path / "ws", {f"f{i}.py": "x\n" for i in range(4)})
    entries, limitations, complete = walk_workspace(root, max_files=3, max_depth=32)
    assert complete is False
    assert len(entries) == 3
    assert any(
        limitation.scope_kind == "index" and "max_files" in limitation.reason
        for limitation in limitations
    )


def test_depth_exactly_at_boundary_indexed(tmp_path: Path) -> None:
    deep = "/".join([f"d{i}" for i in range(7)] + ["deep.py"])  # depth 8
    root = _write(tmp_path / "ws", {deep: "x\n"})
    entries, _, complete = walk_workspace(root, max_files=20000, max_depth=8)
    assert complete is True
    assert [e.relative_path for e in entries] == [deep]


def test_depth_one_beyond_skipped_with_limitation(tmp_path: Path) -> None:
    deep = "/".join([f"d{i}" for i in range(8)] + ["deep.py"])  # depth 9
    root = _write(tmp_path / "ws", {deep: "x\n", "top.py": "y\n"})
    entries, limitations, complete = walk_workspace(root, max_files=20000, max_depth=8)
    assert complete is False
    assert [e.relative_path for e in entries] == ["top.py"]
    assert any("max_depth" in limitation.reason for limitation in limitations)


def test_limits_come_from_centralized_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.core.config import load_settings

    override_env(monkeypatch, {"REPOLENS_OPERATIONAL__INDEX_MAX_FILES": "1000"})
    assert load_settings().operational.index_max_files == 1000
    root = _write(tmp_path / "ws", {f"f{i}.py": "x\n" for i in range(1002)})
    entries, limitations, complete = walk_workspace(
        root,
        max_files=load_settings().operational.index_max_files,
        max_depth=load_settings().operational.index_max_depth,
    )
    assert complete is False
    assert len(entries) == 1000


def test_indexing_canary_visible_as_data_never_executed(tmp_path: Path) -> None:
    source = read_fixture_text("security", "execution_canary.py")
    assert fixture_contains_canary_payload(source)
    root = _write(tmp_path / "ws", {"canary_check.py": source})
    entries, _, complete = walk_workspace(root, max_files=20000, max_depth=32)
    assert complete is True
    records = [classify_file(root, e, file_max_bytes=1_000_000) for e in entries]
    assert [r.relative_path for r in records] == ["canary_check.py"]
    assert records[0].eligibility == "eligible"
    assert_canary_absent()


def test_unreadable_content_recorded_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.repository.indexing as indexing_module

    root = _write(tmp_path / "ws", {"a.py": "x = 1\n"})
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    monkeypatch.setattr(
        indexing_module, "is_binary_content", lambda path, size: (_ for _ in ()).throw(OSError())
    )
    record = classify_file(root, entries[0], file_max_bytes=1_000_000)
    assert record.eligibility == "not_eligible"
    assert record.indexing_limitation is not None


class _FakeStat:
    def __init__(self, mode: int, reparse: bool = False) -> None:
        self.st_mode = mode
        self.st_size = 0
        if reparse:
            self.st_file_attributes = 0x400


class _FakeEntry:
    def __init__(self, name: str, *, symlink: bool = False, stat: Any = None) -> None:
        self._name = name
        self._symlink = symlink
        self._stat: Any = stat

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> str:
        return self._name

    def is_symlink(self) -> bool:
        return self._symlink

    def stat(self, *, follow_symlinks: bool = True) -> Any:
        if self._stat is None:
            raise OSError("cannot stat")
        return self._stat


def test_classifier_junction_special_and_unstatable() -> None:
    import stat as stat_module

    junction = _FakeEntry("linked", stat=_FakeStat(stat_module.S_IFDIR | 0o755, reparse=True))
    assert classify_entry(junction) == EntryKind.JUNCTION
    fifo = _FakeEntry("pipe", stat=_FakeStat(stat_module.S_IFIFO | 0o600))
    assert classify_entry(fifo) == EntryKind.SPECIAL
    broken = _FakeEntry("ghost")
    assert classify_entry(broken) == EntryKind.SPECIAL
    link = _FakeEntry("shortcut", symlink=True)
    assert classify_entry(link) == EntryKind.SYMLINK
    regular = _FakeEntry("a.py", stat=_FakeStat(stat_module.S_IFREG | 0o644))
    assert classify_entry(regular) == EntryKind.FILE
