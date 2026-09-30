"""Parse pipeline integration: states persisted, failures isolated (TASK-069/071).

SQLite-backed; PostgreSQL remains the configured target. Proves the
good/broken/good2 contract end to end with real file rows.
"""

from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.core.config import load_settings
from app.models import repository as _repository_models  # noqa: F401 (register tables)
from app.parsers.pipeline import ParsePhaseResult, run_parse_phase
from app.parsers.result import ParseState
from app.repositories import indexing as gateway
from app.repository.index_types import IndexedFile
from app.repository.workspace import WorkspaceManager
from tests.fixtures.helpers.canary import assert_canary_absent, fixture_contains_canary_payload
from tests.fixtures.helpers.db_helpers import make_sqlite_factory
from tests.fixtures.helpers.paths import read_fixture_bytes

pytestmark = pytest.mark.security


def _file(path: str, **overrides: object) -> IndexedFile:
    base: dict[str, object] = {
        "relative_path": path,
        "file_type": "source",
        "extension": "py",
        "size": 10,
        "language": "python",
        "support_status": "supported",
        "is_binary": False,
        "is_generated": False,
        "excluded": False,
        "exclusion_reason": None,
        "eligibility": "eligible",
        "eligibility_reason": "supported source file; parser may consider",
        "indexing_limitation": None,
    }
    base.update(overrides)
    return IndexedFile(**base)  # type: ignore[arg-type]


def _run(
    tmp_path: Path, files: dict[str, bytes], rows: list[IndexedFile]
) -> tuple[ParsePhaseResult, Session, Engine]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for relpath, content in files.items():
        target = workspace / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    engine, factory = make_sqlite_factory()
    session = factory()
    gateway.save_index(session, "a1", rows, [])
    session.commit()
    workspaces = WorkspaceManager(tmp_path / "roots")
    summary = run_parse_phase(
        session=session,
        analysis_id="a1",
        workspace=workspace,
        workspaces=workspaces,
        settings=load_settings(),
    )
    session.commit()
    return summary, session, engine


def test_good_broken_good2_isolation(tmp_path) -> None:
    """One failed file never stops the rest; unsupported stays unsupported."""

    files = {
        "good.py": b"def ok():\n    return 1\n",
        "broken.py": b"def broken(:\n",
        "good2.py": b"X = 2\n",
        "notes.js": b"var x = 1;\n",
        "data.xyz": b"???\n",
    }
    rows = [
        _file("good.py"),
        _file("broken.py"),
        _file("good2.py"),
        _file(
            "notes.js",
            file_type="source",
            extension="js",
            language="javascript",
            support_status="unsupported",
            eligibility="not_eligible",
            eligibility_reason="language javascript not supported for source analysis",
        ),
        _file(
            "data.xyz",
            file_type="other",
            extension="xyz",
            language=None,
            support_status="unrecognized",
            eligibility="not_eligible",
            eligibility_reason="unrecognized language/format",
        ),
    ]
    summary, session, engine = _run(tmp_path, files, rows)
    try:
        assert summary.total == 5
        assert summary.parsed == 2
        assert summary.failed == 1
        assert summary.unsupported == 2
        assert len(summary.modules) == 2
        persisted = {row.path: row for row in gateway.get_files(session, "a1")}
        assert persisted["good.py"].parse_result == ParseState.PARSED.value
        assert persisted["broken.py"].parse_result == ParseState.FAILED.value
        assert persisted["broken.py"].diagnostics
        assert persisted["good2.py"].parse_result == ParseState.PARSED.value
        assert persisted["notes.js"].parse_result is None
        assert persisted["data.xyz"].parse_result is None
    finally:
        session.close()
        engine.dispose()


def test_canary_content_parsed_as_data_only(tmp_path) -> None:
    """Canary source passes through the full pipeline without side effects."""
    source = read_fixture_bytes("security", "execution_canary.py")
    assert fixture_contains_canary_payload(source.decode("utf-8"))
    summary, session, engine = _run(
        tmp_path, {"canary_check.py": source}, [_file("canary_check.py")]
    )
    try:
        assert summary.parsed == 1
        assert_canary_absent()
    finally:
        session.close()
        engine.dispose()


def test_diagnostics_contain_no_host_paths(tmp_path) -> None:
    """Diagnostics carry repo-relative paths only, never workspace absolutes."""
    summary, session, engine = _run(
        tmp_path, {"broken.py": b"def broken(:\n"}, [_file("broken.py")]
    )
    try:
        rows = gateway.get_files(session, "a1")
        assert rows[0].parse_result == ParseState.FAILED.value
        dumped = repr(rows[0].diagnostics)
        assert str(tmp_path) not in dumped
        assert "broken.py" in dumped
    finally:
        session.close()
        engine.dispose()


def test_update_parse_result_rejects_bad_states() -> None:
    engine, factory = make_sqlite_factory()
    try:
        with factory() as session:
            gateway.save_index(session, "a1", [_file("a.py")], [])
            session.commit()
            row_id = gateway.get_files(session, "a1")[0].id
            with pytest.raises(ValueError):
                gateway.update_parse_result(session, row_id, ParseState.UNSUPPORTED, [])
            with pytest.raises(ValueError):
                gateway.update_parse_result(session, "missing-id", ParseState.PARSED, [])
    finally:
        engine.dispose()
