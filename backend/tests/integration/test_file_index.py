"""File-index persistence tests: roundtrip, isolation, atomicity (TASK-057+).

SQLite-backed; PostgreSQL remains the configured target. Proves indexed
files belong to exactly one analysis snapshot and half-indexed data never
lands as complete.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models import repository as _repository_models  # noqa: F401 (register tables)
from app.repositories import indexing as gateway
from app.repository.index_types import IndexedFile, LimitationRecord
from tests.fixtures.helpers.db_helpers import make_sqlite_factory

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


def test_roundtrip_preserves_records_and_order() -> None:
    engine, factory = make_sqlite_factory()
    try:
        with factory() as session:
            gateway.save_index(
                session,
                "a1",
                [_file("z.py"), _file("a.py", eligibility="not_eligible")],
                [LimitationRecord(scope_kind="file", file_path="x", reason="r")],
            )
            session.commit()
        with factory() as session:
            rows = gateway.get_files(session, "a1")
            assert [r.path for r in rows] == ["a.py", "z.py"]
            assert rows[0].eligibility == "not_eligible"
            assert rows[1].language == "python"
            assert rows[1].parse_result is None
            limitations = gateway.get_limitations(session, "a1")
            assert len(limitations) == 1
            assert limitations[0].scope_kind == "file"
    finally:
        engine.dispose()


def test_duplicate_path_rejected_atomically() -> None:
    engine, factory = make_sqlite_factory()
    try:
        with factory() as session:
            gateway.save_index(session, "a1", [_file("dup.py")], [])
            session.commit()
        with factory() as session:
            with pytest.raises(IntegrityError):
                gateway.save_index(session, "a1", [_file("dup.py"), _file("other.py")], [])
                session.commit()
        with factory() as session:
            # Failed save left no partial rows behind.
            assert [r.path for r in gateway.get_files(session, "a1")] == ["dup.py"]
    finally:
        engine.dispose()


def test_same_repo_different_analyses_isolated() -> None:
    engine, factory = make_sqlite_factory()
    try:
        with factory() as session:
            gateway.save_index(session, "commit-a", [_file("main.py", size=10)], [])
            gateway.save_index(session, "commit-b", [_file("main.py", size=20)], [])
            session.commit()
        with factory() as session:
            first = gateway.get_files(session, "commit-a")
            second = gateway.get_files(session, "commit-b")
            assert first[0].size == 10 and second[0].size == 20
            assert session.scalar(text("SELECT COUNT(*) FROM files")) == 2
    finally:
        engine.dispose()


def test_invalid_vocabulary_rejected_before_persist() -> None:
    engine, factory = make_sqlite_factory()
    try:
        with factory() as session:
            with pytest.raises(ValueError, match="Unknown eligibility"):
                gateway.save_index(session, "a1", [_file("x.py", eligibility="maybe")], [])
        with factory() as session:
            assert gateway.get_files(session, "a1") == []
    finally:
        engine.dispose()
