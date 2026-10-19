"""Migration determinism tests (no live database required).

SQLite does not enforce foreign-key targets at ``CREATE TABLE`` time, so the
suite above can pass while a migration is invalid on PostgreSQL. These tests
record the DDL order of the Phase 11 migration and assert that every
referenced table exists before the referencing table is created.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PHASE11_MIGRATION = (
    BACKEND_ROOT / "alembic" / "versions" / "b7e1f9a2c4d8_phase11_results.py"
)


class _Batch:
    def __enter__(self) -> "_Batch":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def add_column(self, *args: object, **kwargs: object) -> None:
        return None

    def drop_column(self, name: str) -> None:
        return None

    def create_foreign_key(self, *args: object, **kwargs: object) -> None:
        return None

    def drop_constraint(self, *args: object, **kwargs: object) -> None:
        return None


class _OpRecorder:
    def __init__(self) -> None:
        self.created: dict[str, set[str]] = {}
        self.dropped: list[str] = []

    def create_table(self, name: str, *columns: object, **kwargs: object) -> None:
        referenced: set[str] = set()
        for column in columns:
            for foreign_key in getattr(column, "foreign_keys", ()):
                referenced.add(foreign_key.target_fullname.split(".", 1)[0])
        self.created[name] = referenced

    def create_index(self, *args: object, **kwargs: object) -> None:
        return None

    def drop_table(self, name: str, **kwargs: object) -> None:
        self.dropped.append(name)

    def drop_index(self, *args: object, **kwargs: object) -> None:
        return None

    def batch_alter_table(self, *args: object, **kwargs: object) -> _Batch:
        return _Batch()


def _load_phase11_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "phase11_results_migration", PHASE11_MIGRATION
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def phase11(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, _OpRecorder]:
    module = _load_phase11_migration()
    recorder = _OpRecorder()
    monkeypatch.setattr(module, "op", recorder)
    return module, recorder


def test_upgrade_creates_referenced_tables_first(
    phase11: tuple[ModuleType, _OpRecorder],
) -> None:
    module, recorder = phase11
    module.upgrade()

    created_tables = set(recorder.created)
    existing: set[str] = set()
    for table, referenced in recorder.created.items():
        internal = referenced & created_tables
        missing = internal - existing - {table}
        assert not missing, f"{table} references tables created later: {sorted(missing)}"
        existing.add(table)


def test_downgrade_drops_referencing_tables_first(
    phase11: tuple[ModuleType, _OpRecorder],
) -> None:
    module, upgrade_recorder = phase11
    module.upgrade()

    downgrade_recorder = _OpRecorder()
    module.op = downgrade_recorder
    module.downgrade()

    positions = {table: index for index, table in enumerate(downgrade_recorder.dropped)}
    for child, referenced in upgrade_recorder.created.items():
        for parent in referenced:
            if child in positions and parent in positions:
                assert positions[child] < positions[parent], (
                    f"{child} must be dropped before {parent}"
                )
