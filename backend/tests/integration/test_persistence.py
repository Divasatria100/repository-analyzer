"""Ingestion persistence tests (TASK-045): models, transitions, migration.

SQLite-backed (same convention as test_database.py); PostgreSQL remains the
configured target. Verifies the Alembic revision upgrades AND downgrades.
"""

from pathlib import Path

import pytest
from alembic.command import downgrade, upgrade
from alembic.config import Config
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import create_session_factory, session_scope
from app.models.base import Base
from app.models.repository import Repository
from app.repositories import ingestion as persistence
from app.repository.identity import RepositoryIdentity

from .test_database import BACKEND_ROOT

IDENTITY = RepositoryIdentity(owner="acme", name="web")


def _session() -> tuple[Engine, Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    return engine, factory()


def test_repository_reuse_and_default_branch_update() -> None:
    engine, session = _session()
    try:
        first = persistence.get_or_create_repository(session, IDENTITY, default_branch="main")
        session.commit()
        second = persistence.get_or_create_repository(session, IDENTITY, default_branch="trunk")
        session.commit()
        assert first.id == second.id
        assert second.default_branch == "trunk"
        assert session.scalar(text("SELECT COUNT(*) FROM repositories")) == 1
    finally:
        session.close()
        engine.dispose()


def test_duplicate_normalized_url_rejected() -> None:
    engine, session = _session()
    try:
        session.add(
            Repository(normalized_url="https://github.com/acme/web", owner="acme", name="web")
        )
        session.commit()
        session.add(
            Repository(normalized_url="https://github.com/acme/web", owner="acme", name="web")
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.close()
        engine.dispose()


def test_analysis_lifecycle_transitions() -> None:
    engine, session = _session()
    try:
        repo = persistence.get_or_create_repository(session, IDENTITY)
        analysis = persistence.create_analysis(
            session,
            repo,
            requested_branch=None,
            requested_commit=None,
            analyzer_version="0.1.0",
            rule_set_version="1.0",
        )
        assert analysis.stage == "Queued" and analysis.outcome is None
        persistence.set_stage(session, analysis, "ResolvingCommit")
        assert analysis.stage == "ResolvingCommit"
        persistence.record_context_resolution(
            session,
            analysis,
            resolved_branch="main",
            branch_origin="defaulted",
            resolved_commit_sha="a" * 40,
            commit_origin="defaulted",
        )
        persistence.record_workspace(session, analysis, "/tmp/ws-x")
        assert analysis.resolved_commit_sha == "a" * 40
        persistence.mark_failed(session, analysis, "boom")
        assert analysis.outcome == "Failed"
        assert analysis.completed_at is not None
        with pytest.raises(ValueError):
            persistence.set_stage(session, analysis, "ResolvingCommit")
        with pytest.raises(ValueError):
            persistence.set_stage(session, analysis, "Nope")
        session.commit()
    finally:
        session.close()
        engine.dispose()


def test_failure_rolls_back_uncommitted_context() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    try:
        with pytest.raises(RuntimeError), session_scope(factory) as session:
            persistence.get_or_create_repository(session, IDENTITY)
            raise RuntimeError("boom")
        with session_scope(factory) as session:
            assert session.scalar(text("SELECT COUNT(*) FROM repositories")) == 0
    finally:
        engine.dispose()


def test_repeat_analyses_coexist_for_same_commit() -> None:
    engine, session = _session()
    try:
        repo = persistence.get_or_create_repository(session, IDENTITY)
        first = persistence.create_analysis(
            session,
            repo,
            requested_branch=None,
            requested_commit=None,
            analyzer_version="0.1.0",
            rule_set_version="1.0",
        )
        second = persistence.create_analysis(
            session,
            repo,
            requested_branch=None,
            requested_commit=None,
            analyzer_version="0.1.0",
            rule_set_version="1.0",
        )
        session.commit()
        assert first.id != second.id
    finally:
        session.close()
        engine.dispose()


def test_migration_upgrades_and_downgrades(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # env.py sources the URL from centralized settings; point it at sqlite.
    db_file = tmp_path / "migration.db"
    url = f"sqlite:///{db_file}"
    monkeypatch.setenv("REPOLENS_DATABASE__URL", url)
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    upgrade(config, "head")
    engine = create_engine(url)
    try:
        tables = inspect(engine).get_table_names()
        assert "repositories" in tables and "analyses" in tables
    finally:
        engine.dispose()
    downgrade(config, "base")
    engine = create_engine(url)
    try:
        tables = inspect(engine).get_table_names()
        assert "repositories" not in tables and "analyses" not in tables
    finally:
        engine.dispose()
