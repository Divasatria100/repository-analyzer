"""Database/Alembic foundation tests (no live PostgreSQL required).

Engine/session behavior is verified against in-memory SQLite; PostgreSQL
remains the configured target (see ``DatabaseSettings.url`` default).
Alembic wiring is verified structurally: the environment reads the
centralized settings URL and targets the shared ``Base.metadata``.
"""

import configparser
import py_compile
from pathlib import Path

import pytest
from sqlalchemy import Engine, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from app.core.config import DatabaseSettings
from app.core.database import create_engine_from_settings, create_session_factory, session_scope
from app.models.base import Base, TimestampMixin

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Probe(Base, TimestampMixin):
    __tablename__ = "test_probe"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64))


def _sqlite_engine() -> Engine:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def test_sqlalchemy_initialization_and_roundtrip() -> None:
    engine = _sqlite_engine()
    factory = create_session_factory(engine)
    with session_scope(factory) as session:
        session.add(Probe(name="alpha"))
    with session_scope(factory) as session:
        assert session.scalar(text("SELECT COUNT(*) FROM test_probe")) == 1
    assert "test_probe" in inspect(engine).get_table_names()
    engine.dispose()


def test_session_scope_rolls_back_on_failure() -> None:
    engine = _sqlite_engine()
    factory: sessionmaker[Session] = create_session_factory(engine)
    with pytest.raises(RuntimeError), session_scope(factory) as session:
        session.add(Probe(name="bad"))
        raise RuntimeError("boom")
    with session_scope(factory) as session:
        assert session.scalar(text("SELECT COUNT(*) FROM test_probe")) == 0
    engine.dispose()


def test_engine_factory_uses_configured_url() -> None:
    db = DatabaseSettings(url="sqlite:///:memory:")
    engine = create_engine_from_settings(db)
    assert engine.url.database == ":memory:"
    engine.dispose()


def test_postgresql_remains_configured_target() -> None:
    assert DatabaseSettings().url.startswith("postgresql+psycopg://")


def test_alembic_config_points_at_versions_dir() -> None:
    parser = configparser.ConfigParser()
    parser.read(BACKEND_ROOT / "alembic.ini")
    assert parser.get("alembic", "script_location") == "alembic"
    assert (BACKEND_ROOT / "alembic" / "versions").is_dir()


def test_alembic_env_compiles_and_uses_settings_and_metadata() -> None:
    env_path = BACKEND_ROOT / "alembic" / "env.py"
    py_compile.compile(str(env_path), doraise=True)
    source = env_path.read_text(encoding="utf-8")
    assert "get_settings" in source
    assert "target_metadata = Base.metadata" in source
    assert 'set_main_option("sqlalchemy.url"' in source
