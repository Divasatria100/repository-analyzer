"""FastAPI dependencies (foundation).

Providers that route FastAPI request handling to centralized
configuration and infrastructure factories. Analysis logic never
lives here (see docs/11 §7.1).
"""

from collections.abc import Iterator

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.database import create_engine_from_settings, create_session_factory, session_scope

_session_factory: sessionmaker[Session] | None = None


def get_settings_dep() -> Settings:
    """Provide the centralized application settings."""
    return get_settings()


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    """Lazily build the session factory (no I/O at import time)."""
    global _session_factory
    if _session_factory is None:
        active = settings or get_settings()
        engine = create_engine_from_settings(active.database)
        _session_factory = create_session_factory(engine)
    return _session_factory


def reset_session_factory() -> None:
    """Reset the cached factory (tests only)."""
    global _session_factory
    _session_factory = None


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a transactional session."""
    with session_scope(get_session_factory()) as session:
        yield session
