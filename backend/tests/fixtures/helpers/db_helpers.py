"""Database test helpers reusing the app's SQLAlchemy foundation (SQLite only)."""

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import create_session_factory
from app.models.base import Base


def make_sqlite_factory() -> tuple[Engine, sessionmaker[Session]]:
    """Create an in-memory SQLite engine + session factory; caller disposes.

    Uses the shared ``Base.metadata`` so future domain models are covered
    without helper changes. Never touches PostgreSQL or real data.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, create_session_factory(engine)
