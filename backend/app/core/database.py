"""SQLAlchemy engine/session foundation for the RepoLens database.

* PostgreSQL is the target (see docs/09 §7); the URL comes from
  centralized settings — never hardcoded credentials.
* Engines and sessions are created lazily through factories so importing
  the application performs no I/O and opens no connections.
* Analyzers never touch this module (see docs/11 §7.3, docs/15
  SECISO-1005/1401): only the persistence gateway and FastAPI
  dependencies may use it.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import DatabaseSettings

#: Bound connection setup so an unreachable database fails within a bounded
#: time instead of blocking an API request indefinitely. libpq applies this
#: per host address, so ``localhost`` (IPv6 + IPv4) takes at most twice this.
_DB_CONNECT_TIMEOUT_S = 5


def create_engine_from_settings(db: DatabaseSettings) -> Engine:
    """Create a SQLAlchemy engine from database settings (lazy, no I/O)."""
    connect_args: dict[str, object] = {}
    if db.url.startswith("postgresql"):
        connect_args["connect_timeout"] = _DB_CONNECT_TIMEOUT_S
    return create_engine(
        db.url, echo=db.echo, pool_pre_ping=True, connect_args=connect_args
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Provide a transactional session scope with rollback on failure."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
