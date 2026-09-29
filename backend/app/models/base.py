"""Typed SQLAlchemy model foundation (no domain entities yet).

Provides the declarative base every future RepoLens persistence model
(Repository, Analysis, File, Finding, …) will inherit from. Domain
models arrive in the persistence/data-model phase, not here.
"""

from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all RepoLens database models."""

    type_annotation_map = {datetime: DateTime(timezone=True)}


class TimestampMixin:
    """Generic creation/update timestamps for persistence models."""

    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
