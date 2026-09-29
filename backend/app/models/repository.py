"""Repository-ingestion domain models (docs/12 §4.1–4.2, §6.1–6.3).

Only the entities required for ingestion: Repository (stable public-repo
anchor, holds no results) and Analysis (one pipeline execution at one
resolved commit). Later phases add File/Finding/Dependency/etc.

Design decisions (docs/12 leaves DDL to implementation):
- surrogate string PKs (uuid4 hex); no uniqueness on repo+commit (NFR-034,
  retries create new rows, never overwrite);
- normalized_url unique so equivalent URL forms share one Repository;
- lifecycle as plain strings validated in the persistence layer.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

ANALYSIS_STAGES = frozenset(
    {
        "Queued",
        "ValidatingRepository",
        "ResolvingCommit",
        "RetrievingRepository",
        "IndexingFiles",
        "DetectingLanguages",
        "ParsingSource",
        "BuildingCodeModel",
        "RunningAnalysis",
        "AggregatingResults",
        "GeneratingReports",
    }
)

TERMINAL_OUTCOMES = frozenset({"Completed", "CompletedWithLimitations", "Failed"})

ORIGIN_REQUESTED = "requested"
ORIGIN_DEFAULTED = "defaulted"


def _new_id() -> str:
    return uuid.uuid4().hex


class Repository(Base, TimestampMixin):
    """Stable anchor for one public GitHub repository (docs/12 §4.1)."""

    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    normalized_url: Mapped[str] = mapped_column(String(2048), unique=True, nullable=False)
    owner: Mapped[str] = mapped_column(String(39), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)

    analyses: Mapped[list[Analysis]] = relationship(back_populates="repository")


class Analysis(Base, TimestampMixin):
    """One pipeline execution for one repository at one commit (docs/12 §4.2)."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    requested_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    requested_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolved_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    branch_origin: Mapped[str | None] = mapped_column(String(16), nullable=True)
    resolved_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit_origin: Mapped[str | None] = mapped_column(String(16), nullable=True)
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="Queued")
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    analyzer_version: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    workspace_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)

    repository: Mapped[Repository] = relationship(back_populates="analyses")


def utcnow() -> datetime:
    """Timezone-aware now for lifecycle timestamps."""
    return datetime.now(UTC)
