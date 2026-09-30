"""File-index domain models (docs/12 §4.3, §4.9).

One File row per indexed entry at one analyzed commit (analysis-scoped;
same path in two analyses = two rows). Limitation rows record skipped,
rejected, and limit-affected content so nothing is silently omitted.
File contents are never persisted — metadata only.

Design decisions (docs/12 leaves DDL to implementation):
- surrogate string PKs matching the ingestion models;
- (analysis_id, path) unique: one record per path per analysis (#11);
- support/eligibility/type vocabularies validated in the gateway;
- parse_result NULL until the parsing phase (never fabricated here).
"""

from __future__ import annotations

import uuid

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin

FILE_TYPES = frozenset(
    {"source", "configuration", "manifest", "documentation", "other", "link", "special"}
)

SUPPORT_STATUSES = frozenset({"supported", "unsupported", "unrecognized", "binary"})

ELIGIBILITY_VALUES = frozenset({"eligible", "not_eligible"})


def _new_id() -> str:
    return uuid.uuid4().hex


class File(Base, TimestampMixin):
    """One indexed file/link entry at an analyzed commit (docs/12 §4.3)."""

    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    file_type: Mapped[str] = mapped_column(String(32), nullable=False)
    extension: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    size: Mapped[int] = mapped_column(nullable=False, default=0)
    language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    support_status: Mapped[str] = mapped_column(String(16), nullable=False)
    is_binary: Mapped[bool] = mapped_column(nullable=False, default=False)
    is_generated: Mapped[bool] = mapped_column(nullable=False, default=False)
    excluded: Mapped[bool] = mapped_column(nullable=False, default=False)
    exclusion_reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    eligibility: Mapped[str] = mapped_column(String(16), nullable=False)
    eligibility_reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    parse_result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    diagnostics: Mapped[list[dict[str, object]] | None] = mapped_column(JSON, nullable=True)
    indexing_limitation: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    __table_args__ = (
        # One record per path per analysis (docs/12 constraint #11).
        UniqueConstraint("analysis_id", "path", name="uq_files_analysis_path"),
    )


class Limitation(Base, TimestampMixin):
    """Explicit record for skipped/rejected/limit-affected content."""

    __tablename__ = "limitations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    # Current vocabulary: "index" (subtree/limit scope) and "file"
    # (single entry). Area/rule scopes arrive with aggregation.
    scope_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
