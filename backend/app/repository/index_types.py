"""Shared value objects for the file-index boundary (docs/12 §4.3).

Kept in a dependency-free module so the indexing service
(``app.repository.indexing``) and the persistence gateway
(``app.repositories.indexing``) share one representation without
importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LimitationRecord:
    """Explicit record for skipped/rejected/limit-affected content (in-memory)."""

    scope_kind: str  # "index" (subtree/limit scope) or "file" (single entry)
    file_path: str | None
    reason: str


@dataclass(frozen=True)
class IndexedFile:
    """File metadata record: the durable input for parsing/filtering."""

    relative_path: str
    file_type: str  # source|configuration|manifest|documentation|other|link|special
    extension: str
    size: int
    language: str | None
    support_status: str  # supported|unsupported|unrecognized|binary
    is_binary: bool
    is_generated: bool
    excluded: bool
    exclusion_reason: str | None
    eligibility: str  # eligible|not_eligible (parser may consider)
    eligibility_reason: str
    indexing_limitation: str | None


@dataclass
class IndexResult:
    """Outcome of indexing one workspace (persisted + returned)."""

    files: list[IndexedFile] = field(default_factory=list)
    limitations: list[LimitationRecord] = field(default_factory=list)
    complete: bool = True
    total_bytes: int = 0
