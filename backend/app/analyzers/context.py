"""Shared analysis context (TASK-083).

The controlled input/environment handed to analyzers: identities, the
immutable commit, NCM, configuration, versions, and known limitations.
Frozen and minimal — no network clients, no filesystem handles, no
execution facilities, no secrets. Analyzers read; they never reach out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.ncm import NcmRepository

if TYPE_CHECKING:
    from app.analyzers.findings import Limitation
    from app.analyzers.thresholds import ThresholdSet


@dataclass(frozen=True)
class AnalysisContext:
    """Everything an analyzer may legitimately need, nothing it must not."""

    analysis_id: str
    repository_id: str
    owner: str
    name: str
    canonical_url: str
    resolved_branch: str
    resolved_commit_sha: str
    ncm: NcmRepository
    analyzer_version: str
    rule_set_version: str
    thresholds: ThresholdSet
    limitations: tuple[Limitation, ...] = ()
    requested_branch: str | None = None
    requested_commit: str | None = None

    def describe(self) -> dict[str, Any]:
        """Operator-safe summary (identities and versions only, no content)."""
        return {
            "analysis_id": self.analysis_id,
            "repository_id": self.repository_id,
            "owner": self.owner,
            "name": self.name,
            "canonical_url": self.canonical_url,
            "resolved_branch": self.resolved_branch,
            "resolved_commit_sha": self.resolved_commit_sha,
            "analyzer_version": self.analyzer_version,
            "rule_set_version": self.rule_set_version,
            "ncm_completeness": self.ncm.completeness,
            "limitation_count": len(self.limitations),
        }
