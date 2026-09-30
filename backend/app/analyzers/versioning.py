"""Explicit version metadata (TASK-085).

Every finding traces to the analyzer and rule-set versions that produced
it. Versions live on the owning ``Analysis`` (docs/12 §4.2); rules carry
no separate version system (docs/12 §4.5: a rule is identified by its ID
within a rule-set version). The single sources of truth are reused here,
never duplicated:

* analyzer version → ``settings.application.version``
* rule-set version → ``RULE_SET_VERSION`` (``app.repository.ingestion``)
"""

from __future__ import annotations

from dataclasses import dataclass

from app.repository.ingestion import RULE_SET_VERSION

__all__ = ["RULE_SET_VERSION", "Versions", "resolve_versions"]


@dataclass(frozen=True)
class Versions:
    """Analyzer + rule-set versions attached to every result."""

    analyzer_version: str
    rule_set_version: str = RULE_SET_VERSION

    def __post_init__(self) -> None:
        """Fail fast on empty versions (untraceable results are rejected)."""
        if not self.analyzer_version.strip():
            raise ValueError("analyzer_version must not be empty.")
        if not self.rule_set_version.strip():
            raise ValueError("rule_set_version must not be empty.")

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization."""
        return {
            "analyzer_version": self.analyzer_version,
            "rule_set_version": self.rule_set_version,
        }


def resolve_versions(application_version: str) -> Versions:
    """Build versions from the application version (rule set is frozen)."""
    return Versions(analyzer_version=application_version, rule_set_version=RULE_SET_VERSION)
