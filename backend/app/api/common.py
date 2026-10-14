"""Shared API data-access helpers (Phase 12).

Read-only helpers over the existing persistence gateways. No analyzer
execution, no snapshot mutation, no transaction ownership: callers use the
request session. Analyses and repositories are scoped by their own IDs on
every query so resources never leak across scopes.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.errors import ApiError
from app.models.indexing import Limitation
from app.models.repository import Analysis, Repository
from app.models.results import AnalysisSnapshot, DomainState
from app.repositories.results import get_snapshot, load_snapshot_data
from app.results.canonical import SnapshotData, build_canonical_result

#: Domain states whose sections are null in the canonical result (§6.3).
NULL_SECTION_STATES = frozenset(
    {"Analysis not performed", "Analysis failed", "Analysis unavailable"}
)


def get_analysis_or_404(session: Session, analysis_id: str) -> Analysis:
    """Load one analysis by ID or raise a contract 404."""
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise ApiError("ANALYSIS_NOT_FOUND", "Analysis was not found.")
    return analysis


def get_repository_or_404(session: Session, repository_id: str) -> Repository:
    """Load one repository by ID or raise a contract 404."""
    repository = session.get(Repository, repository_id)
    if repository is None:
        raise ApiError("REPOSITORY_NOT_FOUND", "Repository was not found.")
    return repository


def require_completed_snapshot(session: Session, analysis: Analysis) -> SnapshotData:
    """Load sealed snapshot data for endpoints needing usable results.

    Non-terminal analyses yield ANALYSIS_NOT_COMPLETED (409); Failed
    analyses yield ANALYSIS_FAILED (422) with the user-safe explanation in
    details. A completed outcome without a snapshot is an internal
    inconsistency (500), never an empty result.
    """
    if analysis.outcome is None:
        raise ApiError(
            "ANALYSIS_NOT_COMPLETED", "The analysis has not reached a completed outcome."
        )
    if analysis.outcome == "Failed":
        raise ApiError(
            "ANALYSIS_FAILED",
            "Analysis ended as Failed.",
            {"explanation": analysis.explanation},
        )
    try:
        return load_snapshot_data(session, analysis.id)
    except (ValueError, LookupError) as exc:
        raise ApiError("INTERNAL_ERROR", "An unexpected error occurred.") from exc


def canonical_for_snapshot(data: SnapshotData) -> dict[str, object]:
    """Build the canonical result, mapping data faults to INTERNAL_ERROR."""
    try:
        return build_canonical_result(data)
    except ValueError as exc:
        raise ApiError("INTERNAL_ERROR", "An unexpected error occurred.") from exc


def unavailable_areas(status: dict[str, object]) -> list[dict[str, object]]:
    """Areas whose sections are null, so lists are not read as complete."""
    domains = status.get("domains")
    if not isinstance(domains, list):
        return []
    return [
        {"area": domain.get("area"), "state": domain.get("state"), "reason": domain.get("reason")}
        for domain in domains
        if isinstance(domain, dict) and domain.get("state") in NULL_SECTION_STATES
    ]


def status_rows(
    session: Session, analysis_id: str
) -> tuple[list[DomainState], list[Limitation], AnalysisSnapshot | None]:
    """Domain states, limitations, and snapshot row for status responses."""
    domains = list(
        session.scalars(
            select(DomainState)
            .where(DomainState.analysis_id == analysis_id)
            .order_by(DomainState.area)
        ).all()
    )
    limitations = list(
        session.scalars(
            select(Limitation)
            .where(Limitation.analysis_id == analysis_id)
            .order_by(Limitation.scope_kind, Limitation.file_path)
        ).all()
    )
    return domains, limitations, get_snapshot(session, analysis_id)


def history_entry(analysis: Analysis) -> dict[str, object]:
    """One repository-history entry (docs/17 §4.5, most-recent-first sorted by caller)."""
    return {
        "analysis_id": analysis.id,
        "branch": (
            {"name": analysis.resolved_branch, "origin": _origin(analysis.branch_origin)}
            if analysis.resolved_branch
            else None
        ),
        "commit": (
            {"sha": analysis.resolved_commit_sha, "origin": _origin(analysis.commit_origin)}
            if analysis.resolved_commit_sha
            else None
        ),
        "timestamp": _iso(analysis.created_at),
        "analyzer_version": analysis.analyzer_version,
        "rule_set_version": analysis.rule_set_version,
        "outcome": analysis.outcome,
        "explanation": analysis.explanation,
    }


def _origin(value: str | None) -> str | None:
    """Stored lowercase origin to canonical Requested/Defaulted vocabulary."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "requested":
        return "Requested"
    if normalized == "defaulted":
        return "Defaulted"
    raise ApiError("INTERNAL_ERROR", "An unexpected error occurred.")


def _iso(value: datetime | None) -> str | None:
    """UTC ISO-8601 timestamp or None."""
    if value is None:
        return None
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
