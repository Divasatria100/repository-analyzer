"""Persistence gateway for repository-ingestion context (docs/12 §4.2, §6.2).

Only ingestion entities (Repository, Analysis). Callers own the transaction
via ``session_scope`` — helpers flush; failures roll back safely there.
Rejected submissions are never persisted (docs/12 §6.3): persistence starts
at acceptance.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.repository import (
    ANALYSIS_STAGES,
    TERMINAL_OUTCOMES,
    Analysis,
    Repository,
    utcnow,
)
from app.repository.identity import RepositoryIdentity


def get_or_create_repository(
    session: Session,
    identity: RepositoryIdentity,
    default_branch: str | None = None,
) -> Repository:
    """Reuse the stable anchor for this normalized URL, or create it."""
    existing = session.scalar(
        select(Repository).where(Repository.normalized_url == identity.canonical_url)
    )
    if existing is not None:
        if default_branch and existing.default_branch != default_branch:
            existing.default_branch = default_branch  # last observed, informational
        session.flush()
        return existing
    repository = Repository(
        normalized_url=identity.canonical_url,
        owner=identity.owner,
        name=identity.name,
        default_branch=default_branch,
    )
    session.add(repository)
    session.flush()
    return repository


def create_analysis(
    session: Session,
    repository: Repository,
    *,
    requested_branch: str | None,
    requested_commit: str | None,
    analyzer_version: str,
    rule_set_version: str,
) -> Analysis:
    """Persist an accepted analysis in Queued stage (PIPE-REQ-006 ordering)."""
    analysis = Analysis(
        repository_id=repository.id,
        requested_branch=requested_branch,
        requested_commit=requested_commit,
        stage="Queued",
        analyzer_version=analyzer_version,
        rule_set_version=rule_set_version,
    )
    session.add(analysis)
    session.flush()
    return analysis


def set_stage(session: Session, analysis: Analysis, stage: str) -> Analysis:
    """Advance the lifecycle stage; rejects unknown stages and terminal edits."""
    if stage not in ANALYSIS_STAGES:
        raise ValueError(f"Unknown analysis stage: {stage}")
    if analysis.outcome is not None:
        raise ValueError("Terminal analysis lifecycle must not change.")
    analysis.stage = stage
    session.flush()
    return analysis


def record_context_resolution(
    session: Session,
    analysis: Analysis,
    *,
    resolved_branch: str,
    branch_origin: str,
    resolved_commit_sha: str,
    commit_origin: str,
) -> Analysis:
    """Record immutable context before retrieval begins (PIPE-REQ-006)."""
    analysis.resolved_branch = resolved_branch
    analysis.branch_origin = branch_origin
    analysis.resolved_commit_sha = resolved_commit_sha
    analysis.commit_origin = commit_origin
    session.flush()
    return analysis


def record_workspace(session: Session, analysis: Analysis, workspace_path: str) -> Analysis:
    """Attach the disposable workspace path for cleanup reconciliation."""
    analysis.workspace_path = workspace_path
    session.flush()
    return analysis


def mark_failed(session: Session, analysis: Analysis, explanation: str) -> Analysis:
    """Terminal Failed outcome with a user-safe explanation (never internals)."""
    if analysis.outcome is not None:
        return analysis
    analysis.outcome = "Failed"
    analysis.completed_at = utcnow()
    analysis.explanation = explanation
    session.flush()
    return analysis


def terminal_outcomes() -> frozenset[str]:
    """Frozen terminal outcome values (docs/10 §7.2)."""
    return TERMINAL_OUTCOMES
