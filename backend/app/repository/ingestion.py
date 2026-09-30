"""Repository-ingestion lifecycle coordinator (docs/10 §§5.1–5.5).

Conceptual flow (stops cleanly at the ingestion boundary; parsing and
later stages arrive in later phases):

```text
Validate URL -> Validate Public Repository -> Retrieve Metadata
  -> Resolve Branch -> Resolve Commit -> Persist Analysis Context
  -> Acquire Analysis Slot -> Create Workspace -> Retrieve Immutable Commit
  -> Validate Retrieval Result -> Index Files -> Detect Languages
```

Indexing and language detection run here because the workspace snapshot is
their only input; parsing and later stages arrive in later phases (the
analysis row therefore rests at DetectingLanguages with no outcome).

Validation failures happen before any persistence (docs/12 §6.3);
retrieval or indexing failures clean the workspace and mark the analysis
Failed with a user-safe explanation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger, log_event
from app.models.repository import ORIGIN_DEFAULTED, ORIGIN_REQUESTED
from app.repositories import ingestion as persistence
from app.repository.concurrency import ConcurrencyManager
from app.repository.errors import IndexingError, RetrievalError
from app.repository.github import GitHubClient
from app.repository.identity import normalize_github_url
from app.repository.index_types import IndexResult
from app.repository.indexing import index_workspace
from app.repository.retrieval import RetrievalResult, RetrievalService, check_remote_size
from app.repository.workspace import WorkspaceManager

_logger = get_logger("ingestion")

# Initial rule-set version: no rules are implemented yet, but every analysis
# context must record the version its (future) results were produced under.
RULE_SET_VERSION = "1.0"


@dataclass(frozen=True)
class AnalysisContext:
    """Immutable resolved context: repository + branch + commit SHA."""

    analysis_id: str
    repository_id: str
    owner: str
    name: str
    canonical_url: str
    requested_branch: str | None
    requested_commit: str | None
    resolved_branch: str
    branch_origin: str
    resolved_commit_sha: str
    commit_origin: str
    analyzer_version: str
    rule_set_version: str


@dataclass(frozen=True)
class IngestionResult:
    """Successful ingestion: context, disposable workspace, retrieval report."""

    context: AnalysisContext
    workspace: Path
    retrieval: RetrievalResult
    index: IndexResult


def ingest_repository(
    *,
    raw_url: str,
    requested_branch: str | None = None,
    requested_commit: str | None = None,
    settings: Settings,
    session: Session,
    github: GitHubClient,
    workspaces: WorkspaceManager,
    retrieval: RetrievalService,
    concurrency: ConcurrencyManager,
    remote_url_override: str | None = None,
    allow_local_paths: bool = False,
) -> IngestionResult:
    """Run the ingestion lifecycle; raise domain errors on any failure.

    ``remote_url_override`` + ``allow_local_paths`` exist ONLY so tests can
    retrieve local fixture repositories; production calls must omit them
    (remote always derives from the validated identity).
    """
    identity = normalize_github_url(raw_url)
    metadata = github.get_repository(identity)
    check_remote_size(
        metadata.size_kb * 1024 if metadata.size_kb is not None else None,
        settings.operational.repo_max_size_bytes,
    )

    repository = persistence.get_or_create_repository(
        session, identity, default_branch=metadata.default_branch
    )
    analysis = persistence.create_analysis(
        session,
        repository,
        requested_branch=requested_branch,
        requested_commit=requested_commit,
        analyzer_version=settings.application.version,
        rule_set_version=RULE_SET_VERSION,
    )
    persistence.set_stage(session, analysis, "ValidatingRepository")
    persistence.set_stage(session, analysis, "ResolvingCommit")

    if requested_branch:
        branch = github.resolve_branch(identity, requested_branch)
        resolved_branch, branch_origin = branch.name, ORIGIN_REQUESTED
        branch_head_sha: str | None = branch.head_sha
    else:
        resolved_branch, branch_origin = metadata.default_branch, ORIGIN_DEFAULTED
        branch_head_sha = None

    if requested_commit:
        commit = github.resolve_commit(identity, requested_commit)
        resolved_sha, commit_origin = commit.sha, ORIGIN_REQUESTED
    else:
        if branch_head_sha is None:
            branch_head_sha = github.resolve_branch(identity, resolved_branch).head_sha
        resolved_sha, commit_origin = branch_head_sha, ORIGIN_DEFAULTED

    persistence.record_context_resolution(
        session,
        analysis,
        resolved_branch=resolved_branch,
        branch_origin=branch_origin,
        resolved_commit_sha=resolved_sha,
        commit_origin=commit_origin,
    )
    persistence.set_stage(session, analysis, "RetrievingRepository")

    context = AnalysisContext(
        analysis_id=analysis.id,
        repository_id=repository.id,
        owner=identity.owner,
        name=identity.name,
        canonical_url=identity.canonical_url,
        requested_branch=requested_branch,
        requested_commit=requested_commit,
        resolved_branch=resolved_branch,
        branch_origin=branch_origin,
        resolved_commit_sha=resolved_sha,
        commit_origin=commit_origin,
        analyzer_version=settings.application.version,
        rule_set_version=RULE_SET_VERSION,
    )

    with concurrency.acquire(analysis.id):
        workspace = workspaces.create(analysis.id)
        persistence.record_workspace(session, analysis, str(workspace))
        try:
            result = retrieval.retrieve(
                identity=identity,
                commit_sha=resolved_sha,
                workspace=workspace,
                remote_url=remote_url_override,
                allow_local_paths=allow_local_paths,
            )
        except RetrievalError as exc:
            workspaces.cleanup(workspace, analysis.id)
            persistence.mark_failed(session, analysis, exc.user_message)
            session.commit()
            raise
        persistence.set_stage(session, analysis, "IndexingFiles")
        try:
            index = index_workspace(
                workspace=workspace,
                analysis_id=analysis.id,
                settings=settings,
                session=session,
            )
        except IndexingError as exc:
            workspaces.cleanup(workspace, analysis.id)
            persistence.mark_failed(session, analysis, exc.user_message)
            session.commit()
            raise
        persistence.set_stage(session, analysis, "DetectingLanguages")
    log_event(
        _logger,
        logging.INFO,
        "repository.retrieval.completed",
        "Ingestion finished at retrieval boundary",
        analysis_id=analysis.id,
        repository=identity.full_name,
    )
    session.commit()
    return IngestionResult(context=context, workspace=workspace, retrieval=result, index=index)
