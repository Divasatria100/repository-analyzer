"""Post-acceptance execution for VS-001 → VS-002 (TASK-218).

Small, testable orchestration boundary between request acceptance and
retrieval/indexing: given a persisted analysis id, load it in a fresh
session and continue it through language detection using the existing
ingestion continuation. No new pipeline, broker, or worker platform —
callers dispatch this function (e.g. FastAPI BackgroundTasks) and it owns
its own transaction.

Boundaries:
- Only analyses still in Queued stage are claimed; anything else is left
  untouched so retries or concurrent dispatches cannot duplicate work.
- Terminal outcomes are never touched; an unknown id is a no-op.
- Unexpected failures mark the analysis Failed with a user-safe message
  (never internals) instead of leaving it Queued forever.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.database import session_scope
from app.core.logging import get_logger, log_event
from app.models.repository import Analysis, Repository
from app.repositories import ingestion as persistence
from app.repository.concurrency import ConcurrencyManager
from app.repository.errors import ConcurrencyExhaustedError, IngestionError
from app.repository.github import GitHubClient
from app.repository.identity import normalize_github_url
from app.repository.ingestion import continue_ingestion
from app.repository.retrieval import RetrievalService
from app.repository.workspace import WorkspaceManager

_logger = get_logger("analysis_runner")


@dataclass(frozen=True)
class RunnerDependencies:
    """Everything ``run_analysis_to_index`` needs (resolved by the caller)."""

    settings: Settings
    session_factory: sessionmaker[Session]
    workspaces: WorkspaceManager
    retrieval: RetrievalService
    github: GitHubClient
    concurrency: ConcurrencyManager


def run_analysis_to_index(
    *,
    analysis_id: str,
    deps: RunnerDependencies,
    remote_url_override: str | None = None,
    allow_local_paths: bool = False,
) -> None:
    """Continue one persisted analysis through language detection.

    ``remote_url_override`` + ``allow_local_paths`` exist ONLY so tests can
    retrieve local fixture repositories; production callers must omit them.
    """
    with session_scope(deps.session_factory) as session:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            log_event(
                _logger,
                logging.WARNING,
                "analysis.runner.unknown",
                "Runner invoked for unknown analysis; nothing to do",
                analysis_id=analysis_id,
            )
            return
        if analysis.outcome is not None or analysis.stage != "Queued":
            log_event(
                _logger,
                logging.INFO,
                "analysis.runner.skipped",
                "Runner skipping non-queued analysis",
                analysis_id=analysis_id,
                stage=analysis.stage,
                outcome=analysis.outcome,
            )
            return
        repository = session.get(Repository, analysis.repository_id)
        if repository is None:
            persistence.mark_failed(session, analysis, "The analysis could not be completed.")
            return
        identity = normalize_github_url(repository.normalized_url)
        try:
            default_branch = repository.default_branch
            if not default_branch:
                default_branch = deps.github.get_repository(identity).default_branch
            continue_ingestion(
                session=session,
                analysis=analysis,
                identity=identity,
                default_branch=default_branch,
                requested_branch=analysis.requested_branch,
                requested_commit=analysis.requested_commit,
                settings=deps.settings,
                github=deps.github,
                workspaces=deps.workspaces,
                retrieval=deps.retrieval,
                concurrency=deps.concurrency,
                remote_url_override=remote_url_override,
                allow_local_paths=allow_local_paths,
            )
        except ConcurrencyExhaustedError as exc:
            persistence.mark_failed(session, analysis, exc.user_message)
        except IngestionError as exc:
            # Retrieval/indexing failures are already recorded by the
            # continuation; anything else gets its user-safe message.
            # F-1: commit the Failed state explicitly — mark_failed only
            # flushes, and the re-raise below would otherwise roll the
            # whole scope back to Queued.
            if analysis.outcome is None:
                persistence.mark_failed(session, analysis, exc.user_message)
                session.commit()
            log_event(
                _logger,
                logging.WARNING,
                "analysis.runner.failed",
                "Analysis execution failed",
                analysis_id=analysis_id,
                reason=type(exc).__name__,
            )
            raise
        except Exception as exc:
            # F-1: same durability requirement as above — the Failed mark
            # must survive the re-raise through session_scope.
            persistence.mark_failed(session, analysis, "The analysis could not be completed.")
            session.commit()
            log_event(
                _logger,
                logging.ERROR,
                "analysis.runner.unexpected",
                "Analysis execution failed unexpectedly",
                analysis_id=analysis_id,
                error_type=type(exc).__name__,
            )
            raise
        log_event(
            _logger,
            logging.INFO,
            "analysis.runner.completed",
            "Analysis reached language detection",
            analysis_id=analysis_id,
            stage=analysis.stage,
        )
