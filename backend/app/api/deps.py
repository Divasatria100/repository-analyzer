"""FastAPI dependencies (foundation).

Providers that route FastAPI request handling to centralized
configuration and infrastructure factories. Analysis logic never
lives here (see docs/11 §7.1).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from fastapi import BackgroundTasks
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.database import create_engine_from_settings, create_session_factory, session_scope
from app.repository.concurrency import ConcurrencyManager
from app.repository.github import GitHubClient, github_client_from_settings
from app.repository.retrieval import RetrievalService
from app.repository.runner import RunnerDependencies, run_analysis_to_index
from app.repository.workspace import WorkspaceManager

_session_factory: sessionmaker[Session] | None = None
_workspace_manager: WorkspaceManager | None = None
_retrieval_service: RetrievalService | None = None
_concurrency_manager: ConcurrencyManager | None = None


def get_settings_dep() -> Settings:
    """Provide the centralized application settings."""
    return get_settings()


def get_session_factory() -> sessionmaker[Session]:
    """Lazily build the session factory (no I/O at import time).

    Takes no parameters: a ``Settings``-typed parameter would make
    FastAPI treat this sub-dependency as expecting a request body
    field and break body parsing on every route that uses it.
    """
    global _session_factory
    if _session_factory is None:
        engine = create_engine_from_settings(get_settings().database)
        _session_factory = create_session_factory(engine)
    return _session_factory


def reset_session_factory() -> None:
    """Reset the cached factory (tests only)."""
    global _session_factory
    global _workspace_manager
    global _retrieval_service
    global _concurrency_manager
    _session_factory = None
    _workspace_manager = None
    _retrieval_service = None
    _concurrency_manager = None


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a transactional session."""
    with session_scope(get_session_factory()) as session:
        yield session


def get_github_client() -> GitHubClient:
    """Build the GitHub metadata gateway (no I/O at construction).

    Tests override this dependency with a mock-transport client; production
    derives the remote only from the validated repository identity.
    """
    return github_client_from_settings(get_settings())


def get_workspace_manager() -> WorkspaceManager:
    """Cached workspace root owner (created lazily, no I/O at import)."""
    global _workspace_manager
    if _workspace_manager is None:
        _workspace_manager = WorkspaceManager(get_settings().workspace.resolved_root())
    return _workspace_manager


def get_retrieval_service() -> RetrievalService:
    """Cached retrieval service built from centralized settings."""
    global _retrieval_service
    if _retrieval_service is None:
        _retrieval_service = RetrievalService.from_settings(get_settings())
    return _retrieval_service


def get_concurrency_manager() -> ConcurrencyManager:
    """Process-wide analysis slot manager (must stay a singleton)."""
    global _concurrency_manager
    if _concurrency_manager is None:
        _concurrency_manager = ConcurrencyManager(
            get_settings().operational.concurrency_max_analyses
        )
    return _concurrency_manager


#: Dispatch of accepted analyses to post-acceptance execution.
AnalysisDispatch = Callable[[str, RunnerDependencies], None]


def get_analysis_dispatcher(background_tasks: BackgroundTasks) -> AnalysisDispatch:
    """Schedule execution after the 202 response (in-process, no broker).

    The seam exists so execution runs outside the request transaction;
    tests override it to observe dispatch without running retrieval.
    """

    def dispatch(analysis_id: str, deps: RunnerDependencies) -> None:
        background_tasks.add_task(run_analysis_to_index, analysis_id=analysis_id, deps=deps)

    return dispatch
