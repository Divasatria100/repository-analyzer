"""Ingestion lifecycle tests: orchestrator gate 1/2/4/5 (no network).

GitHub is mocked (transport returns the local fixture repo's SHA so the
resolved commit matches retrieved content); git runs against local fixture
repos only. SQLite backs persistence.
"""

from pathlib import Path

import httpx
import pytest
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings, load_settings
from app.core.database import create_session_factory
from app.models.base import Base
from app.models.repository import Analysis
from app.repository.concurrency import ConcurrencyManager
from app.repository.errors import (
    ConcurrencyExhaustedError,
    InvalidRepositoryUrlError,
    RepositoryNotFoundError,
    RetrievalIncompleteError,
    RetrievalSizeLimitError,
)
from app.repository.github import GitHubClient
from app.repository.ingestion import IngestionResult, ingest_repository
from app.repository.retrieval import RetrievalService
from app.repository.workspace import WorkspaceManager
from app.services.http_client import RetryPolicy, ServiceClient
from tests.fixtures.helpers.repo_helpers import init_git_repo
from tests.mocks.github import COMMIT_SHA, DEFAULT_BRANCH, OWNER, REPO

pytestmark = pytest.mark.security

REPO_URL = f"https://github.com/{OWNER}/{REPO}"


def _github_transport(head_sha: str, *, size_kb: int = 128) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == f"/repos/{OWNER}/{REPO}":
            return httpx.Response(
                200,
                json={
                    "id": 1001,
                    "name": REPO,
                    "full_name": f"{OWNER}/{REPO}",
                    "private": False,
                    "default_branch": DEFAULT_BRANCH,
                    "size": size_kb,
                },
            )
        if path == f"/repos/{OWNER}/{REPO}/branches/{DEFAULT_BRANCH}":
            return httpx.Response(200, json={"name": DEFAULT_BRANCH, "commit": {"sha": head_sha}})
        if path.startswith(f"/repos/{OWNER}/{REPO}/commits/"):
            return httpx.Response(200, json={"sha": head_sha, "commit": {}})
        return httpx.Response(404, json={"message": "No mock route"})

    return httpx.MockTransport(handler)


def _not_found_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(404, json={"message": "nf"}))


def _service_client(transport: httpx.MockTransport) -> ServiceClient:
    return ServiceClient(
        name="github-test",
        base_url="https://api.github.com",
        retry_policy=RetryPolicy(max_retries=0, backoff_base_s=0),
        transport=transport,
    )


def _open_session() -> tuple[Engine, Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, create_session_factory(engine)()


def _ingest(
    tmp_path: Path,
    files: dict[str, str],
    **kwargs: object,
) -> tuple[IngestionResult, Session, Engine, WorkspaceManager, str]:
    source = tmp_path / "source"
    head = init_git_repo(source, files)
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(head)))
    try:
        result = ingest_repository(
            raw_url=REPO_URL,
            settings=settings,
            session=session,
            github=github,
            workspaces=workspaces,
            retrieval=RetrievalService.from_settings(settings),
            concurrency=ConcurrencyManager(2),
            remote_url_override=str(source),
            allow_local_paths=True,
            **kwargs,  # type: ignore[arg-type]
        )
        return result, session, engine, workspaces, head
    except Exception:
        session.close()
        engine.dispose()
        raise


def test_happy_path_records_immutable_context(tmp_path: Path) -> None:
    source = tmp_path / "source"
    head = init_git_repo(source, {"main.py": "x = 1\n"})
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(head)))
    try:
        result = ingest_repository(
            raw_url=REPO_URL,
            settings=settings,
            session=session,
            github=github,
            workspaces=workspaces,
            retrieval=RetrievalService.from_settings(settings),
            concurrency=ConcurrencyManager(2),
            remote_url_override=str(source),
            allow_local_paths=True,
        )
        assert isinstance(result, IngestionResult)
        assert result.context.resolved_commit_sha == head
        assert result.context.resolved_branch == DEFAULT_BRANCH
        assert result.context.branch_origin == "defaulted"
        assert result.context.commit_origin == "defaulted"
        assert (result.workspace / "main.py").exists()
        assert result.retrieval.status.value == "completed"
        row = session.get(Analysis, result.context.analysis_id)
        assert row is not None
        assert row.resolved_commit_sha == head
        # Indexing, language detection, and parsing run in the orchestrator.
        assert row.stage == "BuildingCodeModel"
        assert row.outcome is None
        assert row.workspace_path == str(result.workspace)
        assert session.scalar(text("SELECT COUNT(*) FROM repositories")) == 1
    finally:
        session.close()
        engine.dispose()


def test_requested_branch_and_commit_recorded(tmp_path: Path) -> None:
    # Any well-formed requested commit resolves (mock) to the local HEAD.
    result, session, engine, workspaces, head = _ingest(
        tmp_path,
        {"main.py": "x = 1\n"},
        requested_branch=DEFAULT_BRANCH,
        requested_commit="c" * 40,
    )
    try:
        # Mock resolves any requested commit to the local HEAD.
        assert result.context.branch_origin == "requested"
        assert result.context.commit_origin == "requested"
        assert result.context.resolved_commit_sha == head
    finally:
        session.close()
        engine.dispose()


def test_invalid_url_persists_nothing(tmp_path: Path) -> None:
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(COMMIT_SHA)))
    try:
        with pytest.raises(InvalidRepositoryUrlError):
            ingest_repository(
                raw_url="https://gitlab.com/acme/web",
                settings=settings,
                session=session,
                github=github,
                workspaces=workspaces,
                retrieval=RetrievalService.from_settings(settings),
                concurrency=ConcurrencyManager(2),
            )
        assert session.scalar(text("SELECT COUNT(*) FROM repositories")) == 0
        assert session.scalar(text("SELECT COUNT(*) FROM analyses")) == 0
    finally:
        session.close()
        engine.dispose()


def test_unknown_repository_persists_nothing(tmp_path: Path) -> None:
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_not_found_transport()))
    try:
        with pytest.raises(RepositoryNotFoundError):
            ingest_repository(
                raw_url=REPO_URL,
                settings=settings,
                session=session,
                github=github,
                workspaces=workspaces,
                retrieval=RetrievalService.from_settings(settings),
                concurrency=ConcurrencyManager(2),
            )
        assert session.scalar(text("SELECT COUNT(*) FROM analyses")) == 0
    finally:
        session.close()
        engine.dispose()


def test_retrieval_failure_cleans_workspace_and_marks_failed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    head = init_git_repo(source, {"main.py": "x = 1\n"})
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(head)))
    try:
        with pytest.raises(RetrievalIncompleteError):
            ingest_repository(
                raw_url=REPO_URL,
                settings=settings,
                session=session,
                github=github,
                workspaces=workspaces,
                retrieval=RetrievalService.from_settings(settings),
                concurrency=ConcurrencyManager(2),
                remote_url_override=str(source / "missing"),
                allow_local_paths=True,
            )
        row = session.scalar(select(Analysis).limit(1))
        assert row is not None
        assert row.outcome == "Failed"
        assert row.explanation
        assert "traceback" not in row.explanation.lower()
        assert [p for p in workspaces.root.iterdir()] == []
    finally:
        session.close()
        engine.dispose()


def test_concurrency_exhaustion_rejects_third(tmp_path: Path) -> None:
    source = tmp_path / "source"
    head = init_git_repo(source, {"main.py": "x = 1\n"})
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(head)))
    concurrency = ConcurrencyManager(2)
    try:
        with concurrency.acquire("holder-1"), concurrency.acquire("holder-2"):
            with pytest.raises(ConcurrencyExhaustedError) as exc_info:
                ingest_repository(
                    raw_url=REPO_URL,
                    settings=settings,
                    session=session,
                    github=github,
                    workspaces=workspaces,
                    retrieval=RetrievalService.from_settings(settings),
                    concurrency=concurrency,
                    remote_url_override=str(source),
                    allow_local_paths=True,
                )
        assert exc_info.value.contract_code == "RATE_LIMITED"
    finally:
        session.close()
        engine.dispose()


def test_oversize_repository_rejected_before_persistence(tmp_path: Path) -> None:
    source = tmp_path / "source"
    init_git_repo(source, {"main.py": "x = 1\n"})
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(COMMIT_SHA, size_kb=300 * 1024)))
    try:
        with pytest.raises(RetrievalSizeLimitError):
            ingest_repository(
                raw_url=REPO_URL,
                settings=settings,
                session=session,
                github=github,
                workspaces=workspaces,
                retrieval=RetrievalService.from_settings(settings),
                concurrency=ConcurrencyManager(2),
                remote_url_override=str(source),
                allow_local_paths=True,
            )
        assert session.scalar(text("SELECT COUNT(*) FROM analyses")) == 0
    finally:
        session.close()
        engine.dispose()


def test_settings_type_is_settings() -> None:
    settings: Settings = load_settings()
    assert settings.operational.repo_max_size_bytes == 200 * 1024 * 1024


def test_index_persisted_for_ingested_snapshot(tmp_path: Path) -> None:
    from app.models.repository import Analysis
    from app.repositories import indexing as index_gateway

    result, session, engine, workspaces, head = _ingest(
        tmp_path,
        {"main.py": "x = 1\n", "docs/guide.md": "# hi\n"},
    )
    try:
        # M1: file rows belong to this analysis snapshot, index is complete.
        assert result.index.complete is True
        assert result.index.limitations == []
        rows = index_gateway.get_files(session, result.context.analysis_id)
        by_path = {row.path: row for row in rows}
        assert set(by_path) == {"main.py", "docs/guide.md"}
        assert by_path["main.py"].eligibility == "eligible"
        assert by_path["main.py"].language == "python"
        assert by_path["main.py"].parse_result == "parsed"
        assert by_path["main.py"].diagnostics == []
        assert by_path["docs/guide.md"].eligibility == "not_eligible"
        assert by_path["docs/guide.md"].parse_result is None
        assert index_gateway.get_limitations(session, result.context.analysis_id) == []
        row = session.get(Analysis, result.context.analysis_id)
        assert row is not None and row.stage == "BuildingCodeModel"
    finally:
        session.close()
        engine.dispose()


def test_indexing_failure_cleans_workspace_and_marks_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.repository.ingestion as orchestrator
    from app.models.repository import Analysis
    from app.repository.errors import IndexingError

    source = tmp_path / "source"
    head = init_git_repo(source, {"main.py": "x = 1\n"})
    settings = load_settings()
    engine, session = _open_session()
    workspaces = WorkspaceManager(tmp_path / "workspaces")
    github = GitHubClient(_service_client(_github_transport(head)))

    def _boom(**kwargs: object) -> object:
        raise IndexingError("injected indexing failure")

    monkeypatch.setattr(orchestrator, "index_workspace", _boom)
    try:
        with pytest.raises(IndexingError):
            ingest_repository(
                raw_url=REPO_URL,
                settings=settings,
                session=session,
                github=github,
                workspaces=workspaces,
                retrieval=RetrievalService.from_settings(settings),
                concurrency=ConcurrencyManager(2),
                remote_url_override=str(source),
                allow_local_paths=True,
            )
        row = session.scalar(select(Analysis).order_by(Analysis.created_at.desc()).limit(1))
        # Workspace cleaned, analysis Failed, nothing half-indexed.
        assert row is not None and row.outcome == "Failed"
        assert row.explanation == "injected indexing failure"
        assert list(workspaces.root.iterdir()) == []
        assert session.scalar(text("SELECT COUNT(*) FROM files")) == 0
    finally:
        session.close()
        engine.dispose()
