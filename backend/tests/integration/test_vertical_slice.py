"""Vertical-slice tests: VS-001 submission → VS-002 retrieval/index/languages.

POST acceptance is exercised through the real API (dispatcher override
records the dispatch instead of running retrieval); the runner is then
invoked explicitly with a local fixture remote (the sanctioned
test-only override), and every assertion checks persisted rows, lifecycle
state, filesystem effects, and API responses — never mere call counts.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.pool import StaticPool

from app.api.deps import (
    get_analysis_dispatcher,
    get_concurrency_manager,
    get_db,
    get_github_client,
    get_retrieval_service,
    get_workspace_manager,
    reset_session_factory,
)
from app.core.config import Settings, load_settings
from app.core.database import create_session_factory, session_scope
from app.main import create_app
from app.models.base import Base
from app.models.indexing import File, Limitation
from app.models.repository import Analysis as AnalysisModel
from app.models.results import AnalysisSnapshot
from app.repositories import ingestion as persistence
from app.repository.concurrency import ConcurrencyManager
from app.repository.errors import IndexingError, RetrievalError
from app.repository.github import GitHubClient
from app.repository.identity import RepositoryIdentity
from app.repository.ingestion import continue_ingestion
from app.repository.retrieval import RetrievalService
from app.repository.runner import RunnerDependencies, run_analysis_to_index
from app.repository.workspace import WorkspaceManager
from app.services.http_client import RetryPolicy, ServiceClient
from tests.fixtures.helpers.repo_helpers import init_git_repo
from tests.mocks.github import COMMIT_SHA, DEFAULT_BRANCH, OWNER, REPO

pytestmark = pytest.mark.integration

FIXTURE_URL = f"https://github.com/{OWNER}/{REPO}"
FIXTURE_FILES = {
    "app/main.py": "def main():\n    return 1\n",
    "app/util.py": "VALUE = 2\n",
    "web/app.js": "const x = 1;\n",
    "README.md": "# Fixture\n",
    "notes.txt": "plain text\n",
    "requirements.txt": "requests==2.31.0\n",
}

# Static user-safe explanations the API may legitimately surface. Failed
# outcomes must carry one of these — never paths, URLs, or tracebacks.
KNOWN_EXPLANATIONS = frozenset(
    {
        "The repository content could not be found and was not analyzed.",
        "The repository content is not accessible and was not analyzed.",
        "The repository could not be downloaded and was not analyzed.",
        "The repository download was incomplete and was not analyzed.",
        "Retrieving the repository took too long and was stopped.",
        "The repository could not be downloaded due to a connection problem.",
        "The repository exceeds a configured size limit and was not analyzed.",
        "The repository could not be retrieved safely and was not analyzed.",
        "The repository index could not be built.",
        "The analysis workspace could not be prepared.",
        "Too many analyses are running. Please try again later.",
        "The analysis could not be completed.",
    }
)


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


def _service_client(transport: httpx.MockTransport) -> ServiceClient:
    return ServiceClient(
        name="github-test",
        base_url="https://api.github.com",
        retry_policy=RetryPolicy(max_retries=0, backoff_base_s=0),
        transport=transport,
    )


def _factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, create_session_factory(engine)


def _github(head_sha: str) -> GitHubClient:
    return GitHubClient(_service_client(_github_transport(head_sha)))


class _Recorder:
    """Test dispatcher: records dispatches instead of running retrieval."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, RunnerDependencies]] = []

    def __call__(self, analysis_id: str, deps: RunnerDependencies) -> None:
        self.calls.append((analysis_id, deps))


def _slice_client(factory, github: GitHubClient, recorder: _Recorder, workspace_root: Path):
    reset_session_factory()
    application = create_app(Settings(environment="test"))

    def override_db():
        with session_scope(factory) as session:
            yield session

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[get_github_client] = lambda: github
    application.dependency_overrides[get_analysis_dispatcher] = lambda: recorder
    application.dependency_overrides[get_workspace_manager] = lambda: WorkspaceManager(
        workspace_root
    )
    application.dependency_overrides[get_retrieval_service] = lambda: (
        RetrievalService.from_settings(load_settings())
    )
    application.dependency_overrides[get_concurrency_manager] = lambda: ConcurrencyManager(4)
    return TestClient(application, raise_server_exceptions=False)


def _runner_deps(
    factory,
    github: GitHubClient,
    workspace_root: Path,
    concurrency: ConcurrencyManager | None = None,
) -> RunnerDependencies:
    return RunnerDependencies(
        settings=load_settings(),
        session_factory=factory,
        workspaces=WorkspaceManager(workspace_root),
        retrieval=RetrievalService.from_settings(load_settings()),
        github=github,
        concurrency=concurrency or ConcurrencyManager(4),
    )


def _seed_post(factory, client: TestClient, **body: object) -> dict:
    payload = {"url": FIXTURE_URL}
    payload.update(body)  # type: ignore[arg-type]
    response = client.post("/api/analyses", json=payload)
    assert response.status_code == 202, response.text
    return response.json()


def _row_counts(factory, analysis_id: str) -> dict[str, int]:
    with session_scope(factory) as session:
        files = session.scalar(
            select(func.count()).select_from(File).where(File.analysis_id == analysis_id)
        )
        limitations = session.scalar(
            select(func.count())
            .select_from(Limitation)
            .where(Limitation.analysis_id == analysis_id)
        )
        snapshots = session.scalar(
            select(func.count())
            .select_from(AnalysisSnapshot)
            .where(AnalysisSnapshot.analysis_id == analysis_id)
        )
        return {"files": files or 0, "limitations": limitations or 0, "snapshots": snapshots or 0}


def _analysis_state(factory, analysis_id: str) -> AnalysisModel:
    with session_scope(factory) as session:
        analysis = session.get(AnalysisModel, analysis_id)
        assert analysis is not None
        session.expunge(analysis)
        return analysis


def test_post_accepts_persists_and_dispatches(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client, branch="main")
        assert created["stage"] == "Queued"
        assert len(recorder.calls) == 1
        assert recorder.calls[0][0] == created["analysis_id"]
        analysis = _analysis_state(factory, created["analysis_id"])
        assert analysis.stage == "Queued" and analysis.outcome is None
        assert analysis.repository_id == created["repository_id"]
        assert analysis.requested_branch == "main"
        # Acceptance persisted; nothing executed yet (dispatcher only recorded).
        assert list((tmp_path / "workspaces").glob("ws-*")) == []
        assert _row_counts(factory, created["analysis_id"]) == {
            "files": 0,
            "limitations": 0,
            "snapshots": 0,
        }
    finally:
        engine.dispose()


def test_invalid_url_persists_nothing(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        client = _slice_client(factory, _github(COMMIT_SHA), recorder, tmp_path / "workspaces")
        response = client.post("/api/analyses", json={"url": "https://gitlab.com/acme/web"})
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "INVALID_URL"
        assert recorder.calls == []
        with session_scope(factory) as session:
            analyses = session.scalar(select(func.count()).select_from(AnalysisModel))
            assert analyses == 0
    finally:
        engine.dispose()


def test_runner_completes_slice_and_persists_index(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        run_analysis_to_index(
            analysis_id=created["analysis_id"],
            deps=_runner_deps(factory, _github(head), tmp_path / "workspaces"),
            remote_url_override=str(source),
            allow_local_paths=True,
        )
        analysis = _analysis_state(factory, created["analysis_id"])
        assert analysis.stage == "DetectingLanguages"
        assert analysis.outcome is None
        assert analysis.resolved_commit_sha == head
        assert analysis.branch_origin == "defaulted"
        assert analysis.commit_origin == "defaulted"
        assert analysis.workspace_path is not None
        assert Path(analysis.workspace_path).is_dir()
        assert (Path(analysis.workspace_path) / "app" / "main.py").is_file()
        # Clone metadata removed; snapshot content retained.
        assert not (Path(analysis.workspace_path) / ".repolens-git").exists()

        with session_scope(factory) as session:
            files = session.scalars(
                select(File).where(File.analysis_id == created["analysis_id"])
            ).all()
            by_path = {item.path: item for item in files}
            assert set(by_path) == set(FIXTURE_FILES)
            assert by_path["app/main.py"].language == "python"
            assert by_path["web/app.js"].language == "javascript"
            assert by_path["README.md"].language == "markdown"
            assert all(item.parse_result is None for item in files)
        counts = _row_counts(factory, created["analysis_id"])
        assert counts["files"] == len(FIXTURE_FILES)
        assert counts["snapshots"] == 0

        body = client.get(f"/api/analyses/{created['analysis_id']}").json()
        assert body["status"]["stage"] == "DetectingLanguages"
        assert body["status"]["outcome"] is None
        assert body["summary"] is None and body["files"] is None
    finally:
        engine.dispose()


def test_runner_retrieval_failure_marks_failed_and_cleans(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        with pytest.raises(RetrievalError):
            run_analysis_to_index(
                analysis_id=created["analysis_id"],
                deps=_runner_deps(factory, _github(head), tmp_path / "workspaces"),
                remote_url_override=str(tmp_path / "does-not-exist"),
                allow_local_paths=True,
            )
        analysis = _analysis_state(factory, created["analysis_id"])
        assert analysis.outcome == "Failed"
        assert analysis.explanation in KNOWN_EXPLANATIONS
        assert str(tmp_path) not in (analysis.explanation or "")
        assert list((tmp_path / "workspaces").glob("ws-*")) == []
        assert _row_counts(factory, created["analysis_id"])["files"] == 0

        body = client.get(f"/api/analyses/{created['analysis_id']}").json()
        assert body["status"]["outcome"] == "Failed"
        assert body["status"]["explanation"] in KNOWN_EXPLANATIONS
        assert body["security"] is None and body["files"] is None
    finally:
        engine.dispose()


def test_runner_indexing_failure_marks_failed_and_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)

        def _boom(*args: object, **kwargs: object):
            raise IndexingError("The repository index could not be built.")

        monkeypatch.setattr("app.repository.ingestion.index_workspace", _boom)
        try:
            run_analysis_to_index(
                analysis_id=created["analysis_id"],
                deps=_runner_deps(factory, _github(head), tmp_path / "workspaces"),
                remote_url_override=str(source),
                allow_local_paths=True,
            )
        except IndexingError:
            pass
        analysis = _analysis_state(factory, created["analysis_id"])
        assert analysis.outcome == "Failed"
        assert analysis.explanation == "The repository index could not be built."
        assert list((tmp_path / "workspaces").glob("ws-*")) == []
        assert _row_counts(factory, created["analysis_id"])["files"] == 0
    finally:
        engine.dispose()


def test_runner_concurrency_exhaustion_fails_actionably(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        concurrency = ConcurrencyManager(1)
        with concurrency.acquire("other-analysis"):
            run_analysis_to_index(
                analysis_id=created["analysis_id"],
                deps=_runner_deps(
                    factory, _github(head), tmp_path / "workspaces", concurrency=concurrency
                ),
                remote_url_override=str(source),
                allow_local_paths=True,
            )
        analysis = _analysis_state(factory, created["analysis_id"])
        assert analysis.outcome == "Failed"
        assert analysis.explanation == "Too many analyses are running. Please try again later."
        assert _row_counts(factory, created["analysis_id"])["files"] == 0
    finally:
        engine.dispose()


def test_runner_is_idempotent_and_skips_settled(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        deps = _runner_deps(factory, _github(head), tmp_path / "workspaces")
        run_analysis_to_index(
            analysis_id=created["analysis_id"],
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
        )
        first = _row_counts(factory, created["analysis_id"])
        run_analysis_to_index(
            analysis_id=created["analysis_id"],
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
        )
        assert _row_counts(factory, created["analysis_id"]) == first
        assert _analysis_state(factory, created["analysis_id"]).stage == "DetectingLanguages"

        # A terminal analysis is never touched again.
        with session_scope(factory) as session:
            analysis = session.get(AnalysisModel, created["analysis_id"])
            assert analysis is not None
            persistence.mark_failed(session, analysis, "boom")
        run_analysis_to_index(
            analysis_id=created["analysis_id"],
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
        )
        assert _analysis_state(factory, created["analysis_id"]).explanation == "boom"

        # Unknown ids are a quiet no-op.
        run_analysis_to_index(
            analysis_id="0" * 32,
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
        )
    finally:
        engine.dispose()


def test_runner_refuses_rerun_after_stage_advance(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        with session_scope(factory) as session:
            analysis = session.get(AnalysisModel, created["analysis_id"])
            assert analysis is not None
            persistence.set_stage(session, analysis, "RetrievingRepository")
        run_analysis_to_index(
            analysis_id=created["analysis_id"],
            deps=_runner_deps(factory, _github(head), tmp_path / "workspaces"),
            remote_url_override=str(source),
            allow_local_paths=True,
        )
        state = _analysis_state(factory, created["analysis_id"])
        assert state.stage == "RetrievingRepository" and state.outcome is None
        assert _row_counts(factory, created["analysis_id"])["files"] == 0
    finally:
        engine.dispose()


def test_continue_ingestion_stops_at_language_detection(tmp_path: Path) -> None:
    """VS-002 boundary: DetectingLanguages set, parse phase never runs."""
    engine, factory = _factory()
    try:
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        settings = load_settings()
        with session_scope(factory) as session:
            repository = persistence.get_or_create_repository(
                session, RepositoryIdentity(owner=OWNER, name=REPO)
            )
            analysis = persistence.create_analysis(
                session,
                repository,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0",
            )
            analysis_id = analysis.id
        with session_scope(factory) as session:
            analysis = session.get(AnalysisModel, analysis_id)
            assert analysis is not None
            result = continue_ingestion(
                session=session,
                analysis=analysis,
                identity=RepositoryIdentity(owner=OWNER, name=REPO),
                default_branch=DEFAULT_BRANCH,
                settings=settings,
                github=_github(head),
                workspaces=WorkspaceManager(tmp_path / "workspaces"),
                retrieval=RetrievalService.from_settings(settings),
                concurrency=ConcurrencyManager(2),
                remote_url_override=str(source),
                allow_local_paths=True,
            )
            assert result.context.resolved_commit_sha == head
        state = _analysis_state(factory, analysis_id)
        assert state.stage == "DetectingLanguages" and state.outcome is None
    finally:
        engine.dispose()
