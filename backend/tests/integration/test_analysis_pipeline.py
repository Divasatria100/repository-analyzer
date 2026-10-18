"""VS-003/VS-004 vertical slice: parse → NCM → analyze → persist → seal.

The production orchestrator ``run_analysis_pipeline`` is driven through the
sanctioned test-only overrides (local fixture remote, in-memory providers)
after a real POST acceptance. Every assertion checks persisted rows, the
terminal lifecycle, the sealed snapshot, and the read API — never mere
call counts.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi import BackgroundTasks
from sqlalchemy import func, select

from app.analysis import run_analysis_pipeline
from app.analyzers.dependency.osv import OsvClient
from app.analyzers.security.source import DictSourceProvider
from app.api.deps import get_analysis_dispatcher
from app.core.database import session_scope
from app.models.indexing import File, Limitation
from app.models.results import (
    AnalysisSnapshot,
    ArchitectureMetric,
    Dependency,
    DependencyAdvisory,
    DomainState,
    FileCoverage,
    Module,
    RuleEvaluation,
)
from app.repository.errors import RetrievalError
from tests.fixtures.helpers.dependency_helpers import mock_osv_client
from tests.fixtures.helpers.repo_helpers import init_git_repo
from tests.integration.test_vertical_slice import (
    _analysis_state,
    _factory,
    _github,
    _Recorder,
    _runner_deps,
    _seed_post,
    _slice_client,
)

pytestmark = pytest.mark.integration

#: A small but complete repository: a cross-module cycle (architecture),
#: declared sources (security/code-structure), and a manifest (dependency).
FIXTURE_FILES = {
    "app/__init__.py": "",
    "app/main.py": (
        "from app.services.alpha import alpha\n"
        "from app.services.beta import beta\n\n\n"
        "def main():\n"
        "    return alpha() + beta()\n"
    ),
    "app/services/__init__.py": "",
    "app/services/alpha.py": (
        "from app.services.beta import beta\n\n\ndef alpha():\n    return beta() + 1\n"
    ),
    "app/services/beta.py": (
        "from app.services.alpha import alpha\n\n\ndef beta():\n    return 1\n"
    ),
    "requirements.txt": "requests==2.31.0\n",
    "README.md": "# Fixture\n",
}

_SUPPORTED_SOURCE = {path: text for path, text in FIXTURE_FILES.items() if path.endswith(".py")}


def _count(factory, model, analysis_id: str) -> int:
    with session_scope(factory) as session:
        return int(
            session.scalar(
                select(func.count()).select_from(model).where(model.analysis_id == analysis_id)
            )
            or 0
        )


def _count_file_coverages(factory, analysis_id: str) -> int:
    with session_scope(factory) as session:
        return int(
            session.scalar(
                select(func.count())
                .select_from(FileCoverage)
                .join(File, File.id == FileCoverage.file_id)
                .where(File.analysis_id == analysis_id)
            )
            or 0
        )


def _count_advisories(factory, analysis_id: str) -> int:
    with session_scope(factory) as session:
        return int(
            session.scalar(
                select(func.count())
                .select_from(DependencyAdvisory)
                .join(Dependency, Dependency.id == DependencyAdvisory.dependency_id)
                .where(Dependency.analysis_id == analysis_id)
            )
            or 0
        )


def _pipeline_deps(factory, head: str, workspace_root: Path):
    return _runner_deps(factory, _github(head), workspace_root)


def test_pipeline_completes_slice_and_seals_snapshot(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]

        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )

        analysis = _analysis_state(factory, analysis_id)
        assert analysis.outcome in ("Completed", "Completed with limitations")
        assert analysis.resolved_commit_sha == head
        # The last pipeline stage is retained for operations (docs/13 §6.1).
        assert analysis.stage == "GeneratingReports"
        assert analysis.analysis_config is not None
        assert analysis.analysis_config["architecture"]["coupling_definition"] == "coupling-def-1"

        # The workspace is disposable and cleaned on success.
        assert list((tmp_path / "workspaces").glob("ws-*")) == []

        # Every result section is persisted, never inferred from absence.
        domain_states = _count(factory, DomainState, analysis_id)
        assert domain_states == 4
        rule_evaluations = _count(factory, RuleEvaluation, analysis_id)
        assert rule_evaluations == 29  # 12 SEC + 4 DEP + 9 ARCH + 4 CODE
        assert _count(factory, Module, analysis_id) >= 3
        assert _count(factory, ArchitectureMetric, analysis_id) >= 1
        assert _count_file_coverages(factory, analysis_id) >= 1
        assert _count(factory, Dependency, analysis_id) >= 1
        assert _count(factory, File, analysis_id) == len(FIXTURE_FILES)

        # A completed analysis is sealed exactly once.
        with session_scope(factory) as session:
            snapshot = session.scalar(
                select(AnalysisSnapshot).where(AnalysisSnapshot.analysis_id == analysis_id)
            )
            assert snapshot is not None
            assert snapshot.outcome == analysis.outcome

        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["status"]["outcome"] in ("Completed", "Completed with limitations")
        assert body["summary"] is not None
        assert body["files"] is not None
        assert body["architecture"] is not None
        assert body["dependencies"] is not None
        assert body["code_structure"] is not None
    finally:
        engine.dispose()


def test_pipeline_is_idempotent_and_skips_settled(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]
        deps = _pipeline_deps(factory, head, tmp_path / "workspaces")

        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )
        first = _count(factory, RuleEvaluation, analysis_id)
        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )
        assert _count(factory, RuleEvaluation, analysis_id) == first
        assert _count(factory, AnalysisSnapshot, analysis_id) == 1

        # Unknown ids are a quiet no-op.
        run_analysis_pipeline(analysis_id="0" * 32, deps=deps)
    finally:
        engine.dispose()


def test_pipeline_marks_failed_and_cleans_on_retrieval_failure(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]

        with pytest.raises(RetrievalError):
            run_analysis_pipeline(
                analysis_id=analysis_id,
                deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
                remote_url_override=str(tmp_path / "does-not-exist"),
                allow_local_paths=True,
            )

        analysis = _analysis_state(factory, analysis_id)
        assert analysis.outcome == "Failed"
        assert str(tmp_path) not in (analysis.explanation or "")
        assert list((tmp_path / "workspaces").glob("ws-*")) == []
        assert _count(factory, AnalysisSnapshot, analysis_id) == 0
        assert _count(factory, File, analysis_id) == 0
        assert _count(factory, Limitation, analysis_id) == 0
    finally:
        engine.dispose()


def test_pipeline_persistence_failure_never_reads_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MEDIUM-2: a mid-persistence failure yields Failed with no snapshot.

    Transaction boundaries are a design decision (docs/12 §15), but the
    logical requirements hold: a completed outcome is recorded only after
    all result records exist (constraint 20), and partly persisted results
    are never presented as complete (NFR-010). The failed retry is a no-op.
    """
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]

        def _boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("persistence failed")

        monkeypatch.setattr("app.analysis.pipeline.persist_findings", _boom)
        with pytest.raises(RuntimeError):
            run_analysis_pipeline(
                analysis_id=analysis_id,
                deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
                remote_url_override=str(source),
                allow_local_paths=True,
                source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
            )

        analysis = _analysis_state(factory, analysis_id)
        assert analysis.outcome == "Failed"
        assert _count(factory, AnalysisSnapshot, analysis_id) == 0

        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["status"]["outcome"] == "Failed"
        assert body["status"]["snapshot"] is None
        assert body["summary"] is None
        assert body["files"] is None
        assert body["dependencies"] is None
        assert body["architecture"] is None
        assert body["code_structure"] is None

        # A terminal Failed analysis is never re-run or sealed.
        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )
        assert _count(factory, AnalysisSnapshot, analysis_id) == 0
        assert _analysis_state(factory, analysis_id).outcome == "Failed"
    finally:
        engine.dispose()


# --- Advisory (OSV) production-path integration -----------------------------

#: Two pinned manifests so two exact-version queries run.
TWO_DEP_FILES = {
    **FIXTURE_FILES,
    "services/api/requirements.txt": "flask==3.0.0\n",
}

#: A range-only manifest: no exact version, so nothing is ever queried.
UNPINNED_FILES = {**FIXTURE_FILES, "requirements.txt": "requests>=2.31.0\n"}


def _osv_handler(
    *,
    vulns_by_index: dict[int, list[str]] | None = None,
    fail_transport: bool = False,
    fail_hydration: frozenset[str] = frozenset(),
):
    """Mock OSV transport: deterministic batch + hydration, no real network."""

    def handler(request: httpx.Request) -> httpx.Response:
        if fail_transport:
            raise httpx.ConnectError("osv down", request=request)
        if request.url.path == "/v1/querybatch":
            body = json.loads(request.content.decode("utf-8"))
            count = len(body["queries"])
            results: list[object] = []
            for index in range(count):
                ids = (vulns_by_index or {}).get(index, [])
                results.append({"vulns": [{"id": vid} for vid in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        advisory_id = request.url.path.rsplit("/", 1)[-1]
        if advisory_id in fail_hydration:
            return httpx.Response(500, json={})
        return httpx.Response(
            200,
            json={
                "id": advisory_id,
                "aliases": ["CVE-2024-0001"],
                "summary": "fixture advisory",
            },
        )

    return handler


def _run_pipeline(tmp_path: Path, files: dict[str, str], osv_client: OsvClient):
    engine, factory = _factory()
    recorder: _Recorder = _Recorder()
    source = tmp_path / "source"
    head = init_git_repo(source, files)
    client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
    created = _seed_post(factory, client)
    run_analysis_pipeline(
        analysis_id=created["analysis_id"],
        deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
        remote_url_override=str(source),
        allow_local_paths=True,
        source_provider=DictSourceProvider(
            {path: text for path, text in files.items() if path.endswith(".py")}
        ),
        osv_client=osv_client,
    )
    return engine, factory, client, created["analysis_id"]


def test_pipeline_persists_advisory_success_and_finding(tmp_path: Path) -> None:
    client_osv = mock_osv_client(_osv_handler(vulns_by_index={0: ["GHSA-x"]}))  # type: ignore[arg-type]
    engine, factory, client, analysis_id = _run_pipeline(tmp_path, FIXTURE_FILES, client_osv)
    try:
        analysis = _analysis_state(factory, analysis_id)
        assert analysis.advisory_source == "OSV"
        assert analysis.advisory_status == "succeeded"
        assert analysis.advisory_consulted_at is not None
        assert _count_advisories(factory, analysis_id) == 1

        body = client.get(f"/api/analyses/{analysis_id}").json()
        data = body["analysis"]["advisory_data"]
        assert data["source"] == "OSV"
        assert data["outcome"] == "Succeeded"
        assert data["consulted_at"] is not None
        advisories = [item for dep in body["dependencies"]["items"] for item in dep["advisories"]]
        assert advisories == [{"advisory_id": "GHSA-x", "source": "OSV"}]
        assert body["summary"]["dependencies"]["vulnerable_count"] == 1
    finally:
        engine.dispose()


def test_pipeline_records_advisory_success_without_matches(tmp_path: Path) -> None:
    osv = mock_osv_client(_osv_handler())  # type: ignore[arg-type]
    engine, factory, client, analysis_id = _run_pipeline(tmp_path, FIXTURE_FILES, osv)
    try:
        analysis = _analysis_state(factory, analysis_id)
        assert analysis.advisory_source == "OSV"
        assert analysis.advisory_status == "succeeded"
        assert _count_advisories(factory, analysis_id) == 0
        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["analysis"]["advisory_data"]["outcome"] == "Succeeded"
        assert body["summary"]["dependencies"]["vulnerable_count"] == 0
    finally:
        engine.dispose()


def test_pipeline_records_advisory_unavailable_on_transport_failure(tmp_path: Path) -> None:
    osv = mock_osv_client(_osv_handler(fail_transport=True), max_retries=0)
    engine, factory, client, analysis_id = _run_pipeline(tmp_path, FIXTURE_FILES, osv)
    try:
        analysis = _analysis_state(factory, analysis_id)
        assert analysis.advisory_source == "OSV"
        assert analysis.advisory_status == "unavailable"
        # A recorded limit means a usable result is never rendered as Complete.
        assert analysis.outcome == "Completed with limitations"
        assert _count(factory, AnalysisSnapshot, analysis_id) == 1
        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["analysis"]["advisory_data"]["outcome"] == "Unavailable"
        # The failure is recorded, never rendered as an absence of vulnerabilities.
        reasons = [item["reason"] for item in body["status"]["limitations"]]
        assert any("Advisory" in reason or "advisory" in reason for reason in reasons)
    finally:
        engine.dispose()


def test_pipeline_records_advisory_partly_succeeded(tmp_path: Path) -> None:
    # flask (index 0) hydrates; requests (index 1) hydration fails.
    osv = mock_osv_client(
        _osv_handler(
            vulns_by_index={0: ["GHSA-a"], 1: ["GHSA-b"]},
            fail_hydration=frozenset({"GHSA-b"}),
        ),
        max_retries=0,
    )
    engine, factory, client, analysis_id = _run_pipeline(tmp_path, TWO_DEP_FILES, osv)
    try:
        analysis = _analysis_state(factory, analysis_id)
        assert analysis.advisory_status == "partly succeeded"
        assert _count_advisories(factory, analysis_id) == 1
        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["analysis"]["advisory_data"]["outcome"] == "Partly succeeded"
    finally:
        engine.dispose()


def test_pipeline_records_null_advisory_when_nothing_queryable(tmp_path: Path) -> None:
    osv = mock_osv_client(_osv_handler())  # type: ignore[arg-type]
    engine, factory, client, analysis_id = _run_pipeline(tmp_path, UNPINNED_FILES, osv)
    try:
        analysis = _analysis_state(factory, analysis_id)
        assert analysis.advisory_source is None
        assert analysis.advisory_status is None
        assert analysis.advisory_consulted_at is None
        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["analysis"]["advisory_data"] is None
    finally:
        engine.dispose()


def test_dispatcher_injects_osv_client_into_pipeline(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        deps = _pipeline_deps(factory, head, tmp_path / "workspaces")
        tasks = BackgroundTasks()
        get_analysis_dispatcher(tasks)("analysis-1", deps)
        assert len(tasks.tasks) == 1
        (task,) = tasks.tasks
        assert task.func is run_analysis_pipeline
        assert isinstance(task.kwargs.get("osv_client"), OsvClient)
    finally:
        engine.dispose()


def test_pipeline_domain_failure_is_isolated_and_sealed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing analyzer never stops the others and never reads as clean."""
    from app.analyzers.dependency.analyzer import DependencyAnalyzer
    from app.analyzers.errors import AnalyzerError

    def _boom(self: object, context: object) -> None:
        raise AnalyzerError("The dependency analysis could not be completed.")

    engine, factory = _factory()
    try:
        monkeypatch.setattr(DependencyAnalyzer, "analyze", _boom)
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]
        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )

        analysis = _analysis_state(factory, analysis_id)
        assert analysis.outcome == "Completed with limitations"
        assert _count(factory, AnalysisSnapshot, analysis_id) == 1
        body = client.get(f"/api/analyses/{analysis_id}").json()
        states = {item["area"]: item["state"] for item in body["status"]["domains"]}
        assert states["dependency"] in ("Analysis failed", "Analysis unavailable")
        # Sibling domains still produced usable output.
        assert body["security"] is not None
        assert body["architecture"] is not None
        assert body["code_structure"] is not None
        # A failed domain never masquerades as a clean result.
        assert states["dependency"] != "No findings detected"
    finally:
        engine.dispose()


def test_full_workflow_submission_results_reports_history_comparison(tmp_path: Path) -> None:
    """TASK-251: the real pipeline connects submission, persisted results,
    reports, history, and comparison for two analyses of one repository."""
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        first = _seed_post(factory, client)
        second = _seed_post(factory, client)
        assert first["repository_id"] == second["repository_id"]

        for created in (first, second):
            run_analysis_pipeline(
                analysis_id=created["analysis_id"],
                deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
                remote_url_override=str(source),
                allow_local_paths=True,
                source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
            )
            state = _analysis_state(factory, created["analysis_id"])
            assert state.outcome in ("Completed", "Completed with limitations")
            assert _count(factory, AnalysisSnapshot, created["analysis_id"]) == 1
            assert list((tmp_path / "workspaces").glob("ws-*")) == []

        # History exposes both analyses of the shared repository, newest first.
        history = client.get(f"/api/repositories/{first['repository_id']}").json()
        assert {entry["analysis_id"] for entry in history["analyses"]} == {
            first["analysis_id"],
            second["analysis_id"],
        }
        assert all(
            entry["outcome"] in ("Completed", "Completed with limitations")
            for entry in history["analyses"]
        )

        # Comparison links the two sealed results: identical inputs → unchanged.
        comparison = client.get(
            f"/api/analyses/{second['analysis_id']}?comparison_base={first['analysis_id']}"
        ).json()["comparison"]
        assert comparison["comparable"] is True
        assert comparison["new"] == [] and comparison["resolved"] == []
        assert len(comparison["unchanged"]) >= 1

        # Report: canonical JSON equals the §4.2 result; markdown/html render it.
        json_report = client.get(f"/api/analyses/{second['analysis_id']}/report?format=json")
        assert json_report.status_code == 200, json_report.text
        assert json_report.json() == client.get(f"/api/analyses/{second['analysis_id']}").json()
        for fmt, content_type in (("markdown", "text/markdown"), ("html", "text/html")):
            report = client.get(f"/api/analyses/{second['analysis_id']}/report?format={fmt}")
            assert report.status_code == 200, report.text
            assert report.headers["content-type"] == content_type
            assert history["name"] in report.text
    finally:
        engine.dispose()
