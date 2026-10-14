"""API contract tests (Phase 12, TASK-162–173).

TestClient against the real app with an isolated SQLite database (shared
static connection for the ASGI worker threads) and mock GitHub
transports. Completed snapshots are seeded through the supported
ingestion and persistence gateways with production-generated finding
identities — never injected keys.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.analyzers.findings import Confidence, Severity, create_finding
from app.api.deps import get_db, get_github_client, reset_session_factory
from app.core.config import Settings
from app.core.database import create_session_factory, session_scope
from app.main import create_app
from app.models.base import Base
from app.models.repository import Analysis as AnalysisModel
from app.ncm import SourceLocation
from app.repositories import results as gateway
from app.repositories.indexing import save_index
from app.repositories.ingestion import (
    create_analysis,
    get_or_create_repository,
    mark_failed,
)
from app.repository.github import GitHubClient
from app.repository.identity import RepositoryIdentity, normalize_github_url
from app.repository.index_types import IndexedFile
from app.services.http_client import RetryPolicy, ServiceClient
from tests.mocks.github import COMMIT_SHA, github_transport

FIXTURE_URL = "https://github.com/fixture-owner/fixture-repo"

RULES = [
    gateway.RuleDefinition(
        rule_id="SEC-HARDCODED-SECRET", name="Hardcoded secret", category="security"
    ),
    gateway.RuleDefinition(
        rule_id="ARCH-HIGH-FAN-OUT", name="High fan-out", category="architecture"
    ),
    gateway.RuleDefinition(
        rule_id="DEP-KNOWN-VULNERABILITY", name="Known vulnerability", category="dependency"
    ),
    gateway.RuleDefinition(
        rule_id="CODE-HIGH-COMPLEXITY", name="High complexity", category="code_structure"
    ),
]

CONFIGURATION = {
    "generated_files": "Included",
    "architecture": {
        "coupling_definition": "coupling-def-1",
        "thresholds": {"ARCH-HIGH-FAN-OUT": {"fan_out": 3}},
    },
}


def _factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, create_session_factory(engine)


def _github(scenario: str = "public_repo") -> GitHubClient:
    return GitHubClient(
        ServiceClient(
            name="github-test",
            base_url="https://api.github.com",
            retry_policy=RetryPolicy(max_retries=0, backoff_base_s=0),
            transport=github_transport(scenario),
        )
    )


def _client(factory, scenario: str = "public_repo") -> TestClient:
    reset_session_factory()
    application = create_app(Settings(environment="test"))

    def override_db():
        with session_scope(factory) as session:
            yield session

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[get_github_client] = lambda: _github(scenario)
    return TestClient(application, raise_server_exceptions=False)


def _state(area: str, has_findings: bool, forced: str | None) -> gateway.DomainStateInput:
    if has_findings:
        return gateway.DomainStateInput(area, None)
    state = forced or "Analysis not performed"
    return gateway.DomainStateInput(area, state, f"No supported content was evaluated for {area}.")


def _indexed(path: str) -> IndexedFile:
    return IndexedFile(
        relative_path=path,
        file_type="source",
        extension=".py",
        size=100,
        language="python",
        support_status="supported",
        is_binary=False,
        is_generated=False,
        excluded=False,
        exclusion_reason=None,
        eligibility="eligible",
        eligibility_reason="",
        indexing_limitation=None,
    )


def _finding(
    analysis_id: str,
    rule_id: str,
    category: str,
    path: str,
    subject: str,
    severity: Severity,
    line: int = 1,
    confidence: Confidence = Confidence.HIGH,
):
    return create_finding(
        rule_id=rule_id,
        analyzer_id=category,
        category=category,
        title=f"{rule_id} at {path}",
        description=f"Observation from {rule_id}.",
        severity=severity,
        confidence=confidence,
        location=SourceLocation(path, line, line, 0, 0),
        recommendation="Review.",
        analysis_id=analysis_id,
        subject_key=subject,
        severity_factors=("test factor",),
        confidence_factors=("direct observation",),
    )


def _seed_completed(
    session: Session,
    *,
    owner: str = "acme",
    name: str = "web",
    arch_state: str | None = None,
    arch_findings: bool = True,
    sec_state: str | None = None,
    sec_findings: bool = True,
    limitations: list | None = None,
    outcome: str = "Completed",
    explanation: str = "",
) -> tuple[str, str]:
    """Seed one sealed snapshot through the supported gateways."""
    repo = get_or_create_repository(session, RepositoryIdentity(owner=owner, name=name))
    analysis = create_analysis(
        session,
        repo,
        requested_branch=None,
        requested_commit=None,
        analyzer_version="1.0.0",
        rule_set_version="1.0.0",
    )
    analysis.resolved_branch = "main"
    analysis.branch_origin = "defaulted"
    analysis.resolved_commit_sha = COMMIT_SHA
    analysis.commit_origin = "defaulted"
    save_index(session, analysis.id, [_indexed("app/main.py"), _indexed("app/util.py")], [])
    rules = gateway.ensure_rules(session, "1.0.0", RULES)
    gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
    gateway.persist_modules(
        session,
        analysis.id,
        [
            gateway.ModuleInput(
                module_id="app/main.py",
                file_path="app/main.py",
                dependencies=(
                    gateway.ModuleDepInput(
                        target="app/util.py",
                        target_text="app.util",
                        resolution="internal",
                        file_path="app/main.py",
                        line=3,
                        column=0,
                        locations=(("app/main.py", 3, 0),),
                    ),
                ),
            ),
            gateway.ModuleInput(module_id="app/util.py", file_path="app/util.py"),
        ],
    )
    gateway.persist_metrics(
        session,
        analysis.id,
        [
            gateway.MetricInput(
                area="architecture", metric_name="fan_out", subject_path="app/main.py", value=5
            )
        ],
    )
    findings = []
    if sec_findings:
        findings.append(
            _finding(
                analysis.id,
                "SEC-HARDCODED-SECRET",
                "security",
                "app/main.py",
                "password:api_key:5",
                Severity.CRITICAL,
            )
        )
    if arch_findings:
        findings.append(
            _finding(
                analysis.id,
                "ARCH-HIGH-FAN-OUT",
                "architecture",
                "app/main.py",
                "fan-out:app/main.py",
                Severity.MEDIUM,
            )
        )
        findings.append(
            _finding(
                analysis.id,
                "ARCH-HIGH-FAN-OUT",
                "architecture",
                "app/util.py",
                "fan-out:app/util.py",
                Severity.LOW,
                confidence=Confidence.MEDIUM,
            )
        )
    gateway.persist_findings(session, analysis, rules, findings)
    gateway.persist_domain_states(
        session,
        analysis.id,
        [
            _state("security", sec_findings, sec_state),
            _state("architecture", arch_findings, arch_state),
            gateway.DomainStateInput("dependency", "No findings detected"),
            gateway.DomainStateInput("code_structure", "No findings detected"),
        ],
    )
    evaluated = ["DEP-KNOWN-VULNERABILITY", "CODE-HIGH-COMPLEXITY"]
    if sec_findings:
        evaluated.append("SEC-HARDCODED-SECRET")
    if arch_findings:
        evaluated.append("ARCH-HIGH-FAN-OUT")
    gateway.persist_rule_evaluations(
        session,
        analysis,
        rules,
        [gateway.RuleEvaluationInput(rule_id, "Evaluated") for rule_id in evaluated],
    )
    gateway.persist_file_coverages(session, analysis.id, [])
    gateway.persist_limitations(session, analysis, rules, limitations or [])
    gateway.mark_completed(session, analysis, outcome=outcome, explanation=explanation)
    gateway.seal_snapshot(session, analysis.id)
    session.commit()
    return repo.id, analysis.id


def _envelope(response: httpx.Response, code: str, status: int) -> dict:
    assert response.status_code == status, response.text
    payload = response.json()
    assert set(payload) == {"error"}, payload
    error = payload["error"]
    assert set(error) == {"code", "message", "details"}, error
    assert error["code"] == code, error
    assert isinstance(error["message"], str) and error["message"]
    assert error["details"] is None or isinstance(error["details"], dict)
    return error


def test_post_valid_returns_queued() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        response = client.post("/api/analyses", json={"url": FIXTURE_URL})
        assert response.status_code == 202, response.text
        payload = response.json()
        assert set(payload) == {"analysis_id", "repository_id", "stage"}
        assert payload["stage"] == "Queued"
        status = client.get(f"/api/analyses/{payload['analysis_id']}")
        assert status.status_code == 200, status.text
        body = status.json()
        assert body["status"]["stage"] == "Queued"
        assert body["status"]["outcome"] is None
        assert body["summary"] is None and body["security"] is None
        assert body["comparison"] is None
    finally:
        engine.dispose()


def test_post_same_url_coexists_as_new_analysis() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        first = client.post("/api/analyses", json={"url": FIXTURE_URL}).json()
        second = client.post("/api/analyses", json={"url": "  " + FIXTURE_URL + "  "}).json()
        assert first["repository_id"] == second["repository_id"]
        assert first["analysis_id"] != second["analysis_id"]
    finally:
        engine.dispose()


def test_post_invalid_url_rejected() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        for bad in [
            "not-a-url",
            "http://github.com/acme/web",
            "https://gitlab.com/acme/web",
            "https://user:pass@github.com/acme/web",
            "",
        ]:
            error = _envelope(client.post("/api/analyses", json={"url": bad}), "INVALID_URL", 422)
            assert error["details"] is None
    finally:
        engine.dispose()


def test_post_malformed_body_rejected() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        _envelope(client.post("/api/analyses", json={}), "VALIDATION_ERROR", 400)
        _envelope(client.post("/api/analyses", json={"url": 5}), "VALIDATION_ERROR", 400)
        _envelope(
            client.post("/api/analyses", json={"url": FIXTURE_URL, "branch": 5}),
            "VALIDATION_ERROR",
            400,
        )
    finally:
        engine.dispose()


def test_post_unknown_private_and_bad_refs() -> None:
    engine, factory = _factory()
    try:
        missing = _client(factory, "not_found")
        _envelope(
            missing.post("/api/analyses", json={"url": FIXTURE_URL}),
            "REPOSITORY_NOT_ACCESSIBLE",
            422,
        )
        private = _client(factory, "private_repo")
        _envelope(
            private.post("/api/analyses", json={"url": FIXTURE_URL}),
            "REPOSITORY_NOT_ACCESSIBLE",
            422,
        )
        public = _client(factory, "public_repo")
        _envelope(
            public.post("/api/analyses", json={"url": FIXTURE_URL, "branch": "nope..bad"}),
            "INVALID_BRANCH",
            422,
        )
        _envelope(
            public.post("/api/analyses", json={"url": FIXTURE_URL, "commit": "zzz"}),
            "INVALID_COMMIT",
            422,
        )
        branch_missing = _client(factory, "branch_missing")
        _envelope(
            branch_missing.post("/api/analyses", json={"url": FIXTURE_URL, "branch": "gone"}),
            "INVALID_BRANCH",
            422,
        )
        commit_missing = _client(factory, "commit_missing")
        _envelope(
            commit_missing.post("/api/analyses", json={"url": FIXTURE_URL, "commit": "a" * 40}),
            "INVALID_COMMIT",
            422,
        )
        ok = public.post(
            "/api/analyses",
            json={"url": FIXTURE_URL, "branch": "main", "commit": "b" * 40},
        )
        assert ok.status_code == 202, ok.text
    finally:
        engine.dispose()


def test_get_analysis_completed_and_failed() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            _, completed_id = _seed_completed(session)
            repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            failed = create_analysis(
                session,
                repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            mark_failed(session, failed, "boom")
        response = client.get(f"/api/analyses/{completed_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {
            "analysis",
            "repository",
            "status",
            "summary",
            "security",
            "architecture",
            "dependencies",
            "code_structure",
            "files",
            "comparison",
        }
        assert body["status"]["outcome"] == "Completed"
        assert body["status"]["stage"] is None
        assert body["comparison"] is None
        assert body["summary"]["architecture"]["findings"]["total"] == 2
        failed_response = client.get(f"/api/analyses/{failed.id}")
        assert failed_response.status_code == 200, failed_response.text
        failed_body = failed_response.json()
        assert failed_body["status"]["outcome"] == "Failed"
        assert failed_body["status"]["explanation"] == "boom"
        assert failed_body["security"] is None and failed_body["summary"] is None
        _envelope(client.get("/api/analyses/" + "0" * 32), "ANALYSIS_NOT_FOUND", 404)
    finally:
        engine.dispose()


def test_get_analysis_comparison_base() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            _, base_id = _seed_completed(session)
            _, target_id = _seed_completed(session)
            queued_repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            queued = create_analysis(
                session,
                queued_repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
        response = client.get(f"/api/analyses/{target_id}?comparison_base={base_id}")
        assert response.status_code == 200, response.text
        comparison = response.json()["comparison"]
        assert comparison["comparable"] is True
        assert len(comparison["unchanged"]) == 3
        assert comparison["new"] == [] and comparison["resolved"] == []
        _envelope(
            client.get(f"/api/analyses/{target_id}?comparison_base={'1' * 32}"),
            "ANALYSIS_NOT_FOUND",
            404,
        )
        _envelope(
            client.get(f"/api/analyses/{target_id}?comparison_base={queued.id}"),
            "ANALYSIS_NOT_COMPLETED",
            409,
        )
    finally:
        engine.dispose()


def test_findings_states_filters_and_search() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            _, completed_id = _seed_completed(session)
            queued_repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            queued = create_analysis(
                session,
                queued_repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            failed = create_analysis(
                session,
                queued_repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            mark_failed(session, failed, "boom")
        _envelope(client.get("/api/analyses/" + "0" * 32 + "/findings"), "ANALYSIS_NOT_FOUND", 404)
        _envelope(client.get(f"/api/analyses/{queued.id}/findings"), "ANALYSIS_NOT_COMPLETED", 409)
        failed_error = _envelope(
            client.get(f"/api/analyses/{failed.id}/findings"), "ANALYSIS_FAILED", 422
        )
        assert failed_error["details"] == {"explanation": "boom"}
        base = f"/api/analyses/{completed_id}/findings"
        page = client.get(base).json()
        assert (page["page"], page["page_size"], page["total"]) == (1, 50, 3)
        assert [item["finding_id"] for item in page["items"]] == ["F-0003", "F-0001", "F-0002"]
        assert "unavailable_areas" not in page
        assert client.get(base + "?category=security").json()["total"] == 3
        assert len(client.get(base + "?category=security").json()["items"]) == 1
        assert client.get(base + "?category=dependency").json()["items"] == []
        assert (
            client.get(base + "?severity=Critical").json()["items"][0]["rule_id"]
            == "SEC-HARDCODED-SECRET"
        )
        assert len(client.get(base + "?severity=Critical&severity=Low").json()["items"]) == 2
        assert len(client.get(base + "?confidence=High").json()["items"]) == 2
        assert len(client.get(base + "?rule_id=ARCH-HIGH-FAN-OUT").json()["items"]) == 2
        assert client.get(base + "?rule_id=SEC-NOPE").json()["items"] == []
        assert len(client.get(base + "?q=ARCH-HIGH").json()["items"]) == 2
        assert len(client.get(base + "?q=MAIN.PY").json()["items"]) == 2
        assert len(client.get(base + "?q=util.py").json()["items"]) == 1
        assert (
            client.get(base + "?sort=rule&order=desc").json()["items"][0]["rule_id"]
            == "SEC-HARDCODED-SECRET"
        )
        by_file = client.get(base + "?sort=file").json()["items"]
        assert [item["finding_id"] for item in by_file] == ["F-0001", "F-0003", "F-0002"]
        second = client.get(base + "?page=2&page_size=2").json()
        assert (second["page"], second["total"], len(second["items"])) == (2, 3, 1)
        assert second["items"][0]["finding_id"] == "F-0002"
        for bad in [
            "?severity=Urgent",
            "?confidence=Highish",
            "?category=bugs",
            "?rule_id=FOO-1",
            "?rule_id=",
            "?sort=bogus",
            "?order=sideways",
            "?page=0",
            "?page=-1",
            "?page=abc",
            "?page_size=0",
            "?page_size=201",
            "?page_size=many",
        ]:
            _envelope(client.get(base + bad), "VALIDATION_ERROR", 400)
    finally:
        engine.dispose()


def test_findings_unavailable_areas_listed() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            _, analysis_id = _seed_completed(
                session, sec_state="Analysis not performed", sec_findings=False
            )
        payload = client.get(f"/api/analyses/{analysis_id}/findings").json()
        assert payload["total"] == 2
        assert payload["unavailable_areas"] == [
            {
                "area": "security",
                "state": "Analysis not performed",
                "reason": "No supported content was evaluated for security.",
            }
        ]
    finally:
        engine.dispose()


def test_architecture_document_states() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            _, completed_id = _seed_completed(session)
            _, null_id = _seed_completed(
                session, arch_state="Analysis not performed", arch_findings=False
            )
            queued_repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            queued = create_analysis(
                session,
                queued_repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
        document = client.get(f"/api/analyses/{completed_id}/architecture").json()
        assert set(document) == {
            "granularity",
            "potentially_incomplete",
            "nodes",
            "edges",
            "external_and_unresolved_references",
            "cycles",
            "metrics",
            "metric_definitions",
            "findings",
            "rule_evaluations",
        }
        assert document["granularity"] == "Source file"
        assert len(document["nodes"]) == 2 and len(document["edges"]) == 1
        assert len(document["findings"]) == 2
        _envelope(
            client.get(f"/api/analyses/{queued.id}/architecture"), "ANALYSIS_NOT_COMPLETED", 409
        )
        _envelope(client.get(f"/api/analyses/{null_id}/architecture"), "REPORT_UNAVAILABLE", 404)
        _envelope(
            client.get("/api/analyses/" + "0" * 32 + "/architecture"),
            "ANALYSIS_NOT_FOUND",
            404,
        )
    finally:
        engine.dispose()


def test_repository_history() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            repo_id, first_id = _seed_completed(session)
            repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            second = create_analysis(
                session,
                repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            first_created = session.get(AnalysisModel, first_id).created_at
            assert first_created is not None
            second.created_at = first_created + timedelta(seconds=10)
            mark_failed(session, second, "boom")
        payload = client.get(f"/api/repositories/{repo_id}").json()
        assert payload["repository_id"] == repo_id
        assert payload["url"] == "https://github.com/acme/web"
        assert (payload["owner"], payload["name"]) == ("acme", "web")
        assert [entry["analysis_id"] for entry in payload["analyses"]] == [second.id, first_id]
        failed_entry = payload["analyses"][0]
        assert failed_entry["outcome"] == "Failed"
        assert failed_entry["explanation"] == "boom"
        assert set(failed_entry) == {
            "analysis_id",
            "branch",
            "commit",
            "timestamp",
            "analyzer_version",
            "rule_set_version",
            "outcome",
            "explanation",
        }
        completed_entry = payload["analyses"][1]
        assert completed_entry["outcome"] == "Completed"
        assert completed_entry["branch"] == {"name": "main", "origin": "Defaulted"}
        assert completed_entry["commit"]["sha"] == COMMIT_SHA
        _envelope(client.get("/api/repositories/" + "0" * 32), "REPOSITORY_NOT_FOUND", 404)
    finally:
        engine.dispose()


def test_report_formats_and_states() -> None:
    engine, factory = _factory()
    try:
        client = _client(factory)
        with session_scope(factory) as session:
            _, completed_id = _seed_completed(session)
            queued_repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            queued = create_analysis(
                session,
                queued_repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            failed = create_analysis(
                session,
                queued_repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            mark_failed(session, failed, "boom")
        as_json = client.get(f"/api/analyses/{completed_id}/report?format=json")
        assert as_json.status_code == 200, as_json.text
        as_analysis = client.get(f"/api/analyses/{completed_id}")
        assert as_json.json() == as_analysis.json()
        markdown = client.get(f"/api/analyses/{completed_id}/report?format=markdown")
        assert markdown.status_code == 200, markdown.text
        assert markdown.headers["content-type"] == "text/markdown"
        assert "# Analysis Report: acme/web" in markdown.text
        assert "ARCH-HIGH-FAN-OUT" in markdown.text
        assert "manual review" in markdown.text
        assert "Critical" in markdown.text and "High" in markdown.text
        assert "## Dependencies\nState: `No findings detected`" in markdown.text
        assert "## Architecture\nState: `null`" in markdown.text
        html = client.get(f"/api/analyses/{completed_id}/report?format=html")
        assert html.status_code == 200, html.text
        assert html.headers["content-type"] == "text/html"
        assert "<html" in html.text and "ARCH-HIGH-FAN-OUT" in html.text
        assert "State: <code>null</code>" in html.text
        default = client.get(f"/api/analyses/{completed_id}/report")
        assert default.status_code == 200 and default.json() == as_json.json()
        _envelope(
            client.get(f"/api/analyses/{completed_id}/report?format=pdf"),
            "VALIDATION_ERROR",
            400,
        )
        _envelope(client.get(f"/api/analyses/{queued.id}/report"), "ANALYSIS_NOT_COMPLETED", 409)
        _envelope(client.get(f"/api/analyses/{failed.id}/report"), "ANALYSIS_NOT_COMPLETED", 409)
        _envelope(client.get("/api/analyses/" + "0" * 32 + "/report"), "ANALYSIS_NOT_FOUND", 404)
    finally:
        engine.dispose()


def test_cross_layer_create_verify_retrieve() -> None:
    """POST → status → seeded results → findings/architecture/history/report."""
    engine, factory = _factory()
    try:
        client = _client(factory, "public_repo")
        created = client.post(
            "/api/analyses",
            json={"url": "https://github.com/fixture-owner/fixture-repo"},
        )
        assert created.status_code == 202, created.text
        analysis_id = created.json()["analysis_id"]
        repository_id = created.json()["repository_id"]
        assert client.get(f"/api/analyses/{analysis_id}").json()["status"]["stage"] == "Queued"
        identity = normalize_github_url("https://github.com/fixture-owner/fixture-repo")
        with session_scope(factory) as session:
            repo = get_or_create_repository(session, identity)
            assert repo.id == repository_id
            analysis = session.get(AnalysisModel, analysis_id)
            assert analysis is not None
            analysis.resolved_branch = "main"
            analysis.branch_origin = "defaulted"
            analysis.resolved_commit_sha = COMMIT_SHA
            analysis.commit_origin = "defaulted"
            _seed_completed_into(session, repo, analysis)
        findings = client.get(f"/api/analyses/{analysis_id}/findings").json()
        assert findings["total"] == 3
        architecture = client.get(f"/api/analyses/{analysis_id}/architecture").json()
        assert len(architecture["nodes"]) == 2
        history = client.get(f"/api/repositories/{repository_id}").json()
        assert history["analyses"][0]["analysis_id"] == analysis_id
        assert history["analyses"][0]["outcome"] == "Completed"
        report = client.get(f"/api/analyses/{analysis_id}/report?format=markdown")
        assert report.status_code == 200 and "fixture-repo" in report.text
    finally:
        engine.dispose()


def _seed_completed_into(session: Session, repo, analysis: AnalysisModel) -> None:
    """Complete a POST-created analysis through the supported gateways."""
    save_index(session, analysis.id, [_indexed("app/main.py"), _indexed("app/util.py")], [])
    rules = gateway.ensure_rules(session, analysis.rule_set_version, RULES)
    gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
    gateway.persist_modules(
        session,
        analysis.id,
        [
            gateway.ModuleInput(module_id="app/main.py", file_path="app/main.py"),
            gateway.ModuleInput(module_id="app/util.py", file_path="app/util.py"),
        ],
    )
    gateway.persist_findings(
        session,
        analysis,
        rules,
        [
            _finding(
                analysis.id,
                "SEC-HARDCODED-SECRET",
                "security",
                "app/main.py",
                "password:api_key:5",
                Severity.CRITICAL,
            ),
            _finding(
                analysis.id,
                "ARCH-HIGH-FAN-OUT",
                "architecture",
                "app/main.py",
                "fan-out:app/main.py",
                Severity.MEDIUM,
            ),
            _finding(
                analysis.id,
                "ARCH-HIGH-FAN-OUT",
                "architecture",
                "app/util.py",
                "fan-out:app/util.py",
                Severity.LOW,
            ),
        ],
    )
    gateway.persist_domain_states(
        session,
        analysis.id,
        [
            gateway.DomainStateInput("security", None),
            gateway.DomainStateInput("architecture", None),
            gateway.DomainStateInput("dependency", "No findings detected"),
            gateway.DomainStateInput("code_structure", "No findings detected"),
        ],
    )
    gateway.persist_rule_evaluations(
        session,
        analysis,
        rules,
        [gateway.RuleEvaluationInput(rule.rule_id, "Evaluated") for rule in RULES],
    )
    gateway.persist_file_coverages(session, analysis.id, [])
    gateway.persist_limitations(session, analysis, rules, [])
    gateway.mark_completed(session, analysis, outcome="Completed", explanation="")
    gateway.seal_snapshot(session, analysis.id)
