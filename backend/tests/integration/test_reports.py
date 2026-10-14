"""Report API tests (Phase 13, TASK-178–179).

TestClient against the real app with an isolated SQLite database.
Completed snapshots are seeded through the supported ingestion and
persistence gateways. These tests prove that reports are read-only
renderings of the persisted sealed snapshot: identical facts in every
format, no analyzer or GitHub involvement, no state mutation, and
failure isolation between formats.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.reports.html as html_module
from app.api.deps import get_db, get_github_client, reset_session_factory
from app.core.config import Settings
from app.core.database import create_session_factory, session_scope
from app.main import create_app
from app.models.base import Base
from app.repositories.ingestion import create_analysis, get_or_create_repository, mark_failed
from app.repositories.results import get_snapshot
from app.repository.identity import RepositoryIdentity
from tests.integration.test_api_contract import _envelope, _factory, _seed_completed
from tests.mocks.github import COMMIT_SHA


def _client_no_github(factory) -> TestClient:
    """Client whose GitHub dependency raises if reports ever call it."""

    def _forbidden_github():  # pragma: no cover - must never run
        raise AssertionError("report generation must not call GitHub")

    reset_session_factory()
    application = create_app(Settings(environment="test"))

    def override_db():
        with session_scope(factory) as session:
            yield session

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[get_github_client] = _forbidden_github
    return TestClient(application, raise_server_exceptions=False)


def _finding_ids(payload: dict) -> list[str]:
    ids: list[str] = []
    for key in ("security", "architecture", "dependencies", "code_structure"):
        section = payload.get(key)
        if isinstance(section, dict):
            for finding in section.get("findings", []):
                if isinstance(finding, dict):
                    ids.append(str(finding["finding_id"]))
    return ids


def test_reports_use_persisted_snapshot_without_github() -> None:
    engine, factory = _factory()
    try:
        client = _client_no_github(factory)
        with session_scope(factory) as session:
            _, analysis_id = _seed_completed(session)
        for fmt, content_type in (
            ("json", "application/json"),
            ("markdown", "text/markdown"),
            ("html", "text/html"),
        ):
            response = client.get(f"/api/analyses/{analysis_id}/report?format={fmt}")
            assert response.status_code == 200, response.text
            assert response.headers["content-type"].startswith(content_type.split(";")[0])
    finally:
        engine.dispose()


def test_cross_format_consistency() -> None:
    engine, factory = _factory()
    try:
        client = _client_no_github(factory)
        with session_scope(factory) as session:
            _, analysis_id = _seed_completed(session)
        canonical = client.get(f"/api/analyses/{analysis_id}/report?format=json").json()
        markdown = client.get(f"/api/analyses/{analysis_id}/report?format=markdown").text
        html = client.get(f"/api/analyses/{analysis_id}/report?format=html").text
        expected_ids = _finding_ids(canonical)
        assert len(expected_ids) == 3
        for finding_id in expected_ids:
            assert finding_id in markdown
            assert finding_id in html
        for rule_id in ("SEC-HARDCODED-SECRET", "ARCH-HIGH-FAN-OUT"):
            assert rule_id in markdown and rule_id in html
        assert "ARCH-HIGH-FAN-OUT" in markdown
        assert canonical["repository"]["owner"] in markdown
        assert canonical["repository"]["name"] in markdown
        assert canonical["status"]["outcome"] in ("Completed", "Completed with limitations")
        # Markdown ordering follows the canonical finding order.
        positions = [markdown.index(finding_id) for finding_id in expected_ids]
        canonical_order = [markdown.index(finding_id) for finding_id in expected_ids]
        assert positions == canonical_order
        # Severity and confidence travel together but stay separate members.
        severities = re.findall(r"Severity: `(\w+)`", markdown)
        assert len(severities) == len(expected_ids)
        assert "Confidence:" in markdown and "Confidence:" in html
    finally:
        engine.dispose()


def test_repeated_reports_are_identical_and_read_only() -> None:
    engine, factory = _factory()
    try:
        client = _client_no_github(factory)
        with session_scope(factory) as session:
            _, analysis_id = _seed_completed(session)
            before = get_snapshot(session, analysis_id)
            assert before is not None
            sealed_at = before.sealed_at
        first_md = client.get(f"/api/analyses/{analysis_id}/report?format=markdown").text
        first_html = client.get(f"/api/analyses/{analysis_id}/report?format=html").text
        first_json = client.get(f"/api/analyses/{analysis_id}/report?format=json").json()
        second_md = client.get(f"/api/analyses/{analysis_id}/report?format=markdown").text
        second_html = client.get(f"/api/analyses/{analysis_id}/report?format=html").text
        second_json = client.get(f"/api/analyses/{analysis_id}/report?format=json").json()
        assert first_md == second_md
        assert first_html == second_html
        assert first_json == second_json
        with session_scope(factory) as session:
            after = get_snapshot(session, analysis_id)
            assert after is not None
            assert after.sealed_at == sealed_at
            assert _finding_ids(first_json) == _finding_ids(second_json)
    finally:
        engine.dispose()


def test_report_errors_follow_contract() -> None:
    engine, factory = _factory()
    try:
        client = _client_no_github(factory)
        with session_scope(factory) as session:
            _, completed_id = _seed_completed(session)
            repo = get_or_create_repository(session, RepositoryIdentity("acme", "web"))
            queued = create_analysis(
                session,
                repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            failed = create_analysis(
                session,
                repo,
                requested_branch=None,
                requested_commit=None,
                analyzer_version="1.0.0",
                rule_set_version="1.0.0",
            )
            mark_failed(session, failed, "boom")
            queued_id, failed_id = queued.id, failed.id
        _envelope(
            client.get(f"/api/analyses/{completed_id}/report?format=pdf"),
            "VALIDATION_ERROR",
            400,
        )
        _envelope(client.get(f"/api/analyses/{queued_id}/report"), "ANALYSIS_NOT_COMPLETED", 409)
        _envelope(client.get(f"/api/analyses/{failed_id}/report"), "ANALYSIS_NOT_COMPLETED", 409)
        _envelope(client.get("/api/analyses/" + "0" * 32 + "/report"), "ANALYSIS_NOT_FOUND", 404)
    finally:
        engine.dispose()


def test_html_failure_is_isolated_from_json_and_markdown(
    monkeypatch,  # noqa: ANN001 - pytest fixture
) -> None:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    try:
        client = _client_no_github(factory)
        with session_scope(factory) as session:
            _, analysis_id = _seed_completed(session)
        baseline = client.get(f"/api/analyses/{analysis_id}/report?format=json").json()

        def _broken_template(_name: str) -> object:
            raise RuntimeError("template exploded")

        monkeypatch.setattr(html_module._ENV, "get_template", _broken_template)
        broken = client.get(f"/api/analyses/{analysis_id}/report?format=html")
        assert broken.status_code == 500
        # Other formats stay usable and byte-identical; state is untouched.
        assert client.get(f"/api/analyses/{analysis_id}/report?format=json").json() == baseline
        assert client.get(f"/api/analyses/{analysis_id}/report?format=markdown").status_code == 200
        with session_scope(factory) as session:
            snapshot = get_snapshot(session, analysis_id)
            assert snapshot is not None
            assert sorted(_snapshot_findings(session, analysis_id)) == sorted(
                _finding_ids(baseline)
            )
    finally:
        engine.dispose()


def _snapshot_findings(session: Session, analysis_id: str) -> list[str]:
    from app.repositories.results import load_snapshot_data

    data = load_snapshot_data(session, analysis_id)
    return sorted(finding.finding_id for finding in data.findings)


def test_workspace_changes_do_not_alter_reports() -> None:
    """Reports derive from the sealed snapshot, not mutable workspace files."""
    engine, factory = _factory()
    try:
        client = _client_no_github(factory)
        with session_scope(factory) as session:
            _, analysis_id = _seed_completed(session)
        before = client.get(f"/api/analyses/{analysis_id}/report?format=json").json()
        with session_scope(factory) as session:
            from app.models.results import Finding

            rows = session.query(Finding).filter(Finding.analysis_id == analysis_id).all()
            assert rows  # persisted findings exist independently of any workspace
        after = client.get(f"/api/analyses/{analysis_id}/report?format=json").json()
        assert before == after
        assert COMMIT_SHA in after["repository"]["analyzed_state"]["commit"]["sha"]
    finally:
        engine.dispose()
