"""API unit tests (Phase 12, TASK-168–173).

Pure validation behavior: request schemas, error envelope and codes,
pagination bounds. Endpoint behavior lives in test_api_contract.py.
"""

import pytest
from pydantic import ValidationError

from app.api.errors import ERROR_STATUS, ApiError, error_body
from app.api.pagination import paginate, parse_pagination
from app.core.config import load_settings
from app.reports.html import render_html
from app.reports.markdown import render_markdown
from app.schemas.api import AnalysisCreateRequest


def _settings():
    return load_settings()


def test_create_request_schema() -> None:
    body = AnalysisCreateRequest(url="https://github.com/acme/web")
    assert body.branch is None and body.commit is None
    full = AnalysisCreateRequest(url="https://github.com/acme/web", branch="main", commit="a" * 40)
    assert full.branch == "main"
    with pytest.raises(ValidationError):
        AnalysisCreateRequest()
    with pytest.raises(ValidationError):
        AnalysisCreateRequest(url=5)  # type: ignore[arg-type]


def test_error_envelope_and_codes() -> None:
    assert set(ERROR_STATUS) == {
        "INVALID_URL",
        "REPOSITORY_NOT_ACCESSIBLE",
        "INVALID_BRANCH",
        "INVALID_COMMIT",
        "ANALYSIS_NOT_FOUND",
        "REPOSITORY_NOT_FOUND",
        "ANALYSIS_FAILED",
        "ANALYSIS_NOT_COMPLETED",
        "REPORT_UNAVAILABLE",
        "VALIDATION_ERROR",
        "RATE_LIMITED",
        "INTERNAL_ERROR",
    }
    assert ERROR_STATUS["VALIDATION_ERROR"] == 400
    assert ERROR_STATUS["ANALYSIS_NOT_FOUND"] == 404
    assert ERROR_STATUS["ANALYSIS_NOT_COMPLETED"] == 409
    assert ERROR_STATUS["INVALID_URL"] == 422
    assert ERROR_STATUS["RATE_LIMITED"] == 429
    assert ERROR_STATUS["INTERNAL_ERROR"] == 500
    assert error_body("ANALYSIS_NOT_FOUND", "Analysis was not found.") == {
        "error": {
            "code": "ANALYSIS_NOT_FOUND",
            "message": "Analysis was not found.",
            "details": None,
        }
    }
    assert error_body("ANALYSIS_FAILED", "Failed.", {"explanation": "boom"})["error"][
        "details"
    ] == {"explanation": "boom"}
    assert ApiError("VALIDATION_ERROR", "Bad.").http_status == 400
    assert ApiError("REPORT_UNAVAILABLE", "Gone.", http_status=409).http_status == 409
    with pytest.raises(ValueError):
        ApiError("MADE_UP_CODE", "Nope.")


def test_pagination_bounds() -> None:
    settings = _settings()
    assert parse_pagination(settings, None, None) == (1, 50)
    assert parse_pagination(settings, "2", "10") == (2, 10)
    assert parse_pagination(settings, "1", "200") == (1, 200)
    for bad_page in ["0", "-1", "abc", "1.5", ""]:
        with pytest.raises(ApiError) as exc:
            parse_pagination(settings, bad_page, None)
        assert exc.value.code == "VALIDATION_ERROR" and exc.value.http_status == 400
    for bad_size in ["0", "-5", "201", "1000", "many", "10.5"]:
        with pytest.raises(ApiError) as exc:
            parse_pagination(settings, None, bad_size)
        assert exc.value.code == "VALIDATION_ERROR"
    page = paginate([{"id": i} for i in range(5)], 5, 2, 2)
    assert page == {"page": 2, "page_size": 2, "total": 5, "items": [{"id": 2}, {"id": 3}]}
    last = paginate([{"id": i} for i in range(5)], 5, 3, 2)
    assert last["items"] == [{"id": 4}]
    assert paginate([], 0, 1, 50)["items"] == []


def _minimal_result() -> dict:
    return {
        "analysis": {
            "analysis_id": "a" * 32,
            "repository_id": "r" * 32,
            "timestamp": "2026-10-14T00:00:00Z",
            "analyzer_version": "1.0.0",
            "rule_set_version": "1.0.0",
            "configuration": {},
            "advisory_data": None,
        },
        "repository": {
            "repository_id": "r" * 32,
            "url": "https://github.com/acme/web",
            "owner": "acme",
            "name": "web",
            "analyzed_state": {"branch": None, "commit": None},
        },
        "status": {
            "stage": None,
            "outcome": "Completed",
            "completed_at": "2026-10-14T00:00:00Z",
            "explanation": "",
            "snapshot": {"sealed_at": "2026-10-14T00:00:00Z"},
            "domains": [
                {"area": "security", "state": "No findings detected", "reason": None},
                {"area": "architecture", "state": None, "reason": None},
                {"area": "dependency", "state": "No findings detected", "reason": None},
                {"area": "code_structure", "state": "No findings detected", "reason": None},
            ],
            "limitations": [],
        },
        "summary": {"languages": [], "files": {"indexed": 0, "parse_results": {}}},
        "security": {"rule_evaluations": [], "findings": []},
        "architecture": {
            "rule_evaluations": [],
            "findings": [],
            "metric_definitions": {},
            "metrics": [],
            "graph": {
                "granularity": "Source file",
                "potentially_incomplete": False,
                "nodes": [],
                "edges": [],
                "external_and_unresolved_references": [],
            },
            "cycles": [],
        },
        "dependencies": {"rule_evaluations": [], "findings": [], "items": []},
        "code_structure": {"rule_evaluations": [], "findings": []},
        "files": [],
        "comparison": None,
    }


def test_reports_render_states_and_escape() -> None:
    result = _minimal_result()
    markdown = render_markdown(result)
    assert markdown.startswith("# Analysis Report: acme/web")
    assert "## Dependencies\nState: `No findings detected`" in markdown
    assert "## Architecture\nState: `null`" in markdown
    assert "manual review" in markdown
    assert "No limitations recorded." in markdown
    assert "score" not in markdown.lower()
    html = render_html(result)
    assert "<html" in html and "No findings detected" in html

    evil = _minimal_result()
    evil["files"] = [
        {
            "path": "<script>alert(1)</script>.py",
            "file_type": "source",
            "language": "Python",
            "support": "Primary Support",
            "size": 1,
            "binary": False,
            "generated": False,
            "exclusion": None,
            "eligibility": {"classification": "Eligible", "reason": None},
            "parse_result": "Parsed",
            "diagnostics": [],
            "indexing_limitation": None,
            "coverage": [],
            "finding_count": 0,
        }
    ]
    rendered = render_html(evil)
    assert "<script>alert(1)" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "<script>alert(1)</script>.py" in render_markdown(evil)
