"""Regression: browser CORS for the local frontend (POST /api/analyses).

The reported defect was a preflight ``OPTIONS /api/analyses`` from
``http://localhost:5173`` returning no CORS headers because the app
registered no CORS middleware at all. These tests pin the allow-list
behavior: allowed origins are echoed, disallowed origins are refused, and
no wildcard/credentials combination is ever produced.
"""

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

FRONTEND_ORIGIN = "http://localhost:5173"


def _client() -> TestClient:
    return TestClient(create_app(Settings(environment="test")))


def test_preflight_options_analyses_allows_frontend_origin() -> None:
    client = _client()
    response = client.options(
        "/api/analyses",
        headers={
            "Origin": FRONTEND_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()
    # Never wildcard, never credentialed.
    assert response.headers["access-control-allow-origin"] != "*"
    assert "access-control-allow-credentials" not in response.headers


def test_actual_request_from_allowed_origin_carries_cors_header() -> None:
    client = _client()
    response = client.get("/api/health", headers={"Origin": FRONTEND_ORIGIN})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN


def test_preflight_from_disallowed_origin_is_refused() -> None:
    client = _client()
    response = client.options(
        "/api/analyses",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_simple_request_from_disallowed_origin_has_no_cors_header() -> None:
    client = _client()
    response = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers
