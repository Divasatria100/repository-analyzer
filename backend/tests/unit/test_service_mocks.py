"""GitHub/OSV mock infrastructure tests. Explicitly network-free.

Every scenario runs through the real ServiceClient HTTP boundary with an
injected MockTransport — no `if TESTING` branches, no sockets. Response
data is synthetic; parsing/matching logic belongs to future services.
"""

import httpx
import pytest

from app.services.http_client import (
    RetryPolicy,
    ServiceClient,
    ServiceResponseError,
    ServiceTimeoutError,
)
from tests.mocks.github import (
    COMMIT_SHA,
    DEFAULT_BRANCH,
    OWNER,
    REPO,
    REPO_PATH,
    github_transport,
)
from tests.mocks.osv import OSV_API, QUERY_PATH, VERSION, VULN_ID, osv_transport

pytestmark = pytest.mark.security


def _service(transport: httpx.MockTransport, base_url: str) -> ServiceClient:
    return ServiceClient(
        name="mock-service",
        base_url=base_url,
        retry_policy=RetryPolicy(max_retries=0, backoff_base_s=0),
        transport=transport,
    )


def test_github_public_repo_metadata() -> None:
    client = _service(github_transport("public_repo"), "https://api.github.com")
    response = client.send_with_retry_sync("GET", f"{REPO_PATH}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["full_name"] == f"{OWNER}/{REPO}"
    assert payload["private"] is False
    assert payload["default_branch"] == DEFAULT_BRANCH


def test_github_private_repo_flagged_not_fetched() -> None:
    client = _service(github_transport("private_repo"), "https://api.github.com")
    payload = client.send_with_retry_sync("GET", f"{REPO_PATH}").json()
    assert payload["private"] is True


def test_github_branch_and_commit_resolution() -> None:
    client = _service(github_transport("public_repo"), "https://api.github.com")
    branch = client.send_with_retry_sync("GET", f"{REPO_PATH}/branches/{DEFAULT_BRANCH}").json()
    assert branch["commit"]["sha"] == COMMIT_SHA
    commit = client.send_with_retry_sync("GET", f"{REPO_PATH}/commits/{COMMIT_SHA}").json()
    assert commit["sha"] == COMMIT_SHA


@pytest.mark.parametrize(
    ("scenario", "path", "status"),
    [
        ("not_found", REPO_PATH, 404),
        ("branch_missing", f"{REPO_PATH}/branches/{DEFAULT_BRANCH}", 404),
        ("commit_missing", f"{REPO_PATH}/commits/{COMMIT_SHA}", 404),
        ("rate_limited", REPO_PATH, 403),
    ],
)
def test_github_not_found_and_rate_limit_shapes(scenario: str, path: str, status: int) -> None:
    client = _service(github_transport(scenario), "https://api.github.com")  # type: ignore[arg-type]
    response = client.send_with_retry_sync("GET", path)
    assert response.status_code == status


def test_github_server_error_maps_to_response_error() -> None:
    client = _service(github_transport("server_error"), "https://api.github.com")
    with pytest.raises(ServiceResponseError):
        client.send_with_retry_sync("GET", REPO_PATH)


def test_github_timeout_maps_to_timeout_error() -> None:
    client = _service(github_transport("timeout"), "https://api.github.com")
    with pytest.raises(ServiceTimeoutError):
        client.send_with_retry_sync("GET", REPO_PATH)


def test_github_malformed_body_surfaced_at_parse_boundary() -> None:
    """Transport returns bytes; JSON decoding fails in the (future) service layer."""
    client = _service(github_transport("malformed"), "https://api.github.com")
    response = client.send_with_retry_sync("GET", REPO_PATH)
    assert response.status_code == 200
    with pytest.raises(ValueError):
        response.json()


def test_osv_no_vulnerabilities() -> None:
    client = _service(osv_transport("no_vulns"), OSV_API)
    payload = client.send_with_retry_sync("POST", QUERY_PATH).json()
    assert payload == {"vulns": []}


def test_osv_single_and_multiple_vulnerabilities() -> None:
    client = _service(osv_transport("one_vuln"), OSV_API)
    payload = client.send_with_retry_sync("POST", QUERY_PATH).json()
    assert [v["id"] for v in payload["vulns"]] == [VULN_ID]
    assert VERSION in payload["vulns"][0]["affected"][0]["versions"]

    client = _service(osv_transport("multiple_vulns"), OSV_API)
    payload = client.send_with_retry_sync("POST", QUERY_PATH).json()
    assert len(payload["vulns"]) == 2


def test_osv_server_error_maps_to_response_error() -> None:
    client = _service(osv_transport("server_error"), OSV_API)
    with pytest.raises(ServiceResponseError):
        client.send_with_retry_sync("POST", QUERY_PATH)


def test_osv_timeout_and_malformed() -> None:
    with pytest.raises(ServiceTimeoutError):
        _service(osv_transport("timeout"), OSV_API).send_with_retry_sync("POST", QUERY_PATH)
    response = _service(osv_transport("malformed"), OSV_API).send_with_retry_sync(
        "POST", QUERY_PATH
    )
    with pytest.raises(ValueError):
        response.json()


def test_mock_transports_cannot_open_real_connections() -> None:
    """The injected transport is in-memory; no socket is ever involved."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    client = _service(transport, "https://api.github.com")
    assert isinstance(client.transport, httpx.MockTransport)
    client.send_with_retry_sync("GET", REPO_PATH)
    assert seen == [f"https://api.github.com{REPO_PATH}"]
