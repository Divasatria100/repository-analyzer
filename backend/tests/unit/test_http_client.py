"""HTTPX service-client foundation tests. No real network I/O."""

import asyncio
from collections.abc import Callable

import httpx
import pytest

from app.core.config import load_settings
from app.services.http_client import (
    RetryPolicy,
    ServiceClient,
    ServiceClientError,
    ServiceConnectionError,
    ServiceResponseError,
    ServiceTimeoutError,
    TimeoutConfig,
    _to_service_error,
    client_from_network_settings,
)

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler | None = None, **kwargs: object) -> ServiceClient:
    return ServiceClient(
        name="test-service",
        base_url="https://example.test/api",
        retry_policy=RetryPolicy(max_retries=2, backoff_base_s=0),
        transport=httpx.MockTransport(handler) if handler is not None else None,
        **kwargs,  # type: ignore[arg-type]
    )


def test_client_construction_is_inert() -> None:
    """Building clients performs no network call."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={})

    client = _client(handler)
    sync_client = client.build_sync_client()
    sync_client.close()
    assert requests == []


def test_timeout_config_maps_to_httpx() -> None:
    timeout = TimeoutConfig(connect=10, read=60).to_httpx()
    assert timeout.connect == 10
    assert timeout.read == 60


def test_sync_send_succeeds() -> None:
    client = _client(lambda request: httpx.Response(200, json={"ok": True}))
    response = client.send_with_retry_sync("GET", "status")
    assert response.status_code == 200


def test_sync_send_retries_transient_then_succeeds() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 3:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, json={})

    client = _client(handler)
    response = client.send_with_retry_sync("GET", "status")
    assert response.status_code == 200
    assert len(attempts) == 3


def test_sync_send_exhaustion_raises_connection_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(ServiceConnectionError):
        _client(handler).send_with_retry_sync("GET", "status")


def test_timeout_maps_to_timeout_error() -> None:
    error = httpx.ConnectTimeout("slow")
    assert isinstance(_to_service_error(error), ServiceTimeoutError)


def test_server_error_status_raises_response_error() -> None:
    client = _client(lambda request: httpx.Response(503, json={}))
    with pytest.raises(ServiceResponseError) as exc_info:
        client.send_with_retry_sync("GET", "status")
    assert exc_info.value.status_code == 503


def test_async_send_succeeds_without_event_loop_setup() -> None:
    client = _client(lambda request: httpx.Response(200, json={"ok": True}))
    response = asyncio.run(client.send_with_retry("GET", "status", sleep=lambda delay: None))
    assert response.status_code == 200
    assert isinstance(response, httpx.Response)


def test_non_https_base_url_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        ServiceClient(name="x", base_url="http://example.test")


def test_credential_headers_rejected() -> None:
    with pytest.raises(ValueError, match="Credential header"):
        ServiceClient(
            name="x", base_url="https://example.test", headers={"Authorization": "Bearer abc"}
        )


def test_client_built_from_centralized_network_settings() -> None:
    settings = load_settings()
    client = client_from_network_settings(
        "github",
        "https://api.github.com",
        connect_timeout_s=settings.network.connect_timeout_s,
        read_timeout_s=settings.network.read_timeout_s,
        max_retries=settings.network.retries_metadata,
    )
    assert client.timeout.connect == 10
    assert client.timeout.read == 60
    assert client.retry_policy.max_retries == 2


def test_unexpected_error_is_service_error() -> None:
    assert isinstance(_to_service_error(httpx.HTTPError("x")), ServiceClientError)
