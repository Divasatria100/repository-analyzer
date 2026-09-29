"""HTTPX service-client foundation (inert until used).

Reusable outbound-HTTP building blocks for the future Infrastructure
gateways (GitHub REST API, OSV advisory service). This module provides
**no** GitHub or OSV integration — only the foundation:

* consistent async/sync client factories sharing one timeout model;
* timeout and retry values sourced from centralized settings
  (``NetworkSettings``), never scattered hardcoded values;
* an error-handling boundary mapping ``httpx`` failures to
  ``ServiceClientError`` categories (timeout, connection, response);
* dependency-injectable transports for tests (``httpx.MockTransport``) —
  no test in this foundation performs real network I/O;
* clients are inert: constructing them performs no network call, and
  importing this module performs no I/O at all.

Security notes (docs/15 §11): clients contact only approved destinations
chosen by RepoLens (never repository-directed URLs), always over HTTPS,
and never carry credentials — V1.0 uses no GitHub authentication
(docs/09 §6), so ``Authorization`` headers are rejected outright.
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

_HTTPS = "https://"


class ServiceClientError(Exception):
    """Base error for outbound service communication (user-safe message)."""


class ServiceTimeoutError(ServiceClientError):
    """The service call exceeded its configured timeout."""


class ServiceConnectionError(ServiceClientError):
    """The service could not be reached at an approved destination."""


class ServiceResponseError(ServiceClientError):
    """The service returned an error status."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class TimeoutConfig:
    """Timeout model shared by sync and async clients (seconds)."""

    connect: float = 10.0
    read: float = 60.0

    def to_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.connect, read=self.read, write=self.read, pool=self.connect
        )


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry for transient failures. Counts come from settings."""

    max_retries: int = 2
    backoff_base_s: float = 0.5

    def delay_for_attempt(self, attempt: int) -> float:
        return self.backoff_base_s * (2**attempt)


def _is_transient(error: Exception) -> bool:
    return isinstance(error, (httpx.TimeoutException, httpx.TransportError))


def _to_service_error(error: httpx.HTTPError) -> ServiceClientError:
    if isinstance(error, httpx.TimeoutException):
        return ServiceTimeoutError(f"Service call timed out: {error}")
    if isinstance(error, httpx.TransportError):
        return ServiceConnectionError(f"Service could not be reached: {error}")
    return ServiceClientError(f"Service communication failed: {error}")


def _check_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Reject credential-bearing headers (V1.0 uses no service auth)."""
    safe = dict(headers or {})
    for key in safe:
        if key.lower() in {"authorization", "proxy-authorization", "cookie"}:
            raise ValueError(f"Credential header not allowed in V1.0: {key}")
    return safe


def _check_base_url(base_url: str) -> str:
    if not base_url.startswith(_HTTPS):
        raise ValueError("Service base URL must use HTTPS.")
    return base_url.rstrip("/")


@dataclass
class ServiceClient:
    """Reusable outbound HTTP client foundation for one approved service.

    Inert until a ``send_*`` method is called. ``transport`` accepts an
    ``httpx`` transport (e.g. ``MockTransport``) for tests.
    """

    name: str
    base_url: str
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    transport: httpx.BaseTransport | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.base_url = _check_base_url(self.base_url)
        self.headers = _check_headers(self.headers)

    def build_async_client(self) -> httpx.AsyncClient:
        """Build an async client. Performs no network I/O."""
        return httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout.to_httpx(),
            headers=self.headers,
            transport=cast("httpx.AsyncBaseTransport | None", self.transport),
        )

    def build_sync_client(self) -> httpx.Client:
        """Build a sync client. Performs no network I/O."""
        return httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout.to_httpx(),
            headers=self.headers,
            transport=self.transport,
        )

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    async def send_with_retry(
        self,
        method: str,
        path: str,
        sleep: Callable[[float], Any] | None = None,
    ) -> httpx.Response:
        """Send a request with bounded retries on transient failures."""
        last_error: Exception | None = None
        pause = sleep or asyncio.sleep
        async with self.build_async_client() as client:
            for attempt in range(self.retry_policy.max_retries + 1):
                try:
                    response = await client.request(method, self.url(path))
                    if response.status_code >= 500:
                        raise ServiceResponseError(
                            f"{self.name} returned status {response.status_code}.",
                            response.status_code,
                        )
                    return response
                except ServiceResponseError:
                    raise
                except httpx.HTTPError as error:
                    if not _is_transient(error) or attempt >= self.retry_policy.max_retries:
                        raise _to_service_error(error) from error
                    last_error = error
                    await pause(self.retry_policy.delay_for_attempt(attempt))
        if isinstance(last_error, httpx.HTTPError):
            raise _to_service_error(last_error)
        raise ServiceClientError(f"{self.name} request failed.")

    def send_with_retry_sync(self, method: str, path: str) -> httpx.Response:
        """Sync variant of :meth:`send_with_retry`."""
        last_error: Exception | None = None
        with self.build_sync_client() as client:
            for attempt in range(self.retry_policy.max_retries + 1):
                try:
                    response = client.request(method, self.url(path))
                    if response.status_code >= 500:
                        raise ServiceResponseError(
                            f"{self.name} returned status {response.status_code}.",
                            response.status_code,
                        )
                    return response
                except ServiceResponseError:
                    raise
                except httpx.HTTPError as error:
                    if not _is_transient(error) or attempt >= self.retry_policy.max_retries:
                        raise _to_service_error(error) from error
                    last_error = error
                    time.sleep(self.retry_policy.delay_for_attempt(attempt))
        if isinstance(last_error, httpx.HTTPError):
            raise _to_service_error(last_error)
        raise ServiceClientError(f"{self.name} request failed.")


def client_from_network_settings(
    name: str,
    base_url: str,
    *,
    connect_timeout_s: float,
    read_timeout_s: float,
    max_retries: int,
    transport: httpx.BaseTransport | None = None,
) -> ServiceClient:
    """Build a :class:`ServiceClient` from centralized network settings values."""
    return ServiceClient(
        name=name,
        base_url=base_url,
        timeout=TimeoutConfig(connect=connect_timeout_s, read=read_timeout_s),
        retry_policy=RetryPolicy(max_retries=max_retries),
        transport=transport,
    )
