"""OSV advisory gateway: exact-version lookup over the ServiceClient boundary.

Infrastructure gateway for the OSV advisory service (mirrors
``app.repository.github`` for GitHub metadata): HTTPS only, configured
timeouts/retries from centralized settings, no credentials. Responses are
parsed defensively; malformed bodies fail safely and never read as clean.
Raw upstream bodies never reach logs or users.

The official OSV API v1 contract (verified against
https://google.github.io/osv.dev/post-v1-querybatch/ and the OSV OpenAPI
description during implementation):

* ``POST {base}/v1/querybatch`` with
  ``{"queries": [{"package": {"name", "ecosystem"}, "version"}]}`` where the
  ecosystem is ``PyPI`` or ``npm``. The response carries per-query
  vulnerability ID lists (``{"results": [{"vulns": [{"id", "modified"}]}]}``)
  in input order; ``{}`` means no known advisories for that query.
* ``GET {base}/v1/vulns/{id}`` hydrates one advisory into the full OSV
  Vulnerability object (``id``, ``aliases``, ``summary``, ``severity``,
  ``affected``, ``references``, ``published``, ``modified``).

Only exact resolved versions are queried (ranges are never converted to
exact versions; empty versions and unsupported ecosystems are never sent).
The existing :class:`ServiceClient` provides timeouts, transports
(``httpx.MockTransport`` in tests), HTTPS enforcement, and error
normalization; this module adds the POST-body retry loop honoring the same
:class:`RetryPolicy` (transient failures only, bounded, ``Retry-After``
respected) because the foundation's ``send_with_retry`` sends bodyless
requests. No second HTTP client is created.

Failure isolation: manifest analysis always completes; a failed advisory
lookup is recorded as a limitation and never reads as "no advisories".
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

import httpx

from app.analyzers.dependency.models import Advisory
from app.core.config import NetworkSettings
from app.core.logging import get_logger, log_event, redact_text
from app.services.http_client import (
    ServiceClient,
    ServiceConnectionError,
    ServiceResponseError,
    ServiceTimeoutError,
    client_from_network_settings,
)

_logger = get_logger("analyzers.dependency.osv")

OSV_BASE_URL = "https://api.osv.dev"

#: OSV ecosystem identifiers (case-sensitive contract values).
OSV_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}

#: Batch sizing: OSV accepts up to 1000 queries per batch; we stay far below.
MAX_BATCH_QUERIES = 100

#: Follow-up page fetches per batch when responses carry ``next_page_token``
#: (OSV paginates past ~1000 vulns per query / ~3000 per queryset).
MAX_FOLLOWUP_PAGES = 10

#: Hydration guards: per-query and per-``query_batch`` caps on ``GET
#: /v1/vulns/{id}`` calls so one advisory-heavy package cannot produce
#: unbounded traffic. Truncated positions are marked failed (explicit
#: limitation downstream) while advisories already obtained are preserved.
MAX_HYDRATIONS_PER_POSITION = 100
MAX_HYDRATIONS_TOTAL = 1000

#: Defensive cap on one decoded response body (advisories are small JSON).
MAX_RESPONSE_BYTES = 1 * 1024 * 1024

#: Upper bound on honored Retry-After delays (seconds).
MAX_RETRY_AFTER_S = 30.0


@dataclass(frozen=True)
class OsvQuery:
    """One exact-version advisory query (queryable triple only)."""

    ecosystem: str  # internal scope key: pypi | npm
    package_name: str  # canonical name for the ecosystem
    version: str  # exact resolved version


@dataclass
class OsvOutcome:
    """Advisory results keyed by query index, plus explicit failures."""

    advisories: dict[int, list[Advisory]] = field(default_factory=dict)
    failed_indexes: set[int] = field(default_factory=set)
    transport_failed: bool = False
    failure_reason: str = ""


def osv_client_from_network_settings(
    network: NetworkSettings,
    transport: httpx.BaseTransport | None = None,
) -> ServiceClient:
    """Build the OSV service client from centralized network settings.

    Timeout: ``advisory.timeout_s`` bounds reads; connect uses the shared
    ``net.connect_timeout_s``. Retries use the shared metadata policy. No
    value is hardcoded here (TASK-120: frozen policy, never literals).
    """
    return client_from_network_settings(
        "osv",
        OSV_BASE_URL,
        connect_timeout_s=network.connect_timeout_s,
        read_timeout_s=network.advisory_timeout_s,
        max_retries=network.retries_metadata,
        transport=transport,
    )


class OsvClient:
    """Batch advisory lookup over an existing :class:`ServiceClient`."""

    def __init__(self, client: ServiceClient) -> None:
        self._client = client
        self._hydration_budget = MAX_HYDRATIONS_TOTAL

    def query_batch(self, queries: list[OsvQuery]) -> OsvOutcome:
        """Run batch queries with hydration; partial results are preserved."""
        outcome = OsvOutcome()
        if not queries:
            return outcome
        self._hydration_budget = MAX_HYDRATIONS_TOTAL
        for chunk_start in range(0, len(queries), MAX_BATCH_QUERIES):
            chunk = queries[chunk_start : chunk_start + MAX_BATCH_QUERIES]
            self._query_chunk(chunk, chunk_start, outcome)
        return outcome

    def _query_chunk(self, chunk: list[OsvQuery], offset: int, outcome: OsvOutcome) -> None:
        try:
            response = self._post_json("/v1/querybatch", _batch_payload(chunk, None))
        except (ServiceTimeoutError, ServiceConnectionError, ServiceResponseError) as exc:
            outcome.transport_failed = True
            outcome.failure_reason = redact_text(str(exc)) or type(exc).__name__
            for position in range(len(chunk)):
                outcome.failed_indexes.add(offset + position)
            log_event(
                _logger,
                logging.ERROR,
                "dependency.osv.batch.failed",
                "OSV batch query failed; recorded as unavailable, never clean",
                error=redact_text(str(exc)),
            )
            return
        results = _decode_results(response)
        if results is None:
            outcome.transport_failed = True
            outcome.failure_reason = "malformed OSV response; recorded as unavailable"
            for position in range(len(chunk)):
                outcome.failed_indexes.add(offset + position)
            return
        collected = self._collect_pages(chunk, offset, results, outcome)
        for position in sorted(collected):
            self._hydrate_position(chunk, offset, position, collected[position], outcome)

    def _collect_pages(
        self,
        chunk: list[OsvQuery],
        offset: int,
        first_results: list[object],
        outcome: OsvOutcome,
    ) -> dict[int, list[object]]:
        """Gather vuln entries across initial + follow-up pages per position.

        Follow-up requests carry ``page_token`` only for queries whose result
        included ``next_page_token`` (the documented querybatch contract).
        Token loops and page budgets stop the walk; positions left incomplete
        are marked failed while entries already collected are preserved.
        """
        collected: dict[int, list[object]] = {}
        pending: dict[int, str] = {}
        self._absorb_page(chunk, offset, first_results, collected, pending, outcome)
        seen_tokens: set[tuple[int, str]] = set()
        pages = 0
        while pending and pages < MAX_FOLLOWUP_PAGES:
            pages += 1
            ordered = sorted(pending)
            payload = _batch_payload([chunk[i] for i in ordered], [pending[i] for i in ordered])
            try:
                response = self._post_json("/v1/querybatch", payload)
            except (ServiceTimeoutError, ServiceConnectionError, ServiceResponseError):
                for position in ordered:
                    outcome.failed_indexes.add(offset + position)
                pending.clear()
                break
            results = _decode_results(response)
            if results is None or len(results) != len(ordered):
                for position in ordered:
                    outcome.failed_indexes.add(offset + position)
                pending.clear()
                break
            next_pending: dict[int, str] = {}
            for slot, position in enumerate(ordered):
                entry = results[slot]
                if not isinstance(entry, dict):
                    outcome.failed_indexes.add(offset + position)
                    continue
                vulns = entry.get("vulns", [])
                if not isinstance(vulns, list):
                    outcome.failed_indexes.add(offset + position)
                    continue
                collected.setdefault(position, []).extend(
                    item for item in vulns if isinstance(item, dict)
                )
                token = entry.get("next_page_token")
                if isinstance(token, str) and token:
                    if (position, token) in seen_tokens:
                        # Looping token: stop, keep what was collected, mark it.
                        outcome.failed_indexes.add(offset + position)
                        continue
                    seen_tokens.add((position, token))
                    next_pending[position] = token
            pending = next_pending
        for position in pending:
            # Page budget exhausted with results still outstanding.
            outcome.failed_indexes.add(offset + position)
        return collected

    def _absorb_page(
        self,
        chunk: list[OsvQuery],
        offset: int,
        results: list[object],
        collected: dict[int, list[object]],
        pending: dict[int, str],
        outcome: OsvOutcome,
    ) -> None:
        for position in range(len(chunk)):
            if position >= len(results):
                outcome.failed_indexes.add(offset + position)
                continue
            entry = results[position]
            if not isinstance(entry, dict):
                outcome.failed_indexes.add(offset + position)
                continue
            vulns = entry.get("vulns", [])
            if not isinstance(vulns, list):
                outcome.failed_indexes.add(offset + position)
                continue
            collected[position] = [item for item in vulns if isinstance(item, dict)]
            token = entry.get("next_page_token")
            if isinstance(token, str) and token:
                pending[position] = token

    def _hydrate_position(
        self,
        chunk: list[OsvQuery],
        offset: int,
        position: int,
        entries: list[object],
        outcome: OsvOutcome,
    ) -> None:
        query = chunk[position]
        usable = [
            entry
            for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        ]
        if entries and not usable:
            # Structurally present but content-unusable: never read as clean.
            outcome.advisories[offset + position] = []
            outcome.failed_indexes.add(offset + position)
            return
        # The same advisory listed twice (e.g. a replayed page) is one advisory.
        deduped: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        for entry in usable:
            assert isinstance(entry, dict)
            advisory_id = str(entry["id"])
            if advisory_id in seen_ids:
                continue
            seen_ids.add(advisory_id)
            deduped.append(entry)
        usable = deduped
        truncated = False
        if len(usable) > MAX_HYDRATIONS_PER_POSITION:
            usable = usable[:MAX_HYDRATIONS_PER_POSITION]
            truncated = True
        if len(entries) != len(usable):
            # Some entries lacked usable IDs; the rest are still assessed.
            truncated = True
        hydrated: list[Advisory] = []
        failed = truncated
        for entry in usable:
            assert isinstance(entry, dict)
            if self._hydration_budget <= 0:
                failed = True
                break
            self._hydration_budget -= 1
            advisory = self._hydrate(str(entry["id"]), query)
            if advisory is None:
                failed = True
            else:
                hydrated.append(advisory)
        outcome.advisories[offset + position] = hydrated
        if failed:
            outcome.failed_indexes.add(offset + position)

    def _hydrate(self, advisory_id: str, query: OsvQuery) -> Advisory | None:
        """Fetch one advisory record; None when unavailable (never fabricated)."""
        try:
            response = self._get(f"/v1/vulns/{advisory_id}")
        except (ServiceTimeoutError, ServiceConnectionError, ServiceResponseError):
            return None
        try:
            if len(response.content) > MAX_RESPONSE_BYTES:
                return None
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        return parse_advisory(payload, ecosystem=query.ecosystem, package_name=query.package_name)

    def _post_json(self, path: str, payload: dict[str, object]) -> httpx.Response:
        """POST JSON with the client's bounded transient-retry policy."""
        return self._send_with_body("POST", path, payload)

    def _get(self, path: str) -> httpx.Response:
        """GET with the client's bounded transient-retry policy."""
        return self._send_with_body("GET", path, None)

    def _send_with_body(
        self, method: str, path: str, payload: dict[str, object] | None
    ) -> httpx.Response:
        """Send one request; retry transient failures per the shared policy."""
        policy = self._client.retry_policy
        last_error: Exception | None = None
        with self._client.build_sync_client() as client:
            for attempt in range(policy.max_retries + 1):
                try:
                    if payload is None:
                        response = client.request(method, self._client.url(path))
                    else:
                        response = client.request(method, self._client.url(path), json=payload)
                except (httpx.TimeoutException, httpx.TransportError) as error:
                    if attempt >= policy.max_retries:
                        raise _to_service_error(error) from error
                    last_error = error
                    time.sleep(policy.delay_for_attempt(attempt))
                    continue
                if response.status_code == 429:
                    if attempt >= policy.max_retries:
                        raise ServiceResponseError(
                            "OSV rate limit reached; advisory data unavailable.",
                            response.status_code,
                        )
                    time.sleep(_retry_after_s(response) or policy.delay_for_attempt(attempt))
                    continue
                if response.status_code >= 500:
                    if attempt >= policy.max_retries:
                        raise ServiceResponseError(
                            f"OSV returned status {response.status_code}.",
                            response.status_code,
                        )
                    time.sleep(policy.delay_for_attempt(attempt))
                    continue
                if response.status_code >= 400:
                    raise ServiceResponseError(
                        "OSV request was rejected; advisory data unavailable.",
                        response.status_code,
                    )
                return response
        if isinstance(last_error, httpx.TimeoutException):
            raise ServiceTimeoutError("OSV request timed out.") from last_error
        if isinstance(last_error, httpx.TransportError):
            raise ServiceConnectionError("OSV could not be reached.") from last_error
        raise ServiceResponseError("OSV request failed.", 0)


def _batch_payload(queries: list[OsvQuery], tokens: list[str] | None) -> dict[str, object]:
    """Build a querybatch body; ``tokens`` carries per-query page tokens."""
    body: list[dict[str, object]] = []
    for index, query in enumerate(queries):
        entry: dict[str, object] = {
            "package": {
                "name": query.package_name,
                "ecosystem": OSV_ECOSYSTEMS[query.ecosystem],
            },
            "version": query.version,
        }
        if tokens is not None and index < len(tokens):
            entry["page_token"] = tokens[index]
        body.append(entry)
    return {"queries": body}


def _to_service_error(error: httpx.HTTPError) -> ServiceConnectionError | ServiceTimeoutError:
    if isinstance(error, httpx.TimeoutException):
        return ServiceTimeoutError(f"OSV request timed out: {redact_text(str(error))}")
    return ServiceConnectionError(f"OSV could not be reached: {redact_text(str(error))}")


def _retry_after_s(response: httpx.Response) -> float | None:
    """Honored Retry-After delay in seconds (bounded, None when absent)."""
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        delay = float(raw.strip().split(",")[0])
    except ValueError:
        return None
    if delay < 0:
        return None
    return min(delay, MAX_RETRY_AFTER_S)


def _decode_results(response: httpx.Response) -> list[object] | None:
    """Decode a batch response defensively; None when unusable."""
    try:
        if len(response.content) > MAX_RESPONSE_BYTES:
            return None
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    results = payload.get("results")
    if not isinstance(results, list):
        return None
    return results


def parse_advisory(payload: dict[str, object], *, ecosystem: str, package_name: str) -> Advisory:
    """Normalize one OSV Vulnerability object defensively (never fabricated).

    Severity from OSV is a CVSS vector, not a RepoLens severity: it is kept
    as a ``type:score`` label when present and ``unknown`` otherwise. The
    finding severity (High, DEP-REQ-001) is assigned by the analyzer rule,
    never derived here.
    """
    advisory_id = str(payload.get("id", "") or "unknown")
    aliases_raw = payload.get("aliases")
    aliases = (
        tuple(str(item) for item in aliases_raw if isinstance(item, str))
        if isinstance(aliases_raw, list)
        else ()
    )
    summary = str(payload.get("summary", "") or "")
    severity = _advisory_severity_label(payload.get("severity"))
    references_raw = payload.get("references")
    references: list[str] = []
    if isinstance(references_raw, list):
        for entry in references_raw:
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                references.append(redact_text(entry["url"]))
    published = payload.get("published")
    modified = payload.get("modified")
    affected_version = _affected_version_label(payload.get("affected"))
    _ = json.dumps({"id": advisory_id})  # keep payload JSON-compatible by construction
    return Advisory(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=summary,
        severity=severity,
        references=tuple(references),
        published=str(published) if isinstance(published, str) else None,
        modified=str(modified) if isinstance(modified, str) else None,
        ecosystem=ecosystem,
        package_name=package_name,
        affected_version=affected_version,
    )


def _advisory_severity_label(value: object) -> str:
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, dict):
                entry_type = entry.get("type")
                score = entry.get("score")
                if isinstance(entry_type, str) and isinstance(score, str) and score:
                    return f"{entry_type}:{score}"
    return "unknown"


def _affected_version_label(value: object) -> str | None:
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, dict):
            versions = first.get("versions")
            if isinstance(versions, list) and versions and isinstance(versions[0], str):
                return versions[0]
    return None
