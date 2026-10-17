"""OSV advisory integration tests (TASK-119/120).

All advisory traffic runs over ``httpx.MockTransport``: unit tests never
depend on live OSV responses. Covers query semantics (exact versions only),
defensive response parsing, timeout/retry/failure behavior from frozen
settings, failure isolation, deduplication, and redaction.
"""

import json

import httpx
import pytest

from app.analyzers.dependency.osv import (
    OsvClient,
    OsvOutcome,
    OsvQuery,
    advisory_status,
    build_queries,
    osv_client_from_network_settings,
    parse_advisory,
)
from app.core.config import load_settings
from tests.fixtures.helpers.dependency_helpers import (
    analyze_manifests,
    default_osv_client,
    mock_osv_client,
    rule_result,
)

VULN_FULL = {
    "id": "GHSA-test-0001",
    "aliases": ["CVE-2024-0001", "PYSEC-2024-1"],
    "summary": "Test advisory summary",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "references": [{"type": "ADVISORY", "url": "https://example.test/advisory/1"}],
    "published": "2024-01-01T00:00:00Z",
    "modified": "2024-01-02T00:00:00Z",
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
}


def _batch_handler(
    vulns_by_index: dict[int, list[dict[str, object]]],
    hydrate: dict[str, dict[str, object]] | None = None,
    requests: list[httpx.Request] | None = None,
) -> object:
    def handler(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request)
        if request.url.path == "/v1/querybatch":
            body = json.loads(request.content.decode("utf-8"))
            count = len(body["queries"])
            results: list[object] = []
            for index in range(count):
                vulns = vulns_by_index.get(index, [])
                if vulns:
                    results.append({"vulns": vulns})
                else:
                    results.append({})
            return httpx.Response(200, json={"results": results})
        if request.url.path.startswith("/v1/vulns/"):
            advisory_id = request.url.path.rsplit("/", 1)[-1]
            record = (hydrate or {}).get(advisory_id, VULN_FULL)
            return httpx.Response(200, json=record)
        return httpx.Response(404, json={})

    return handler


def _occurrence(ecosystem: str, name: str, version: str | None) -> object:
    from app.analyzers.dependency.models import DependencyOccurrence

    return DependencyOccurrence(
        ecosystem=ecosystem,
        canonical_name=name,
        original_name=name,
        constraint=None,
        resolved_version=version,
        source_file="requirements.txt",
        project_context="",
        section="requirements",
    )


def test_query_building_exact_versions_only() -> None:
    queries, skipped = build_queries(
        [
            _occurrence("pypi", "requests", "2.31.0"),
            _occurrence("pypi", "flask", None),  # range-only: never queried
            _occurrence("npm", "react", "18.2.0"),
            _occurrence("gems", "rails", "7.0.0"),  # unsupported ecosystem
            _occurrence("pypi", "requests", "2.31.0"),  # duplicate triple
            _occurrence("pypi", "empty", "  "),
        ]
    )
    assert [(q.ecosystem, q.package_name, q.version) for q in queries] == [
        ("npm", "react", "18.2.0"),
        ("pypi", "requests", "2.31.0"),
    ]
    # Skipped: range-only flask, unsupported gems, blank version. The repeated
    # triple is deduplicated into one query (not recorded as skipped).
    assert sorted(skipped) == [1, 3, 5]


def test_osv_ecosystem_identifiers_are_contract_values() -> None:
    seen: list[httpx.Request] = []
    client = mock_osv_client(_batch_handler({}, requests=seen))  # type: ignore[arg-type]
    client.query_batch([OsvQuery("pypi", "requests", "2.31.0"), OsvQuery("npm", "react", "18.2.0")])
    body = json.loads(seen[0].content.decode("utf-8"))
    ecosystems = [item["package"]["ecosystem"] for item in body["queries"]]
    assert ecosystems == ["PyPI", "npm"]


def test_known_advisory_becomes_high_high_finding() -> None:
    client = mock_osv_client(_batch_handler({0: [{"id": "GHSA-test-0001"}]}))  # type: ignore[arg-type]
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"}, osv_client=client)
    findings = rule_result(result, "DEP-KNOWN-VULNERABILITY").findings
    assert len(findings) == 1
    (finding,) = findings
    assert finding.severity.value == "High"
    assert finding.confidence.value == "High"
    assert "GHSA-test-0001" in finding.description
    assert "CVE-2024-0001" in finding.description
    assert "advisory information for review" in finding.description
    assert "requirements.txt" in finding.description


def test_no_advisories_is_not_failure() -> None:
    client = mock_osv_client(_batch_handler({}))  # type: ignore[arg-type]
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"}, osv_client=client)
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert outcome.failure is None


def test_multiple_advisories_multiple_findings() -> None:
    second = dict(VULN_FULL, id="GHSA-test-0002", aliases=["CVE-2024-0002"])
    client = mock_osv_client(
        _batch_handler(
            {0: [{"id": "GHSA-test-0001"}, {"id": "GHSA-test-0002"}]},
            hydrate={"GHSA-test-0001": VULN_FULL, "GHSA-test-0002": second},
        )  # type: ignore[arg-type]
    )
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"}, osv_client=client)
    findings = rule_result(result, "DEP-KNOWN-VULNERABILITY").findings
    assert {item.identity_key for item in findings}.__len__() == 2


def test_repeated_occurrences_share_one_advisory_finding() -> None:
    """One advisory over two occurrences: one finding, both mapped."""
    client = mock_osv_client(_batch_handler({0: [{"id": "GHSA-test-0001"}]}))  # type: ignore[arg-type]
    result, _, _ = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "services/api/requirements.txt": "requests==2.31.0\n",
        },
        osv_client=client,
    )
    findings = rule_result(result, "DEP-KNOWN-VULNERABILITY").findings
    assert len(findings) == 1
    assert "services/api/requirements.txt" in findings[0].description


def test_missing_severity_is_unknown_not_invented() -> None:
    advisory = parse_advisory(
        {"id": "GHSA-x", "aliases": []}, ecosystem="pypi", package_name="requests"
    )
    assert advisory.severity == "unknown"
    client = mock_osv_client(
        _batch_handler({0: [{"id": "GHSA-x"}]}, hydrate={"GHSA-x": {"id": "GHSA-x"}})  # type: ignore[arg-type]
    )
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"}, osv_client=client)
    (finding,) = rule_result(result, "DEP-KNOWN-VULNERABILITY").findings
    assert finding.severity.value == "High"  # frozen rule severity, not advisory-derived


def test_malformed_json_is_failure_not_clean() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json{{{")

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, osv_client=mock_osv_client(handler)
    )
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert any(
        "failed" in item.reason or "unavailable" in item.reason for item in outcome.limitations
    )


def test_unexpected_shape_is_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": []})

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, osv_client=mock_osv_client(handler)
    )
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert outcome.limitations


def test_http_4xx_is_failure_without_retry() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404, json={})

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, osv_client=mock_osv_client(handler)
    )
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert outcome.limitations
    assert len(calls) == 1  # permanent client errors are never retried


def test_http_5xx_retries_then_fails() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500, json={})

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, osv_client=mock_osv_client(handler)
    )
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert outcome.limitations
    assert len(calls) == 3  # initial + 2 frozen retries


def test_timeout_retries_then_succeeds() -> None:
    calls: list[httpx.Request] = []
    batch = _batch_handler({0: [{"id": "GHSA-test-0001"}]})

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectTimeout("slow", request=request)
        return batch(request)  # type: ignore[operator]

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, osv_client=mock_osv_client(handler)
    )
    assert len(rule_result(result, "DEP-KNOWN-VULNERABILITY").findings) == 1
    assert len(calls) >= 2


def test_timeout_exhaustion_is_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, osv_client=mock_osv_client(handler)
    )
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert any(
        "failed" in item.reason or "timed out" in item.reason for item in outcome.limitations
    )


def test_partial_batch_failure_preserves_valid_results() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-a"}]}, {"vulns": [{"id": "GHSA-b"}]}]},
            )
        if request.url.path.endswith("GHSA-a"):
            return httpx.Response(200, json=dict(VULN_FULL, id="GHSA-a"))
        return httpx.Response(500, json={})

    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\nflask==3.0.0\n"},
        osv_client=mock_osv_client(handler, max_retries=0),
    )
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert len(outcome.findings) == 1
    assert "GHSA-a" in outcome.findings[0].description
    # Queries sort by (ecosystem, name, version): flask is index 0 (hydrated),
    # requests is index 1 (failed) — the valid result is preserved.
    assert "flask" in outcome.findings[0].description
    assert any("requests" in item.reason for item in outcome.limitations)


def test_osv_failure_preserves_local_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    result, _, _ = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "services/api/requirements.txt": "requests==2.28.0\n",
        },
        osv_client=mock_osv_client(handler, max_retries=0),
    )
    assert len(rule_result(result, "DEP-DUPLICATE-VERSION").findings) == 1
    osv_outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert osv_outcome.findings == ()
    assert osv_outcome.limitations


def test_client_uses_frozen_network_settings() -> None:
    network = load_settings().network
    service = osv_client_from_network_settings(network)
    assert service.base_url == "https://api.osv.dev"
    assert service.timeout.read == network.advisory_timeout_s
    assert service.timeout.connect == network.connect_timeout_s
    assert service.retry_policy.max_retries == network.retries_metadata


def test_default_osv_client_factory() -> None:
    client = default_osv_client(_batch_handler({}))  # type: ignore[arg-type]
    assert isinstance(client, OsvClient)


def test_https_enforced_and_no_credentials() -> None:
    seen: list[httpx.Request] = []
    client = mock_osv_client(_batch_handler({}, requests=seen))  # type: ignore[arg-type]
    client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert seen and str(seen[0].url).startswith("https://")
    assert "authorization" not in {key.lower() for key in seen[0].headers}


def test_error_bodies_are_redacted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("token=secret-value-123", request=request)

    client = mock_osv_client(handler, max_retries=0)
    outcome = client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert outcome.transport_failed
    assert "secret-value-123" not in outcome.failure_reason


def test_retry_after_is_honored_without_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import osv_gateway as gateway_module

    sleeps: list[float] = []
    monkeypatch.setattr(gateway_module.time, "sleep", lambda delay: sleeps.append(delay))
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, json={}, headers={"Retry-After": "1"})
        return httpx.Response(200, json={"results": [{}]})

    client = mock_osv_client(handler)
    outcome = client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert outcome.transport_failed is False
    assert sleeps and sleeps[0] == 1


def test_only_valid_exact_versions_are_queried() -> None:
    """FAIL-2: wildcards/constraints never leave as exact versions."""
    seen: list[httpx.Request] = []
    client = mock_osv_client(_batch_handler({}, requests=seen))  # type: ignore[arg-type]
    result, _, _ = analyze_manifests(
        {
            "Pipfile.lock": (
                '{"default": {"good": {"version": "==1.2.3"}, '
                '"wild": {"version": "*"}, "blank": {"version": ""}, '
                '"ranged": {"version": ">=1.0"}}, "develop": {}}'
            ),
            "requirements.txt": "pinned==4.5.6\nranged>=1.0\n",
        },
        osv_client=client,
    )
    assert seen
    body = json.loads(seen[0].content.decode("utf-8"))
    queried = sorted((item["package"]["name"], item["version"]) for item in body["queries"])
    assert queried == [("good", "1.2.3"), ("pinned", "4.5.6")]
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert any("wild" in item.reason or "no exact" in item.reason for item in outcome.limitations)


def test_dotted_poetry_name_queries_canonical_identity() -> None:
    """FAIL-3: the OSV request uses the full canonical name, never a fragment."""
    seen: list[httpx.Request] = []
    client = mock_osv_client(_batch_handler({}, requests=seen))  # type: ignore[arg-type]
    analyze_manifests(
        {
            "pyproject.toml": (
                '[tool.poetry]\nname="d"\n[tool.poetry.dependencies]\n'
                'python = "^3.13"\n"zope.interface" = "==5.0"\n'
            )
        },
        osv_client=client,
    )
    assert seen
    body = json.loads(seen[0].content.decode("utf-8"))
    names = [item["package"]["name"] for item in body["queries"]]
    assert names == ["zope-interface"]
    assert "interface" not in names


def test_batch_pagination_is_followed() -> None:
    """C4: `next_page_token` results are fetched with page_token follow-ups."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path != "/v1/querybatch":
            return httpx.Response(200, json=dict(VULN_FULL, id=request.url.path.rsplit("/", 1)[-1]))
        body = json.loads(request.content.decode("utf-8"))
        if any("page_token" in item for item in body["queries"]):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-page2"}]}]})
        return httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-page1"}], "next_page_token": "tok"}]}
        )

    client = mock_osv_client(handler)
    outcome = client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert outcome.transport_failed is False
    assert 0 not in outcome.failed_indexes
    assert [item.advisory_id for item in outcome.advisories[0]] == ["GHSA-page1", "GHSA-page2"]
    followups = [
        request
        for request in calls
        if request.url.path == "/v1/querybatch"
        and "page_token" in json.loads(request.content.decode("utf-8"))["queries"][0]
    ]
    assert len(followups) == 1


def test_pagination_token_loop_is_bounded() -> None:
    """C4: a repeating token stops the walk without losing collected entries."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/v1/querybatch":
            return httpx.Response(200, json=dict(VULN_FULL, id="GHSA-loop"))
        return httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-loop"}], "next_page_token": "same"}]}
        )

    client = mock_osv_client(handler)
    outcome = client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert [item.advisory_id for item in outcome.advisories[0]] == ["GHSA-loop"]
    assert 0 in outcome.failed_indexes  # incomplete walk is explicit, not clean


def test_hydration_caps_preserve_obtained_advisories() -> None:
    """C5: per-position hydration is bounded; obtained advisories survive."""
    from app.services import osv_gateway as gateway_module

    ids = [f"GHSA-{index:04d}" for index in range(gateway_module.MAX_HYDRATIONS_PER_POSITION + 5)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": vid} for vid in ids]}]})
        advisory_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=dict(VULN_FULL, id=advisory_id))

    client = mock_osv_client(handler)
    outcome = client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert len(outcome.advisories[0]) == gateway_module.MAX_HYDRATIONS_PER_POSITION
    assert 0 in outcome.failed_indexes  # truncation is explicit


def test_entries_without_ids_are_not_clean() -> None:
    """C6: a page of unusable entries never reads as 'no advisories'."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"noid": 1}, "oops"]}]})
        return httpx.Response(200, json=dict(VULN_FULL, id="GHSA-x"))

    client = mock_osv_client(handler)
    outcome = client.query_batch([OsvQuery("pypi", "requests", "2.31.0")])
    assert outcome.advisories[0] == []
    assert 0 in outcome.failed_indexes


def test_advisory_status_none_when_no_eligible_query() -> None:
    """No eligible query means OSV was never consulted (advisory_data null)."""
    assert advisory_status(OsvOutcome(), 0) is None


def test_advisory_status_succeeded_when_all_assessed() -> None:
    outcome = OsvOutcome(advisories={0: [], 1: []})
    assert advisory_status(outcome, 2) == "succeeded"


def test_advisory_status_partly_succeeded_when_some_failed() -> None:
    outcome = OsvOutcome(advisories={0: []}, failed_indexes={1})
    assert advisory_status(outcome, 2) == "partly succeeded"


def test_advisory_status_unavailable_when_nothing_obtained() -> None:
    """A transport failure over every query is unavailable, never clean."""
    outcome = OsvOutcome(transport_failed=True, failed_indexes={0, 1})
    assert advisory_status(outcome, 2) == "unavailable"


def test_advisory_status_partly_when_all_failed_but_data_obtained() -> None:
    """Advisories obtained despite truncation are partial, not unavailable."""
    advisory = parse_advisory({"id": "GHSA-x"}, ecosystem="pypi", package_name="requests")
    outcome = OsvOutcome(advisories={0: [advisory]}, failed_indexes={0})
    assert advisory_status(outcome, 1) == "partly succeeded"
