"""Deterministic OSV API mocks for future dependency-analysis tests.

Provides advisory response data only — no vulnerability matching logic, no
network access. All package names/versions/IDs are synthetic.
"""

import httpx

OSV_API = "https://api.osv.dev"
QUERY_PATH = "/v1/query"

PACKAGE = "fixture-package"
VERSION = "1.2.3"
VULN_ID = "FIXTURE-2026-0001"

OsvScenario = str

SCENARIOS = (
    "no_vulns",
    "one_vuln",
    "multiple_vulns",
    "server_error",
    "timeout",
    "malformed",
)


def _vuln(vuln_id: str, versions: list[str]) -> dict[str, object]:
    return {
        "id": vuln_id,
        "summary": "Fixture vulnerability (synthetic)",
        "affected": [{"package": {"name": PACKAGE}, "versions": versions}],
    }


def osv_transport(scenario: OsvScenario) -> httpx.MockTransport:
    """Return a MockTransport replaying one OSV scenario deterministically."""

    def handler(request: httpx.Request) -> httpx.Response:
        if scenario == "timeout":
            raise httpx.ConnectTimeout("mock osv timeout", request=request)
        if scenario == "malformed":
            return httpx.Response(200, content=b"[[broken")
        if request.url.path != QUERY_PATH:
            return httpx.Response(404, json={"message": "No mock route"})
        if scenario == "server_error":
            return httpx.Response(500, json={"message": "Mock OSV error"})
        if scenario == "no_vulns":
            return httpx.Response(200, json={"vulns": []})
        if scenario == "one_vuln":
            return httpx.Response(200, json={"vulns": [_vuln(VULN_ID, [VERSION])]})
        return httpx.Response(
            200,
            json={
                "vulns": [
                    _vuln(VULN_ID, [VERSION]),
                    _vuln("FIXTURE-2026-0002", ["1.2.0", VERSION]),
                ]
            },
        )

    return httpx.MockTransport(handler)
