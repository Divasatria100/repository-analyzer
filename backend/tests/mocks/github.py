"""Deterministic GitHub API mocks for future ingestion tests.

Covers repository/branch/commit metadata scenarios through the existing
HTTPX injectable-transport mechanism. All values are synthetic; nothing
here contacts github.com. The GitHub integration itself is NOT implemented.
"""

import httpx

GITHUB_API = "https://api.github.com"

OWNER = "fixture-owner"
REPO = "fixture-repo"
DEFAULT_BRANCH = "main"
COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"

REPO_PATH = f"/repos/{OWNER}/{REPO}"

GitHubScenario = str

SCENARIOS = (
    "public_repo",
    "not_found",
    "private_repo",
    "branch_missing",
    "commit_missing",
    "server_error",
    "rate_limited",
    "timeout",
    "malformed",
)


def _repo_payload(private: bool = False) -> dict[str, object]:
    return {
        "id": 1001,
        "name": REPO,
        "full_name": f"{OWNER}/{REPO}",
        "private": private,
        "default_branch": DEFAULT_BRANCH,
    }


def _branch_payload(name: str) -> dict[str, object]:
    return {"name": name, "commit": {"sha": COMMIT_SHA}}


def _commit_payload() -> dict[str, object]:
    return {"sha": COMMIT_SHA, "commit": {"message": "fixture commit"}}


def github_transport(scenario: GitHubScenario) -> httpx.MockTransport:
    """Return a MockTransport replaying one GitHub scenario deterministically."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if scenario == "timeout":
            raise httpx.ConnectTimeout("mock github timeout", request=request)
        if scenario == "malformed":
            return httpx.Response(200, content=b"<html>not json</html>")
        if scenario == "server_error":
            return httpx.Response(500, json={"message": "Mock server error"})
        if scenario == "rate_limited":
            return httpx.Response(
                403,
                json={"message": "Mock API rate limit exceeded"},
                headers={"X-RateLimit-Remaining": "0"},
            )
        if path == REPO_PATH:
            if scenario == "not_found":
                return httpx.Response(404, json={"message": "Mock not found"})
            return httpx.Response(200, json=_repo_payload(scenario == "private_repo"))
        if path == f"{REPO_PATH}/branches/{DEFAULT_BRANCH}":
            if scenario == "branch_missing":
                return httpx.Response(404, json={"message": "Mock branch not found"})
            return httpx.Response(200, json=_branch_payload(DEFAULT_BRANCH))
        if path == f"{REPO_PATH}/commits/{COMMIT_SHA}":
            if scenario == "commit_missing":
                return httpx.Response(404, json={"message": "Mock commit not found"})
            return httpx.Response(200, json=_commit_payload())
        return httpx.Response(404, json={"message": "No mock route"})

    return httpx.MockTransport(handler)
