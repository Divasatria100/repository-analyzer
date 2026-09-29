"""GitHub REST gateway: validation, metadata, branch/commit resolution.

Reads repository metadata as data through the existing ServiceClient
boundary (HTTPS only, configured timeouts/retries, no credentials —
FR-007). Responses are validated with typed models; malformed bodies fail
safely. Raw upstream bodies and headers never reach logs or users.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from app.core.config import NetworkSettings, Settings
from app.core.logging import get_logger, log_event, redact_text
from app.repository.errors import (
    BranchNotFoundError,
    CommitNotFoundError,
    RepositoryNotAccessibleError,
    RepositoryNotFoundError,
    UpstreamError,
)
from app.repository.identity import RepositoryIdentity, validate_branch_name, validate_commit_sha
from app.services.http_client import (
    ServiceClient,
    ServiceConnectionError,
    ServiceResponseError,
    ServiceTimeoutError,
    client_from_network_settings,
)

GITHUB_API_BASE_URL = "https://api.github.com"

# Defensive cap: metadata responses are small JSON documents (SECISO-1104).
_MAX_METADATA_BYTES = 1 * 1024 * 1024

_logger = get_logger("github")


class RepoMetadata(BaseModel):
    """Validated subset of GET /repos/{owner}/{repo} we are allowed to trust."""

    name: str
    full_name: str
    private: bool
    default_branch: str
    repo_id: int = Field(alias="id")
    # GitHub reports repository size in kibibytes; None when absent.
    size_kb: int | None = Field(default=None, alias="size")

    model_config = {"populate_by_name": True}


class BranchInfo(BaseModel):
    """Verified branch name and its head commit SHA."""

    name: str
    head_sha: str


class CommitInfo(BaseModel):
    """Validated subset of GET .../commits/{sha}: the immutable SHA."""

    sha: str


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"


class GitHubClient:
    """Infrastructure gateway for GitHub metadata (no retrieval here)."""

    def __init__(self, client: ServiceClient) -> None:
        self._client = client

    def _get(self, path: str) -> httpx.Response:
        try:
            return self._client.send_with_retry_sync("GET", path)
        except ServiceTimeoutError as exc:
            raise UpstreamError() from exc
        except ServiceConnectionError as exc:
            raise UpstreamError() from exc
        except ServiceResponseError as exc:
            raise UpstreamError() from exc

    def _decode(self, response: httpx.Response) -> object:
        if len(response.content) > _MAX_METADATA_BYTES:
            raise UpstreamError()
        try:
            return response.json()
        except ValueError as exc:
            raise UpstreamError() from exc

    def get_repository(self, identity: RepositoryIdentity) -> RepoMetadata:
        """Fetch and validate repository metadata (existence/visibility/default)."""
        log_event(
            _logger,
            20,
            "repository.validation.started",
            "Validating public repository",
            repository=identity.full_name,
        )
        response = self._get(f"/repos/{identity.full_name}")
        if response.status_code == 404:
            # Unauthenticated GitHub answers 404 for missing AND private repos.
            raise RepositoryNotFoundError()
        if _is_rate_limited(response):
            raise UpstreamError("GitHub rate limit reached. Please try again later.")
        if response.status_code == 403:
            raise RepositoryNotAccessibleError()
        if response.status_code != 200:
            raise UpstreamError()
        try:
            metadata = RepoMetadata.model_validate(self._decode(response))
        except ValueError as exc:
            raise UpstreamError() from exc
        if metadata.private:
            raise RepositoryNotAccessibleError()
        if metadata.full_name.lower() != identity.full_name:
            raise RepositoryNotAccessibleError()
        log_event(
            _logger,
            20,
            "repository.validation.completed",
            "Repository validated as public",
            repository=identity.full_name,
            default_branch=metadata.default_branch,
        )
        return metadata

    def resolve_branch(self, identity: RepositoryIdentity, branch: str) -> BranchInfo:
        """Verify a branch exists; return its name and head commit SHA."""
        name = validate_branch_name(branch)
        encoded = quote(name, safe="")
        response = self._get(f"/repos/{identity.full_name}/branches/{encoded}")
        if response.status_code == 404:
            raise BranchNotFoundError()
        if _is_rate_limited(response):
            raise UpstreamError("GitHub rate limit reached. Please try again later.")
        if response.status_code != 200:
            raise UpstreamError()
        try:
            payload = self._decode(response)
            assert isinstance(payload, dict)
            commit = payload.get("commit")
            assert isinstance(commit, dict) and isinstance(commit.get("sha"), str)
            head_sha = validate_commit_sha(commit["sha"])
        except (ValueError, AssertionError) as exc:
            raise UpstreamError() from exc
        if len(head_sha) not in (40, 64):
            raise UpstreamError()
        log_event(
            _logger,
            20,
            "repository.branch.resolved",
            "Branch resolved",
            repository=identity.full_name,
            branch=name,
        )
        return BranchInfo(name=name, head_sha=head_sha)

    def resolve_commit(self, identity: RepositoryIdentity, sha_or_ref: str) -> CommitInfo:
        """Resolve a requested commit to its immutable full SHA (repo-scoped)."""
        requested = validate_commit_sha(sha_or_ref)
        encoded = quote(requested, safe="")
        response = self._get(f"/repos/{identity.full_name}/commits/{encoded}")
        if response.status_code == 404:
            raise CommitNotFoundError()
        if _is_rate_limited(response):
            raise UpstreamError("GitHub rate limit reached. Please try again later.")
        if response.status_code != 200:
            raise UpstreamError()
        try:
            payload = self._decode(response)
            assert isinstance(payload, dict) and isinstance(payload.get("sha"), str)
            info = CommitInfo.model_validate(payload)
        except (ValueError, AssertionError) as exc:
            raise UpstreamError() from exc
        validated = validate_commit_sha(info.sha)
        if len(validated) not in (40, 64):
            raise UpstreamError()
        log_event(
            _logger,
            20,
            "repository.commit.resolved",
            "Commit resolved",
            repository=redact_text(identity.full_name),
        )
        return CommitInfo(sha=validated)


def github_client_from_settings(
    settings: Settings,
    transport: httpx.BaseTransport | None = None,
) -> GitHubClient:
    """Build the gateway from centralized network settings (no hardcoded values)."""
    network: NetworkSettings = settings.network
    client = client_from_network_settings(
        "github",
        GITHUB_API_BASE_URL,
        connect_timeout_s=network.connect_timeout_s,
        read_timeout_s=network.read_timeout_s,
        max_retries=network.retries_metadata,
        transport=transport,
    )
    return GitHubClient(client)
