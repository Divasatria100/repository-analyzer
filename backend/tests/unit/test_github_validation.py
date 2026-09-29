"""GitHub gateway tests: validation, metadata, branch/commit resolution.

All scenarios run through ServiceClient + MockTransport (no network).
Uses the shared tests/mocks/github.py scenarios.
"""

import pytest

from app.core.config import load_settings
from app.repository.errors import (
    BranchNotFoundError,
    CommitNotFoundError,
    RepositoryNotAccessibleError,
    RepositoryNotFoundError,
    UpstreamError,
)
from app.repository.github import GitHubClient, github_client_from_settings
from app.repository.identity import normalize_github_url
from app.services.http_client import RetryPolicy, ServiceClient
from tests.mocks.github import COMMIT_SHA, DEFAULT_BRANCH, OWNER, REPO, github_transport

pytestmark = pytest.mark.security

IDENTITY = normalize_github_url(f"https://github.com/{OWNER}/{REPO}")


def _gateway(scenario: str) -> GitHubClient:
    client = ServiceClient(
        name="github-test",
        base_url="https://api.github.com",
        retry_policy=RetryPolicy(max_retries=0, backoff_base_s=0),
        transport=github_transport(scenario),  # type: ignore[arg-type]
    )
    return GitHubClient(client)


def test_public_repository_validated_with_metadata() -> None:
    metadata = _gateway("public_repo").get_repository(IDENTITY)
    assert metadata.full_name == f"{OWNER}/{REPO}"
    assert metadata.private is False
    assert metadata.default_branch == DEFAULT_BRANCH


def test_not_found_distinguished() -> None:
    with pytest.raises(RepositoryNotFoundError) as exc_info:
        _gateway("not_found").get_repository(IDENTITY)
    assert exc_info.value.contract_code == "REPOSITORY_NOT_ACCESSIBLE"


def test_private_repository_distinguished() -> None:
    with pytest.raises(RepositoryNotAccessibleError):
        _gateway("private_repo").get_repository(IDENTITY)


def test_rate_limited_maps_to_upstream() -> None:
    with pytest.raises(UpstreamError):
        _gateway("rate_limited").get_repository(IDENTITY)


def test_server_error_and_timeout_map_to_upstream() -> None:
    with pytest.raises(UpstreamError):
        _gateway("server_error").get_repository(IDENTITY)
    with pytest.raises(UpstreamError):
        _gateway("timeout").get_repository(IDENTITY)


def test_malformed_response_fails_safely() -> None:
    with pytest.raises(UpstreamError):
        _gateway("malformed").get_repository(IDENTITY)


def test_branch_resolution_verifies_existence() -> None:
    info = _gateway("public_repo").resolve_branch(IDENTITY, "feature/login")
    assert info.name == "feature/login"
    assert info.head_sha == COMMIT_SHA


def test_missing_branch_never_substituted() -> None:
    with pytest.raises(BranchNotFoundError) as exc_info:
        _gateway("branch_missing").resolve_branch(IDENTITY, "nope")
    assert exc_info.value.contract_code == "INVALID_BRANCH"


def test_commit_resolution_returns_immutable_sha() -> None:
    info = _gateway("public_repo").resolve_commit(IDENTITY, COMMIT_SHA)
    assert info.sha == COMMIT_SHA
    short = _gateway("public_repo").resolve_commit(IDENTITY, COMMIT_SHA[:12])
    assert short.sha == COMMIT_SHA


def test_missing_or_invalid_commit_rejected() -> None:
    with pytest.raises(CommitNotFoundError) as exc_info:
        _gateway("commit_missing").resolve_commit(IDENTITY, COMMIT_SHA)
    assert exc_info.value.contract_code == "INVALID_COMMIT"
    with pytest.raises(CommitNotFoundError):
        _gateway("public_repo").resolve_commit(IDENTITY, "not-a-sha!!")


def test_gateway_built_from_centralized_settings() -> None:
    settings = load_settings()
    gateway = github_client_from_settings(settings, transport=github_transport("public_repo"))
    assert gateway.get_repository(IDENTITY).default_branch == DEFAULT_BRANCH
    assert gateway._client.timeout.connect == settings.network.connect_timeout_s
    assert gateway._client.retry_policy.max_retries == settings.network.retries_metadata


def test_no_credentials_accepted_or_logged() -> None:
    with pytest.raises(ValueError, match="Credential header"):
        ServiceClient(
            name="github-test",
            base_url="https://api.github.com",
            headers={"Authorization": "Bearer hunter2"},
        )
    try:
        _gateway("not_found").get_repository(IDENTITY)
    except RepositoryNotFoundError as exc:
        assert "hunter2" not in str(exc)
        assert exc.user_message
    else:
        raise AssertionError("expected RepositoryNotFoundError")
