"""URL normalization tests (TASK-038, FR-002, PIPE-REQ-009/010). Synthetic values only."""

import pytest

from app.repository.errors import InvalidRepositoryUrlError
from app.repository.identity import RepositoryIdentity, normalize_github_url


@pytest.mark.parametrize(
    "raw",
    [
        "https://github.com/acme/web",
        "https://github.com/acme/web/",
        "https://github.com/acme/web.git",
        "  https://github.com/acme/web  ",
        "https://github.com/Acme/Web.GIT",
    ],
)
def test_valid_forms_normalize_to_one_identity(raw: str) -> None:
    identity = normalize_github_url(raw)
    assert identity == RepositoryIdentity(owner="acme", name="web")
    assert identity.canonical_url == "https://github.com/acme/web"
    assert identity.clone_url == "https://github.com/acme/web.git"
    assert identity.full_name == "acme/web"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not a url",
        "https://gitlab.com/acme/web",
        "https://bitbucket.org/acme/web",
        "https://example.com/acme/web",
        "http://github.com/acme/web",
        "ssh://git@github.com/acme/web",
        "git@github.com:acme/web.git",
        "file:///tmp/repo",
        "/tmp/repo",
        "https://github.com/acme",
        "https://github.com/",
        "https://github.com",
        "github.com/acme/web",
        "https://github.com/acme/web/extra",
        "https://github.com/acme/web?tab=repositories",
        "https://github.com/acme/web#readme",
        "https://user:pass@github.com/acme/web",
        "https://github.com:8443/acme/web",
        "https://github.com//web",
        "https://github.com/acme//",
        "https://github.com/-acme/web",
        "https://github.com/acme/.",
        "https://GITHUB.com.evil.test/acme/web",
    ],
)
def test_invalid_forms_rejected(raw: str) -> None:
    with pytest.raises(InvalidRepositoryUrlError):
        normalize_github_url(raw)


def test_contract_code_is_invalid_url() -> None:
    try:
        normalize_github_url("https://gitlab.com/acme/web")
    except InvalidRepositoryUrlError as exc:
        assert exc.contract_code == "INVALID_URL"
    else:
        raise AssertionError("expected InvalidRepositoryUrlError")


def test_raw_url_with_credentials_never_echoed() -> None:
    try:
        normalize_github_url("https://hunter2:x@github.com/acme/web")
    except InvalidRepositoryUrlError as exc:
        assert "hunter2" not in str(exc)
    else:
        raise AssertionError("expected InvalidRepositoryUrlError")
