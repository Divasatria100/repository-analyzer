"""GitHub repository identity: URL normalization + ref validation (TASK-038/044).

Only ``https://github.com/OWNER/REPOSITORY`` forms are accepted (optional
trailing slash or ``.git`` suffix, surrounding whitespace trimmed). Every
other domain, scheme, userinfo credential, port, query, fragment, or path
shape is rejected — normalization never invents an identity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.repository.errors import (
    BranchNotFoundError,
    CommitNotFoundError,
    InvalidRepositoryUrlError,
)

_GITHUB_HOST = "github.com"

_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPO_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_SHA_PATTERN = re.compile(r"[0-9a-fA-F]{7,64}")

# Characters/sequences never allowed in a branch name for resolution.
_BRANCH_FORBIDDEN = ("..", "@{", "~", "^", ":", "?", "*", "[", "\\")


@dataclass(frozen=True)
class RepositoryIdentity:
    """Canonical identity of a public GitHub repository (lowercased)."""

    owner: str
    name: str

    @property
    def canonical_url(self) -> str:
        """Normalized URL: equivalent submitted forms resolve here (PIPE-REQ-009)."""
        return f"https://{_GITHUB_HOST}/{self.owner}/{self.name}"

    @property
    def clone_url(self) -> str:
        """Remote URL retrieval derives from — never a user-supplied remote."""
        return f"{self.canonical_url}.git"

    @property
    def full_name(self) -> str:
        """owner/name form used by the GitHub API."""
        return f"{self.owner}/{self.name}"


def normalize_github_url(raw_url: str) -> RepositoryIdentity:
    """Normalize a submitted repository URL or raise InvalidRepositoryUrlError.

    Accepts only https://github.com/OWNER/REPOSITORY with an optional
    trailing slash or .git suffix. Owner/name are lowercased so equivalent
    forms share one identity (GitHub treats them case-insensitively).
    """
    text = (raw_url or "").strip()
    if not text:
        raise InvalidRepositoryUrlError()
    try:
        parsed = urlsplit(text)
    except ValueError:
        raise InvalidRepositoryUrlError() from None
    if parsed.scheme.lower() != "https":
        raise InvalidRepositoryUrlError()
    if (
        (parsed.hostname or "").lower() != _GITHUB_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
    ):
        raise InvalidRepositoryUrlError()
    if parsed.query or parsed.fragment:
        raise InvalidRepositoryUrlError()
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) != 2:
        raise InvalidRepositoryUrlError()
    owner, name = segments
    if name.lower().endswith(".git"):
        name = name[: -len(".git")]
    if not _OWNER_PATTERN.fullmatch(owner) or not _REPO_PATTERN.fullmatch(name):
        raise InvalidRepositoryUrlError()
    if name in {".", ".."}:
        raise InvalidRepositoryUrlError()
    return RepositoryIdentity(owner=owner.lower(), name=name.lower())


def validate_branch_name(branch: str) -> str:
    """Syntax-check a requested branch name (existence is verified via API)."""
    if not branch or len(branch) > 255:
        raise BranchNotFoundError()
    if (
        any(char.isspace() or ord(char) < 32 for char in branch)
        or branch.startswith(("/", ".", "-"))
        or branch.endswith(("/", ".", ".lock"))
        or any(forbidden in branch for forbidden in _BRANCH_FORBIDDEN)
    ):
        raise BranchNotFoundError()
    return branch


def validate_commit_sha(value: str) -> str:
    """Accept a full (40/64 hex) or unambiguous short (7+ hex) SHA; else reject."""
    text = (value or "").strip()
    if not _SHA_PATTERN.fullmatch(text):
        raise CommitNotFoundError()
    return text.lower()
