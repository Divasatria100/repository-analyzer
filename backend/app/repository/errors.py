"""Repository-ingestion domain errors (docs/05 FR-005/006/098/099, docs/17 §3.4).

Each error carries the frozen API contract code it will surface as, plus a
user-safe message (no internals, credentials, paths, or raw upstream bodies).
Internal distinctions (not-found vs private vs rate-limited vs malformed) are
preserved as distinct types so later layers can map them correctly — nothing
is collapsed into a single "invalid repository" error.
"""

from __future__ import annotations


class IngestionError(Exception):
    """Base error for repository ingestion. Message must stay user-safe."""

    contract_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.user_message = message


class InvalidRepositoryUrlError(IngestionError):
    """Submitted value is not a well-formed public GitHub repository URL."""

    contract_code = "INVALID_URL"

    def __init__(
        self,
        message: str = "The submitted value is not a valid public GitHub repository URL.",
    ) -> None:
        super().__init__(message)


class RepositoryNotFoundError(IngestionError):
    """Valid URL form, but GitHub reports no such repository (FR-006)."""

    contract_code = "REPOSITORY_NOT_ACCESSIBLE"

    def __init__(
        self,
        message: str = "The repository was not found. It may have been deleted or renamed.",
    ) -> None:
        super().__init__(message)


class RepositoryNotAccessibleError(IngestionError):
    """Valid URL form, but the repository is private/inaccessible (FR-006)."""

    contract_code = "REPOSITORY_NOT_ACCESSIBLE"

    def __init__(
        self,
        message: str = "The repository is not accessible as a public repository.",
    ) -> None:
        super().__init__(message)


class BranchNotFoundError(IngestionError):
    """Requested branch could not be resolved; never silently substituted."""

    contract_code = "INVALID_BRANCH"

    def __init__(self, message: str = "The requested branch could not be resolved.") -> None:
        super().__init__(message)


class CommitNotFoundError(IngestionError):
    """Requested commit could not be resolved to an immutable SHA."""

    contract_code = "INVALID_COMMIT"

    def __init__(self, message: str = "The requested commit could not be resolved.") -> None:
        super().__init__(message)


class UpstreamError(IngestionError):
    """GitHub did not answer usefully: rate limit, timeout, 5xx, malformed body."""

    contract_code = "REPOSITORY_NOT_ACCESSIBLE"

    def __init__(
        self,
        message: str = "GitHub could not be reached right now. Please try again later.",
    ) -> None:
        super().__init__(message)


class RetrievalError(IngestionError):
    """Repository content could not be retrieved at the resolved commit.

    Surfaced through the analysis outcome (Failed + explanation), never as a
    clean or complete result. ``retryable`` distinguishes transient transport
    failures (retried per net.retries_retrieval) from deterministic ones.
    """

    contract_code = "ANALYSIS_FAILED"
    retryable: bool = False

    def __init__(self, message: str) -> None:
        super().__init__(message)


class RetrievalTimeoutError(RetrievalError):
    """Retrieval exceeded the configured total duration."""

    retryable = True

    def __init__(
        self,
        message: str = "Retrieving the repository took too long and was stopped.",
    ) -> None:
        super().__init__(message)


class RetrievalTransportError(RetrievalError):
    """Retrieval failed at the transport/process layer (transient)."""

    retryable = True

    def __init__(
        self,
        message: str = "The repository could not be downloaded due to a connection problem.",
    ) -> None:
        super().__init__(message)


class RetrievalSizeLimitError(RetrievalError):
    """Repository exceeds a configured size/count/depth limit."""

    def __init__(
        self,
        message: str = "The repository exceeds a configured size limit and was not analyzed.",
    ) -> None:
        super().__init__(message)


class RetrievalSecurityError(RetrievalError):
    """Retrieval blocked by a repository-safety boundary (never bypassed)."""

    def __init__(
        self,
        message: str = "The repository could not be retrieved safely and was not analyzed.",
    ) -> None:
        super().__init__(message)


class RetrievalIncompleteError(RetrievalError):
    """Retrieval produced partial content; never analyzed as complete."""

    def __init__(
        self,
        message: str = "The repository download was incomplete and was not analyzed.",
    ) -> None:
        super().__init__(message)


class WorkspaceError(IngestionError):
    """Workspace infrastructure failure (creation, containment, cleanup)."""

    def __init__(
        self,
        message: str = "The analysis workspace could not be prepared.",
    ) -> None:
        super().__init__(message)


class ConcurrencyExhaustedError(IngestionError):
    """All analysis slots are in use (docs/17 RATE_LIMITED, NFR-045)."""

    contract_code = "RATE_LIMITED"

    def __init__(
        self,
        message: str = "Too many analyses are running. Please try again later.",
    ) -> None:
        super().__init__(message)
