"""Ecosystem detection and support states (TASK-113).

V1.0 ecosystems are authoritative per docs/09 §11.2: PyPI ``Supported``,
npm ``Partially supported``, everything else ``Unsupported``. Unsupported
is never confused with failed: a file that should have parsed but did not
is failed; a format outside the boundary is unsupported.
"""

from __future__ import annotations

from app.analyzers.dependency.models import (
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    SUPPORTED_ECOSYSTEMS,
    SupportState,
)

#: Human-facing support label per ecosystem (docs/09 §11.2).
ECOSYSTEM_SUPPORT: dict[str, str] = {
    ECOSYSTEM_PYPI: "Supported",
    ECOSYSTEM_NPM: "Partially supported",
}


def ecosystem_support(ecosystem: str) -> str:
    """Support label for an ecosystem (unknown ecosystems are unsupported)."""
    return ECOSYSTEM_SUPPORT.get(ecosystem, "Unsupported")


def is_supported_ecosystem(ecosystem: str) -> bool:
    """True for the two V1.0 ecosystems (npm partial support counts)."""
    return ecosystem in SUPPORTED_ECOSYSTEMS


def state_for_parse_outcome(
    *,
    ecosystem: str,
    parsed: bool,
    partial: bool = False,
) -> SupportState:
    """Map a parse outcome to an explicit support state (never ambiguous)."""
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        return SupportState.UNSUPPORTED
    if not parsed:
        return SupportState.FAILED
    if partial:
        return SupportState.PARTIAL
    return SupportState.SUPPORTED
