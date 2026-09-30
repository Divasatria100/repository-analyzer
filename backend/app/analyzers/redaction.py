"""Centralized secret masking for analyzer evidence (TASK-092).

Thin, deterministic policy layer over the existing redaction utilities
(``app.core.logging``): the detection machinery lives in one place, and
this module defines how evidence uses it. This is redaction
infrastructure — not the ``SEC-HARDCODED-SECRET`` rule.
"""

from __future__ import annotations

from app.core.logging import REDACTED, redact_text


def mask_secrets(text: str) -> tuple[str, bool]:
    """Mask secret-like values, reporting whether anything changed.

    Returns ``(masked_text, had_secrets)`` so callers can set redaction
    flags without re-scanning. Normal non-sensitive context passes through
    byte-identical, preserving usefulness.
    """
    masked = redact_text(text)
    return masked, masked != text


def redaction_marker() -> str:
    """The single placeholder substituted for sensitive values."""
    return REDACTED
