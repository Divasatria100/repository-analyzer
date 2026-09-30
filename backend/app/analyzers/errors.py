"""Analyzer-foundation error types (TASK-093 support).

User-safe by construction: messages never carry source content, secrets,
credentials, or workspace paths. Detailed causes stay in structured logs
via ``log_exception`` (already redacting); only categories travel outward.
"""

from __future__ import annotations


class AnalyzerError(Exception):
    """Base error for analyzer-foundation failures (message stays user-safe)."""

    def __init__(self, message: str = "The analysis could not be completed.") -> None:
        super().__init__(message)
        self.user_message = message


class RuleFailedError(AnalyzerError):
    """A single rule did not complete (siblings still run)."""

    def __init__(self, rule_id: str) -> None:
        super().__init__("A rule did not complete; its results are unavailable.")
        self.rule_id = rule_id


class EvidenceUnavailableError(AnalyzerError):
    """Evidence could not be obtained safely (record a limitation instead)."""

    def __init__(self, message: str = "Evidence could not be obtained safely.") -> None:
        super().__init__(message)
