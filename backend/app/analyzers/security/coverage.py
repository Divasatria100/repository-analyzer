"""Security coverage tracking (TASK-095 support).

Coverage answers "how far did this rule get?" — never "is this code
secure?". Vocabulary (no Phase 6 equivalent exists, so this module is the
single source of truth):

* ``covered`` — applicable; the representation was sufficient.
* ``partially_covered`` — analysis ran but some required information was
  unavailable or unresolved (failed files, partial modules).
* ``unsupported`` — no supported-language content in scope; nothing ran.
* ``not_applicable`` — supported content exists but no applicable
  sink/source pattern was encountered.
* ``failed`` — the rule itself did not complete (recorded by the runner
  as a :class:`RuleFailure`; never surfaced as zero findings).

``unsupported`` and ``failed`` are deliberately distinct states, and none
of these states implies absence of vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.ncm import NcmRepository

#: The only language security rules support in V1.0 (docs/07 SEC-REQ-006).
SUPPORTED_LANGUAGE = "python"


class CoverageStatus(StrEnum):
    """Explicit per-rule coverage states (never collapsed, never "secure")."""

    COVERED = "covered"
    PARTIALLY_COVERED = "partially_covered"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"
    FAILED = "failed"


@dataclass(frozen=True)
class ScopeSummary:
    """What one rule run could see (derived from NCM, deterministic)."""

    python_modules: tuple[str, ...]
    partial_modules: tuple[str, ...]
    failed_python_files: tuple[str, ...]
    unsupported_files: tuple[str, ...]

    @property
    def has_supported_content(self) -> bool:
        """Any Python module was available for analysis."""
        return bool(self.python_modules)

    @property
    def is_degraded(self) -> bool:
        """Representation gaps force reduced confidence/coverage."""
        return bool(self.partial_modules or self.failed_python_files)


@dataclass(frozen=True)
class Coverage:
    """One rule's coverage outcome for an analysis (explicit, serializable)."""

    rule_id: str
    status: CoverageStatus
    reason: str

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization."""
        return {
            "rule_id": self.rule_id,
            "status": self.status.value,
            "reason": self.reason,
        }


def summarize_scope(ncm: NcmRepository) -> ScopeSummary:
    """Derive the analysis scope from NCM file entries (sorted, stable)."""
    python_modules: list[str] = []
    partial_modules: list[str] = []
    failed_python_files: list[str] = []
    unsupported_files: list[str] = []
    for entry in sorted(ncm.files, key=lambda item: item.path):
        language = (entry.language or "").lower()
        state = entry.parse_state
        if entry.module is not None and language == SUPPORTED_LANGUAGE:
            python_modules.append(entry.path)
            if entry.module.completeness != "fully":
                partial_modules.append(entry.path)
        elif state == "failed" and (language == SUPPORTED_LANGUAGE or language in ("", "python")):
            failed_python_files.append(entry.path)
        elif state in ("unsupported",):
            unsupported_files.append(entry.path)
        elif entry.module is None and language != SUPPORTED_LANGUAGE:
            unsupported_files.append(entry.path)
    return ScopeSummary(
        python_modules=tuple(python_modules),
        partial_modules=tuple(partial_modules),
        failed_python_files=tuple(failed_python_files),
        unsupported_files=tuple(unsupported_files),
    )


def coverage_for(rule_id: str, scope: ScopeSummary, sinks_found: bool) -> Coverage:
    """Decide one rule's coverage from scope plus whether sinks were seen."""
    if not scope.has_supported_content:
        return Coverage(
            rule_id=rule_id,
            status=CoverageStatus.UNSUPPORTED,
            reason="No supported-language (python) content in scope; the rule did not run.",
        )
    if not sinks_found:
        return Coverage(
            rule_id=rule_id,
            status=CoverageStatus.NOT_APPLICABLE,
            reason=(
                "Supported content was analyzed but no applicable sink pattern "
                "was encountered; this does not mean the code is free of issues."
            ),
        )
    if scope.is_degraded:
        return Coverage(
            rule_id=rule_id,
            status=CoverageStatus.PARTIALLY_COVERED,
            reason=(
                "Sinks were analyzed but some files were only partially "
                "represented or failed to parse; confidence is reduced."
            ),
        )
    return Coverage(
        rule_id=rule_id,
        status=CoverageStatus.COVERED,
        reason="Applicable sinks were analyzed with a sufficient representation.",
    )
