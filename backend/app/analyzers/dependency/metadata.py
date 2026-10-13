"""Dependency rule metadata (Phase 8).

Extends the Phase 6 :class:`RuleMetadata` with the dependency-specific
declaration, mirroring ``app.analyzers.security.metadata``. The four rules
are the complete V1.0 set (docs/10 §5.11A DEP-REQ-006); severities and
confidences below are the only valid V1.0 assignments (DEP-REQ-005).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.rules import RuleMetadata

#: Analyzer identity shared by all dependency rules (Phase 6 convention).
DEPENDENCY_ANALYZER_ID = "dependency"

DEPENDENCY_ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class DependencyRuleSpec:
    """Full static declaration for one dependency rule."""

    rule_id: str
    name: str
    description: str
    default_severity: str
    default_confidence: str
    recommendation: str
    documentation_ref: str = "docs/10-analysis-pipeline.md"

    def to_metadata(self, version: str) -> RuleMetadata:
        """Project onto the Phase 6 registration schema (reused, unmodified)."""
        return RuleMetadata(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            analyzer_id=DEPENDENCY_ANALYZER_ID,
            version=version,
            default_severity=self.default_severity,
            documentation_ref=self.documentation_ref,
        )


KNOWN_VULNERABILITY_SPEC = DependencyRuleSpec(
    rule_id="DEP-KNOWN-VULNERABILITY",
    name="Known Dependency Vulnerability",
    description=(
        "Matches a dependency occurrence with an exact resolved version "
        "against OSV advisory information for the (ecosystem, name, version) "
        "triple. A finding is produced only on an exact-version advisory "
        "match and is presented as advisory information for review, never as "
        "a confirmed exploitable issue in the repository."
    ),
    default_severity="High",
    default_confidence="High",
    recommendation=(
        "Review the referenced advisory information for the affected version. "
        "Where the advisory applies, upgrade the dependency to a fixed "
        "version or apply the vendor-recommended mitigation."
    ),
)

DUPLICATE_VERSION_SPEC = DependencyRuleSpec(
    rule_id="DEP-DUPLICATE-VERSION",
    name="Duplicate Dependency Version",
    description=(
        "Reports when the same package name (same ecosystem, normalized "
        "identity) occurs with two or more distinct exact versions in one "
        "analysis. Occurrences with unknown versions are excluded from the "
        "comparison and recorded as limitations."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review why multiple resolved versions of the same package are "
        "present. Where possible, align the declarations or lockfiles so "
        "that one resolved version is used."
    ),
)

HIGH_DEPENDENCY_COUNT_SPEC = DependencyRuleSpec(
    rule_id="DEP-HIGH-DEPENDENCY-COUNT",
    name="High Dependency Count",
    description=(
        "Reports when the total dependency occurrences within one "
        "package-manager scope (PyPI and npm counted separately) strictly "
        "exceed the configured threshold (default 200 occurrences per "
        "scope). This is a complexity indicator, not a vulnerability."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the dependency inventory for the scope that exceeds the "
        "threshold. Consider whether each dependency is still needed and "
        "whether the scope can be simplified."
    ),
)

UNUSED_CANDIDATE_SPEC = DependencyRuleSpec(
    rule_id="DEP-UNUSED-CANDIDATE",
    name="Possibly Unused Dependency",
    description=(
        "Reports a direct dependency for which no statically observable "
        "usage was found in analyzed source as a candidate for manual "
        "review. This is a heuristic candidate, never a determination that "
        "the dependency is unused."
    ),
    default_severity="Info",
    default_confidence="Low",
    recommendation=(
        "Manually review whether the reported dependency is still required, "
        "including framework-convention, configuration-driven, plugin, "
        "generated-code, dynamic-import, and runtime-loading usage that "
        "static analysis cannot see, before removing anything."
    ),
)


DEPENDENCY_RULE_SPECS: tuple[DependencyRuleSpec, ...] = (
    KNOWN_VULNERABILITY_SPEC,
    DUPLICATE_VERSION_SPEC,
    HIGH_DEPENDENCY_COUNT_SPEC,
    UNUSED_CANDIDATE_SPEC,
)

SPEC_BY_RULE_ID: dict[str, DependencyRuleSpec] = {
    spec.rule_id: spec for spec in DEPENDENCY_RULE_SPECS
}
