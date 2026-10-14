"""Code-structure rule metadata (Phase 10).

Extends the Phase 6 :class:`RuleMetadata`, mirroring the sibling analyzers.
The four rules are the complete V1.0 set (docs/10 §5.14A CODE-REQ-006);
severity/confidence assignments below are exactly CODE-REQ-001–004.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.rules import RuleMetadata

#: Analyzer identity shared by all code-structure rules (Phase 6 convention).
CODE_ANALYZER_ID = "code_structure"

CODE_ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class CodeRuleSpec:
    """Full static declaration for one code-structure rule."""

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
            analyzer_id=CODE_ANALYZER_ID,
            version=version,
            default_severity=self.default_severity,
            documentation_ref=self.documentation_ref,
        )


HIGH_COMPLEXITY_SPEC = CodeRuleSpec(
    rule_id="CODE-HIGH-COMPLEXITY",
    name="High Complexity",
    description=(
        "Identifies functions or methods whose McCabe complexity strictly exceeds "
        "the threshold. A structural observation for maintenance and testing "
        "review; never a claim that the function has a bug or is incorrect."
    ),
    default_severity="Medium",
    default_confidence="High",
    recommendation=(
        "Review the flagged function and consider whether its decision logic can "
        "be simplified or covered more thoroughly by tests."
    ),
)

DEEP_NESTING_SPEC = CodeRuleSpec(
    rule_id="CODE-DEEP-NESTING",
    name="Deep Nesting",
    description=(
        "Identifies functions or methods whose maximum block-nesting depth "
        "strictly exceeds the threshold. Long functions are not reported unless "
        "they are actually nested."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the deeply nested region and consider whether extracting a "
        "helper would make the structure easier to follow."
    ),
)

HIGH_PARAMETER_COUNT_SPEC = CodeRuleSpec(
    rule_id="CODE-HIGH-PARAMETER-COUNT",
    name="High Parameter Count",
    description=(
        "Identifies functions or methods declaring more parameters than the "
        "threshold allows. Many parameters are a maintenance signal, not proof "
        "of a design mistake."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the signature and consider whether grouping related parameters "
        "would help callers; do not treat any single refactor as mandatory."
    ),
)

DUPLICATE_CANDIDATE_SPEC = CodeRuleSpec(
    rule_id="CODE-DUPLICATE-CANDIDATE",
    name="Duplicate Candidate",
    description=(
        "Identifies groups of function or method bodies sharing a long identical "
        "normalized token sequence. A candidate for manual review: structural "
        "similarity may be coincidental or intentional and is not evidence of "
        "shared semantics."
    ),
    default_severity="Info",
    default_confidence="Medium",
    recommendation=(
        "Review the listed locations side by side and decide whether the "
        "similarity is incidental, intentional, or worth consolidating."
    ),
)


CODE_RULE_SPECS: tuple[CodeRuleSpec, ...] = (
    HIGH_COMPLEXITY_SPEC,
    DEEP_NESTING_SPEC,
    HIGH_PARAMETER_COUNT_SPEC,
    DUPLICATE_CANDIDATE_SPEC,
)

SPEC_BY_RULE_ID: dict[str, CodeRuleSpec] = {spec.rule_id: spec for spec in CODE_RULE_SPECS}
