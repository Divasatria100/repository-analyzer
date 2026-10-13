"""Architecture rule metadata (Phase 9).

Extends the Phase 6 :class:`RuleMetadata` with the architecture-specific
declaration, mirroring security/dependency metadata. The nine rules are the
complete V1.0 set (docs/08 §6, ARCH-REQ-036); severity assignments below
follow the §11.1 baseline mapping (Low default; Medium when aggravated)
and the §16 severity ranges. Confidence defaults follow each rule's
considerations; rules adjust them per evidence at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.rules import RuleMetadata

#: Analyzer identity shared by all architecture rules (Phase 6 convention).
ARCHITECTURE_ANALYZER_ID = "architecture"

ARCHITECTURE_ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class ArchitectureRuleSpec:
    """Full static declaration for one architecture rule."""

    rule_id: str
    name: str
    description: str
    default_severity: str
    default_confidence: str
    recommendation: str
    documentation_ref: str = "docs/08-architecture-analysis-requirements.md"

    def to_metadata(self, version: str) -> RuleMetadata:
        """Project onto the Phase 6 registration schema (reused, unmodified)."""
        return RuleMetadata(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            analyzer_id=ARCHITECTURE_ANALYZER_ID,
            version=version,
            default_severity=self.default_severity,
            documentation_ref=self.documentation_ref,
        )


CIRCULAR_DEPENDENCY_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-CIRCULAR-DEPENDENCY",
    name="Circular Dependency",
    description=(
        "Identifies groups of source units whose module dependencies form a "
        "closed path. A circular dependency may indicate structural coupling "
        "or architectural complexity requiring review; it is a structural "
        "observation and does not assert a defect."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the participating modules and the relationships that close the "
        "cycle. Consider whether the relationships are needed and which "
        "relationship, if any, is the most appropriate point to examine."
    ),
)

HIGH_FAN_OUT_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-HIGH-FAN-OUT",
    name="High Fan-Out",
    description=(
        "Identifies modules that depend on an unusually large number of other "
        "modules. The observation is directional: outgoing breadth only."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the outgoing dependencies and consider whether the module's role "
        "explains them, whether some relationships are incidental, and whether "
        "the module combines concerns that could be separated."
    ),
)

HIGH_FAN_IN_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-HIGH-FAN-IN",
    name="High Fan-In",
    description=(
        "Identifies modules that a large number of other modules depend on. "
        "High fan-in is not classified as a defect; shared modules are expected "
        "to be depended on widely."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the dependents and consider whether the module is an intended "
        "shared component with a clear and stable purpose."
    ),
)

HIGH_COUPLING_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-HIGH-COUPLING",
    name="High Coupling",
    description=(
        "Identifies modules whose two-sided structural ties (coupling-def-1, "
        "the union of incoming and outgoing neighbor sets) exceed the "
        "threshold. High coupling does not imply a defect."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the contributing relationships and the graph context. Consider "
        "whether the closeness of the relationships is intended."
    ),
)

LARGE_MODULE_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-LARGE-MODULE",
    name="Large Module",
    description=(
        "Identifies source units that exceed a module size signal. Size may "
        "make understanding and maintenance more difficult; it is not evidence "
        "of poor architecture."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the module's contents and consider whether the declarations it "
        "holds belong together."
    ),
)

LARGE_CLASS_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-LARGE-CLASS",
    name="Large Class",
    description=(
        "Identifies classes that exceed a class size signal. A large class is "
        "not claimed to violate a design principle."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the class's members and consider whether its methods and "
        "attributes form a coherent unit."
    ),
)

LARGE_FUNCTION_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-LARGE-FUNCTION",
    name="Large Function",
    description=(
        "Identifies functions or methods that exceed a function size signal, "
        "with an architectural interpretation: a concentrated unit of behavior "
        "within the module and repository structure."
    ),
    default_severity="Low",
    default_confidence="High",
    recommendation=(
        "Review the function and consider whether its parts represent distinguishable steps."
    ),
)

LAYER_VIOLATION_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-LAYER-VIOLATION",
    name="Layer Violation",
    description=(
        "Identifies a module dependency that runs counter to an identified "
        "layering direction. Layers are inferred observations for the user to "
        "interpret, not a pass or fail judgment."
    ),
    default_severity="Low",
    default_confidence="Medium",
    recommendation=(
        "Confirm whether the identified layering reflects the repository's "
        "intended structure. If it does, review whether the relationship is a "
        "deliberate exception or a boundary crossing that deserves attention."
    ),
)

MULTIPLE_RESPONSIBILITY_SPEC = ArchitectureRuleSpec(
    rule_id="ARCH-MULTIPLE-RESPONSIBILITY",
    name="Potential Multiple Responsibility",
    description=(
        "Identifies modules where structural signals from more than one "
        "category suggest combined responsibilities. A potential structure "
        "requiring contextual review, never proof of a design violation."
    ),
    default_severity="Low",
    default_confidence="Low",
    recommendation=(
        "Review the unit's contents alongside the contributing signals, and "
        "consider whether they fall into separable concerns."
    ),
)


ARCHITECTURE_RULE_SPECS: tuple[ArchitectureRuleSpec, ...] = (
    CIRCULAR_DEPENDENCY_SPEC,
    HIGH_FAN_OUT_SPEC,
    HIGH_FAN_IN_SPEC,
    HIGH_COUPLING_SPEC,
    LARGE_MODULE_SPEC,
    LARGE_CLASS_SPEC,
    LARGE_FUNCTION_SPEC,
    LAYER_VIOLATION_SPEC,
    MULTIPLE_RESPONSIBILITY_SPEC,
)

SPEC_BY_RULE_ID: dict[str, ArchitectureRuleSpec] = {
    spec.rule_id: spec for spec in ARCHITECTURE_RULE_SPECS
}
