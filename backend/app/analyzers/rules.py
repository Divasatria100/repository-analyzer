"""Shared rule abstraction and registry (TASK-084).

Rules declare stable metadata; the registry enforces uniqueness and
deterministic ordering. No rule executes here — execution with failure
isolation lives in :mod:`app.analyzers.runner`.

The frozen rule ID sets (12 SEC + 4 DEP + 9 ARCH + 4 CODE) are not
implemented in this phase; the registry only supports their future
registration. There is deliberately no enabled/disabled state
(docs/12 §4.5: all domains run per PIPE-REQ-004).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.analyzers.context import AnalysisContext
    from app.analyzers.findings import Finding, Limitation

_RULE_ID_PATTERN = re.compile(r"^(SEC|DEP|ARCH|CODE)-[A-Z0-9-]+$")

#: Rule prefix to finding category (docs/13 §8.1: category must match prefix).
CATEGORY_BY_PREFIX = {
    "SEC": "security",
    "DEP": "dependency",
    "ARCH": "architecture",
    "CODE": "code_structure",
}


def category_for_rule(rule_id: str) -> str:
    """Derive the finding category from a rule ID prefix."""
    prefix = rule_id.split("-", 1)[0]
    try:
        return CATEGORY_BY_PREFIX[prefix]
    except KeyError:
        raise ValueError(f"Unknown rule prefix: {rule_id!r}") from None


@dataclass(frozen=True)
class RuleMetadata:
    """Stable, serializable rule declaration (no execution logic)."""

    rule_id: str
    name: str
    description: str
    analyzer_id: str
    version: str
    default_severity: str
    documentation_ref: str = ""

    def __post_init__(self) -> None:
        """Fail fast on malformed metadata (never silently accepted)."""
        if not _RULE_ID_PATTERN.fullmatch(self.rule_id):
            raise ValueError(f"Invalid rule ID: {self.rule_id!r}")
        category_for_rule(self.rule_id)  # validates prefix mapping
        if not self.name.strip():
            raise ValueError(f"Rule {self.rule_id!r} requires a name.")
        if not self.analyzer_id.strip():
            raise ValueError(f"Rule {self.rule_id!r} requires an analyzer ID.")
        if not self.version.strip():
            raise ValueError(f"Rule {self.rule_id!r} requires a version.")

    @property
    def category(self) -> str:
        """Finding category derived from the rule prefix."""
        return category_for_rule(self.rule_id)

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "analyzer_id": self.analyzer_id,
            "version": self.version,
            "default_severity": self.default_severity,
            "documentation_ref": self.documentation_ref,
        }


@dataclass
class RuleOutcome:
    """What one rule execution produced (collected by the runner)."""

    findings: list[Finding] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)


#: A rule implementation: metadata plus a pure NCM inspection function.
#: The callable receives its execution context and returns its outcome;
#: raising is allowed — the runner converts it to an explicit failure.
RuleExecutor = Callable[["RuleExecutionContext"], "RuleOutcome"]


@dataclass(frozen=True)
class RuleExecutionContext:
    """The narrow input one rule execution receives (NCM scope + shared context)."""

    context: AnalysisContext
    rule: RuleMetadata


@dataclass(frozen=True)
class RegisteredRule:
    """Metadata bound to its executor (registered, never fabricated)."""

    metadata: RuleMetadata
    execute: RuleExecutor


class RuleRegistry:
    """Deterministic rule store: duplicates rejected, lookup by ID."""

    def __init__(self) -> None:
        self._rules: dict[str, RegisteredRule] = {}

    def register(self, metadata: RuleMetadata, execute: RuleExecutor) -> RegisteredRule:
        """Register a rule; duplicate IDs raise instead of overwriting."""
        if metadata.rule_id in self._rules:
            raise ValueError(f"Duplicate rule ID: {metadata.rule_id!r}")
        registered = RegisteredRule(metadata=metadata, execute=execute)
        self._rules[metadata.rule_id] = registered
        return registered

    def get(self, rule_id: str) -> RegisteredRule | None:
        """Return the rule, or None when unknown (never fabricated)."""
        return self._rules.get(rule_id)

    def require(self, rule_id: str) -> RegisteredRule:
        """Return the rule or raise KeyError for unknown IDs."""
        try:
            return self._rules[rule_id]
        except KeyError:
            raise KeyError(f"Unknown rule ID: {rule_id!r}") from None

    def ordered(self) -> list[RegisteredRule]:
        """Rules in deterministic rule-ID order (never registration order)."""
        return [self._rules[key] for key in sorted(self._rules)]

    def rule_ids(self) -> list[str]:
        """Sorted rule IDs (deterministic introspection)."""
        return sorted(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[RegisteredRule]:
        return iter(self.ordered())

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization (sorted by rule ID)."""
        return {"rules": [r.metadata.to_dict() for r in self.ordered()]}
