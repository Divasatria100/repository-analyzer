"""Shared analyzer contract (TASK-082).

Parser-independent lifecycle every analysis domain implements. The base
``analyze()`` drives the analyzer's registered rules through isolated
per-rule execution, so a rule failure can never take down siblings and a
failed rule contributes findings to nothing while staying observable.
Analyzers receive an :class:`AnalysisContext` built from NCM and return
structured results — never raw repository content, never parser objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, final

if TYPE_CHECKING:
    from app.analyzers.context import AnalysisContext
    from app.analyzers.findings import Finding, Limitation
    from app.analyzers.rules import RegisteredRule


@dataclass(frozen=True)
class RuleFailure:
    """A rule that did not complete: recorded, never clean, never silent."""

    rule_id: str
    analyzer_id: str
    analysis_id: str
    category: str = "analyzer failure"
    message: str = "The rule did not complete."
    analyzer_version: str = ""
    rule_set_version: str = ""


@dataclass(frozen=True)
class RuleResult:
    """One rule's outcome: findings preserved alongside any failure."""

    rule_id: str
    findings: tuple[Finding, ...] = ()
    failure: RuleFailure | None = None
    limitations: tuple[Limitation, ...] = ()


@dataclass(frozen=True)
class AnalyzerFailure:
    """A whole analyzer that did not complete (sibling analyzers unaffected)."""

    analyzer_id: str
    analysis_id: str
    category: str = "analyzer failure"
    message: str = "The analyzer did not complete."
    analyzer_version: str = ""
    rule_set_version: str = ""


@dataclass(frozen=True)
class AnalyzerResult:
    """One analyzer's outcome: findings plus explicit failure state."""

    analyzer_id: str
    analysis_id: str
    analyzer_version: str
    rule_set_version: str
    rule_results: tuple[RuleResult, ...] = ()
    failure: AnalyzerFailure | None = None
    limitations: tuple[Limitation, ...] = field(default_factory=tuple)

    @property
    def failed(self) -> bool:
        """An analyzer with a failure record is never a clean result."""
        return self.failure is not None

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Findings from rules that completed (failures contribute none)."""
        collected: list[Finding] = []
        for result in self.rule_results:
            collected.extend(result.findings)
        return tuple(collected)


class Analyzer(ABC):
    """Parser-independent analyzer contract (NCM in, results out)."""

    id: str = ""
    name: str = ""
    version: str = ""

    @abstractmethod
    def rules(self) -> list[RegisteredRule]:
        """Rules this analyzer runs (registered metadata + executors)."""
        raise NotImplementedError

    @final
    def analyze(self, context: AnalysisContext) -> AnalyzerResult:
        """Run every rule with per-rule isolation (final; not overridden)."""
        from app.analyzers.runner import run_rule

        rule_results = tuple(run_rule(self, rule, context) for rule in self.rules())
        return AnalyzerResult(
            analyzer_id=self.id,
            analysis_id=context.analysis_id,
            analyzer_version=self.version,
            rule_set_version=context.rule_set_version,
            rule_results=rule_results,
        )
