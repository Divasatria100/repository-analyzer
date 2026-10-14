"""Test-only builders for Phase 10 code-structure tests (never production code)."""

from __future__ import annotations

from app.analyzers.base import AnalyzerResult
from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
from app.analyzers.context import AnalysisContext
from app.analyzers.security.source import DictSourceProvider
from app.ncm import NcmRepository
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.security_helpers import parse_files


def analyze_code(
    files: dict[str, str],
    analysis_id: str = "analysis-1",
    analyzer: CodeStructureAnalyzer | None = None,
) -> tuple[AnalyzerResult, AnalysisContext, CodeStructureAnalyzer]:
    """Parse sources, build context, and run the code-structure analyzer."""
    ncm: NcmRepository = parse_files(files)
    context = make_context(analysis_id=analysis_id, ncm=ncm)
    active = analyzer if analyzer is not None else CodeStructureAnalyzer(DictSourceProvider(files))
    result: AnalyzerResult = active.analyze(context)
    return result, context, active


def rule_result(result: AnalyzerResult, rule_id: str):  # type: ignore[no-untyped-def]
    """Fetch one rule's result by ID."""
    for item in result.rule_results:
        if item.rule_id == rule_id:
            return item
    raise AssertionError(f"missing rule result: {rule_id}")


def decision_body(count: int, kind: str = "if") -> str:
    """Function body with ``count`` sequential decision constructs."""
    lines: list[str] = []
    for index in range(count):
        if kind == "if":
            lines.append(f"    if x == {index}:")
            lines.append(f"        return {index}")
        elif kind == "for":
            lines.append(f"    for i{index} in range(3):")
            lines.append(f"        print(i{index})")
        elif kind == "while":
            lines.append(f"    while x > {index}:")
            lines.append("        x -= 1")
    lines.append("    return -1")
    return "\n".join(lines) + "\n"


def nested_body(depth: int) -> str:
    """Function body nested ``depth`` levels deep with ``if`` blocks."""
    lines: list[str] = []
    for level in range(depth):
        lines.append(f"{'    ' * (level + 1)}if x{level}:")
    lines.append(f"{'    ' * (depth + 1)}return 1")
    for level in reversed(range(depth)):
        lines.append(f"{'    ' * (level + 1)}return 0")
    return "\n".join(lines) + "\n"


def sig_function(params: str, body: str = "    return 1\n") -> str:
    """Function source with an explicit signature."""
    return f"def work({params}):\n{body}"
