"""Test-only builders for Phase 9 architecture tests (never production code)."""

from __future__ import annotations

from app.analyzers.architecture.analyzer import ArchitectureAnalyzer
from app.analyzers.architecture.graph import ExtractionReport, build_graph
from app.analyzers.base import AnalyzerResult
from app.analyzers.context import AnalysisContext
from app.analyzers.security.source import DictSourceProvider
from app.ncm import NcmRepository
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.security_helpers import parse_files


def analyze_arch(
    files: dict[str, str],
    analysis_id: str = "analysis-1",
    analyzer: ArchitectureAnalyzer | None = None,
) -> tuple[AnalyzerResult, AnalysisContext, ArchitectureAnalyzer]:
    """Parse sources, build context, and run the architecture analyzer."""
    ncm: NcmRepository = parse_files(files)
    context = make_context(analysis_id=analysis_id, ncm=ncm)
    active = analyzer if analyzer is not None else ArchitectureAnalyzer(DictSourceProvider(files))
    result: AnalyzerResult = active.analyze(context)
    return result, context, active


def analyze_ncm(
    files: dict[str, str],
    analysis_id: str = "analysis-1",
    sources: dict[str, str] | None = None,
) -> tuple[AnalyzerResult, AnalysisContext, ArchitectureAnalyzer]:
    """Analyze with NCM from ``files`` but source lines from ``sources``."""
    ncm: NcmRepository = parse_files(files)
    context = make_context(analysis_id=analysis_id, ncm=ncm)
    active = ArchitectureAnalyzer(DictSourceProvider(sources if sources is not None else files))
    result: AnalyzerResult = active.analyze(context)
    return result, context, active


def graph_for(files: dict[str, str]) -> ExtractionReport:
    """Build the extraction report for in-memory sources."""
    return build_graph(parse_files(files))


def rule_result(result: AnalyzerResult, rule_id: str):  # type: ignore[no-untyped-def]
    """Fetch one rule's result by ID."""
    for item in result.rule_results:
        if item.rule_id == rule_id:
            return item
    raise AssertionError(f"missing rule result: {rule_id}")


def lines_of(count: int, indent: str = "") -> str:
    """Deterministic filler body of ``count`` physical lines."""
    return "\n".join(f"{indent}step_{index} = {index}" for index in range(count))
