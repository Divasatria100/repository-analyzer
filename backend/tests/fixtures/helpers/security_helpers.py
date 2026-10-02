"""Test-only builders for Phase 7 security tests (never production code)."""

from __future__ import annotations

from app.analyzers.base import AnalyzerResult
from app.analyzers.context import AnalysisContext
from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.source import DictSourceProvider
from app.ncm import NcmFileEntry, NcmRepository
from app.parsers.base import ParserInput
from app.parsers.registry import get_adapter
from tests.fixtures.helpers.analyzer_helpers import make_context


def parse_files(files: dict[str, str]) -> NcmRepository:
    """Parse in-memory sources into an NCM repository (read as data only)."""
    adapter = get_adapter("python")
    assert adapter is not None
    entries: list[NcmFileEntry] = []
    for path in sorted(files):
        source = files[path].encode("utf-8")
        result = adapter.parse(ParserInput(path, "python", source, 30.0, 1_000_000))
        entries.append(
            NcmFileEntry(
                path=path,
                language="python",
                parse_state=result.state.value,
                module=result.ncm,
            )
        )
    return NcmRepository(analysis_id="analysis-1", files=entries)


def analyze_files(
    files: dict[str, str],
    analyzer: SecurityAnalyzer | None = None,
    analysis_id: str = "analysis-1",
) -> tuple[AnalyzerResult, AnalysisContext, SecurityAnalyzer]:
    """Parse sources, build context, and run the security analyzer."""
    ncm = parse_files(files)
    context = make_context(analysis_id=analysis_id, ncm=ncm)
    active = analyzer if analyzer is not None else SecurityAnalyzer(DictSourceProvider(files))
    result: AnalyzerResult = active.analyze(context)
    return result, context, active
