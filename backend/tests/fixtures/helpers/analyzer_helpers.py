"""Test-only factories for analyzer-foundation tests (never production code)."""

from __future__ import annotations

from pathlib import Path

from app.analyzers.context import AnalysisContext
from app.analyzers.findings import (
    Confidence,
    Evidence,
    Finding,
    Limitation,
    Severity,
    create_finding,
)
from app.analyzers.rules import RuleMetadata
from app.analyzers.thresholds import ThresholdSet, default_thresholds
from app.ncm import (
    NcmFileEntry,
    NcmModule,
    NcmRepository,
    NormalizedModule,
    SourceLocation,
)


def make_location(
    path: str = "src/app.py", start: int = 10, end: int | None = None
) -> SourceLocation:
    """One-line default location (1-based lines, 0-based columns)."""
    return SourceLocation(
        file_path=path,
        start_line=start,
        start_column=0,
        end_line=end if end is not None else start,
        end_column=0,
    )


def make_module(path: str = "src/app.py", completeness: str = "fully") -> NormalizedModule:
    """Minimal valid module (empty body, fully represented by default)."""
    return NormalizedModule(
        file_path=path,
        language="python",
        module=NcmModule(id=path, file_path=path, language="python", name="app"),
        completeness=completeness,
        parser="python-ast",
        parser_version="python-3.13",
    )


def make_ncm_repository(*paths: str, analysis_id: str = "analysis-1") -> NcmRepository:
    """NCM container with one parsed module per path (all fully represented)."""
    return NcmRepository(
        analysis_id=analysis_id,
        files=[
            NcmFileEntry(
                path=path,
                language="python",
                parse_state="parsed",
                module=make_module(path),
            )
            for path in paths
        ],
    )


def make_thresholds(**overrides: object) -> ThresholdSet:
    """Frozen defaults with optional field overrides (validated on build)."""
    values: dict[str, object] = dict(default_thresholds().effective())
    values.update(overrides)
    return ThresholdSet(**values)  # type: ignore[arg-type]


def make_context(
    analysis_id: str = "analysis-1",
    ncm: NcmRepository | None = None,
    thresholds: ThresholdSet | None = None,
) -> AnalysisContext:
    """Minimal valid analysis context (frozen, NCM-backed)."""
    return AnalysisContext(
        analysis_id=analysis_id,
        repository_id="repo-1",
        owner="octo",
        name="demo",
        canonical_url="https://github.com/octo/demo",
        resolved_branch="main",
        resolved_commit_sha="0" * 40,
        ncm=ncm if ncm is not None else make_ncm_repository("src/app.py", analysis_id=analysis_id),
        analyzer_version="0.1.0",
        rule_set_version="1.0",
        thresholds=thresholds if thresholds is not None else default_thresholds(),
    )


def make_rule(
    rule_id: str = "SEC-TEST-001",
    analyzer_id: str = "security",
    severity: str = "High",
) -> RuleMetadata:
    """Minimal valid rule metadata (validated on build)."""
    return RuleMetadata(
        rule_id=rule_id,
        name=f"Test rule {rule_id}",
        description="A test-only rule declaration.",
        analyzer_id=analyzer_id,
        version="1.0",
        default_severity=severity,
    )


def make_evidence(path: str = "src/app.py", start: int = 10, end: int = 10) -> Evidence:
    """Minimal bounded evidence excerpt (already redacted form)."""
    lines = tuple(f"line {number}" for number in range(start, end + 1))
    return Evidence(path=path, start_line=start, end_line=end, lines=lines)


def make_finding(
    rule_id: str = "SEC-TEST-001",
    path: str = "src/app.py",
    subject_key: str = "symbol",
    analysis_id: str = "analysis-1",
    **overrides: object,
) -> Finding:
    """Minimal valid finding with deterministic identity."""
    fields: dict[str, object] = {
        "rule_id": rule_id,
        "analyzer_id": "security",
        "category": "security",
        "title": "Test finding",
        "description": "A test-only observation.",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "location": make_location(path),
        "evidence": make_evidence(path),
        "recommendation": "Review the flagged code.",
        "analyzer_version": "0.1.0",
        "rule_set_version": "1.0",
        "analysis_id": analysis_id,
        "subject_key": subject_key,
    }
    fields.update(overrides)
    return create_finding(**fields)  # type: ignore[arg-type]


def make_workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write workspace fixture files as data (never executed, never imported)."""
    root = tmp_path / "ws"
    root.mkdir(parents=True, exist_ok=True)
    for relpath, content in files.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def make_limitation(reason: str = "reference unresolved", scope: str = "rule") -> Limitation:
    """Minimal limitation record."""
    return Limitation(scope=scope, reason=reason)
