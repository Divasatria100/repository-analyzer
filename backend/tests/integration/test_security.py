"""Security integration: repository → index → parse → NCM → analyzer.

Proves the Phase 7 implementation works through the intended
architecture (real workspace files, real parser pipeline, real NCM)
rather than only through isolated unit tests. SQLite-backed; canary and
network guardrails apply.
"""

from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.analyzers.base import AnalyzerResult
from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.source import DictSourceProvider
from app.core.config import load_settings
from app.models import repository as _repository_models  # noqa: F401 (register tables)
from app.ncm import NcmRepository
from app.parsers.pipeline import ParsePhaseResult, run_parse_phase
from app.repositories import indexing as gateway
from app.repository.index_types import IndexedFile
from app.repository.workspace import WorkspaceManager
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.canary import assert_canary_absent
from tests.fixtures.helpers.db_helpers import make_sqlite_factory
from tests.fixtures.helpers.paths import read_fixture_bytes

pytestmark = pytest.mark.security

VULN_APP = read_fixture_bytes("security", "sql_injection.py")
SAFE_APP = read_fixture_bytes("security", "security_safe_patterns.py")


def _file(path: str, **overrides: object) -> IndexedFile:
    base: dict[str, object] = {
        "relative_path": path,
        "file_type": "source",
        "extension": "py",
        "size": 10,
        "language": "python",
        "support_status": "supported",
        "is_binary": False,
        "is_generated": False,
        "excluded": False,
        "exclusion_reason": None,
        "eligibility": "eligible",
        "eligibility_reason": "supported source file; parser may consider",
        "indexing_limitation": None,
    }
    base.update(overrides)
    return IndexedFile(**base)  # type: ignore[arg-type]


def _run(tmp_path: Path, files: dict[str, bytes]) -> tuple[ParsePhaseResult, Session, Engine, Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for relpath, content in files.items():
        target = workspace / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    engine, factory = make_sqlite_factory()
    session = factory()
    gateway.save_index(session, "a1", [_file(path) for path in files], [])
    session.commit()
    workspaces = WorkspaceManager(tmp_path / "roots")
    summary = run_parse_phase(
        session=session,
        analysis_id="a1",
        workspace=workspace,
        workspaces=workspaces,
        settings=load_settings(),
    )
    session.commit()
    assert summary.repository is not None
    return summary, session, engine, workspace


def _analyze(repository: NcmRepository, workspace: Path, paths: list[str]) -> AnalyzerResult:
    sources = {path: (workspace / path).read_text(encoding="utf-8") for path in paths}
    context = make_context(analysis_id="a1", ncm=repository)
    return SecurityAnalyzer(DictSourceProvider(sources)).analyze(context)


def test_pipeline_vulnerable_app_yields_security_finding(tmp_path: Path) -> None:
    """Indexed + parsed fixture reaches the security analyzer end to end."""
    summary, session, engine, workspace = _run(tmp_path, {"app.py": VULN_APP})
    try:
        persisted = {row.path: row for row in gateway.get_files(session, "a1")}
        assert persisted["app.py"].parse_result == "parsed"
        assert summary.repository is not None
        result = _analyze(summary.repository, workspace, ["app.py"])
        assert result.failed is False
        assert [finding.rule_id for finding in result.findings] == ["SEC-SQL-INJECTION"]
        assert_canary_absent()
    finally:
        session.close()
        engine.dispose()


def test_pipeline_safe_app_yields_no_security_findings(tmp_path: Path) -> None:
    """The safe-patterns fixture stays silent through the same pipeline."""
    summary, session, engine, workspace = _run(tmp_path, {"safe.py": SAFE_APP})
    try:
        assert summary.repository is not None
        result = _analyze(summary.repository, workspace, ["safe.py"])
        assert result.failed is False
        assert result.findings == ()
        assert_canary_absent()
    finally:
        session.close()
        engine.dispose()


def test_pipeline_broken_file_is_not_clean(tmp_path: Path) -> None:
    """A file that fails parsing is recorded, never reported as secure."""
    summary, session, engine, workspace = _run(
        tmp_path,
        {"good.py": VULN_APP, "broken.py": b"def broken(:\n"},
    )
    try:
        persisted = {row.path: row for row in gateway.get_files(session, "a1")}
        assert persisted["broken.py"].parse_result == "failed"
        assert summary.repository is not None
        assert summary.repository.completeness == "incomplete"
        result = _analyze(summary.repository, workspace, ["good.py"])
        assert any(finding.rule_id == "SEC-SQL-INJECTION" for finding in result.findings)
        assert any(
            limitation.path == "broken.py"
            for item in result.rule_results
            for limitation in item.limitations
        )
        assert_canary_absent()
    finally:
        session.close()
        engine.dispose()
