"""VS-003/VS-004 vertical slice: parse → NCM → analyze → persist → seal.

The production orchestrator ``run_analysis_pipeline`` is driven through the
sanctioned test-only overrides (local fixture remote, in-memory providers)
after a real POST acceptance. Every assertion checks persisted rows, the
terminal lifecycle, the sealed snapshot, and the read API — never mere
call counts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.analysis import run_analysis_pipeline
from app.analyzers.security.source import DictSourceProvider
from app.core.database import session_scope
from app.models.indexing import File, Limitation
from app.models.results import (
    AnalysisSnapshot,
    ArchitectureMetric,
    Dependency,
    DomainState,
    FileCoverage,
    Module,
    RuleEvaluation,
)
from app.repository.errors import RetrievalError
from tests.fixtures.helpers.repo_helpers import init_git_repo
from tests.integration.test_vertical_slice import (
    _analysis_state,
    _factory,
    _github,
    _Recorder,
    _runner_deps,
    _seed_post,
    _slice_client,
)

pytestmark = pytest.mark.integration

#: A small but complete repository: a cross-module cycle (architecture),
#: declared sources (security/code-structure), and a manifest (dependency).
FIXTURE_FILES = {
    "app/__init__.py": "",
    "app/main.py": (
        "from app.services.alpha import alpha\n"
        "from app.services.beta import beta\n\n\n"
        "def main():\n"
        "    return alpha() + beta()\n"
    ),
    "app/services/__init__.py": "",
    "app/services/alpha.py": (
        "from app.services.beta import beta\n\n\ndef alpha():\n    return beta() + 1\n"
    ),
    "app/services/beta.py": (
        "from app.services.alpha import alpha\n\n\ndef beta():\n    return 1\n"
    ),
    "requirements.txt": "requests==2.31.0\n",
    "README.md": "# Fixture\n",
}

_SUPPORTED_SOURCE = {path: text for path, text in FIXTURE_FILES.items() if path.endswith(".py")}


def _count(factory, model, analysis_id: str) -> int:
    with session_scope(factory) as session:
        return int(
            session.scalar(
                select(func.count()).select_from(model).where(model.analysis_id == analysis_id)
            )
            or 0
        )


def _count_file_coverages(factory, analysis_id: str) -> int:
    with session_scope(factory) as session:
        return int(
            session.scalar(
                select(func.count())
                .select_from(FileCoverage)
                .join(File, File.id == FileCoverage.file_id)
                .where(File.analysis_id == analysis_id)
            )
            or 0
        )


def _pipeline_deps(factory, head: str, workspace_root: Path):
    return _runner_deps(factory, _github(head), workspace_root)


def test_pipeline_completes_slice_and_seals_snapshot(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]

        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )

        analysis = _analysis_state(factory, analysis_id)
        assert analysis.outcome in ("Completed", "Completed with limitations")
        assert analysis.resolved_commit_sha == head
        assert analysis.analysis_config is not None
        assert analysis.analysis_config["architecture"]["coupling_definition"] == "coupling-def-1"

        # The workspace is disposable and cleaned on success.
        assert list((tmp_path / "workspaces").glob("ws-*")) == []

        # Every result section is persisted, never inferred from absence.
        domain_states = _count(factory, DomainState, analysis_id)
        assert domain_states == 4
        rule_evaluations = _count(factory, RuleEvaluation, analysis_id)
        assert rule_evaluations == 29  # 12 SEC + 4 DEP + 9 ARCH + 4 CODE
        assert _count(factory, Module, analysis_id) >= 3
        assert _count(factory, ArchitectureMetric, analysis_id) >= 1
        assert _count_file_coverages(factory, analysis_id) >= 1
        assert _count(factory, Dependency, analysis_id) >= 1
        assert _count(factory, File, analysis_id) == len(FIXTURE_FILES)

        # A completed analysis is sealed exactly once.
        with session_scope(factory) as session:
            snapshot = session.scalar(
                select(AnalysisSnapshot).where(AnalysisSnapshot.analysis_id == analysis_id)
            )
            assert snapshot is not None

        body = client.get(f"/api/analyses/{analysis_id}").json()
        assert body["status"]["outcome"] in ("Completed", "Completed with limitations")
        assert body["summary"] is not None
        assert body["files"] is not None
        assert body["architecture"] is not None
        assert body["dependencies"] is not None
        assert body["code_structure"] is not None
    finally:
        engine.dispose()


def test_pipeline_is_idempotent_and_skips_settled(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]
        deps = _pipeline_deps(factory, head, tmp_path / "workspaces")

        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )
        first = _count(factory, RuleEvaluation, analysis_id)
        run_analysis_pipeline(
            analysis_id=analysis_id,
            deps=deps,
            remote_url_override=str(source),
            allow_local_paths=True,
            source_provider=DictSourceProvider(_SUPPORTED_SOURCE),
        )
        assert _count(factory, RuleEvaluation, analysis_id) == first
        assert _count(factory, AnalysisSnapshot, analysis_id) == 1

        # Unknown ids are a quiet no-op.
        run_analysis_pipeline(analysis_id="0" * 32, deps=deps)
    finally:
        engine.dispose()


def test_pipeline_marks_failed_and_cleans_on_retrieval_failure(tmp_path: Path) -> None:
    engine, factory = _factory()
    try:
        recorder: _Recorder = _Recorder()
        source = tmp_path / "source"
        head = init_git_repo(source, FIXTURE_FILES)
        client = _slice_client(factory, _github(head), recorder, tmp_path / "workspaces")
        created = _seed_post(factory, client)
        analysis_id = created["analysis_id"]

        with pytest.raises(RetrievalError):
            run_analysis_pipeline(
                analysis_id=analysis_id,
                deps=_pipeline_deps(factory, head, tmp_path / "workspaces"),
                remote_url_override=str(tmp_path / "does-not-exist"),
                allow_local_paths=True,
            )

        analysis = _analysis_state(factory, analysis_id)
        assert analysis.outcome == "Failed"
        assert str(tmp_path) not in (analysis.explanation or "")
        assert list((tmp_path / "workspaces").glob("ws-*")) == []
        assert _count(factory, AnalysisSnapshot, analysis_id) == 0
        assert _count(factory, File, analysis_id) == 0
        assert _count(factory, Limitation, analysis_id) == 0
    finally:
        engine.dispose()
