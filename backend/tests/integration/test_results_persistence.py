"""Results gateway integration tests (Phase 11, TASK-148–159).

SQLite-backed round trip: rule registry, results context, modules,
dependencies, metrics, findings with associations, states, evaluations,
coverages, limitations, completion, sealing, canonical serialization, and
comparison. Plus seal guards, double-persist rejection, unknown-reference
rejection, and seal validation.
"""

import pytest
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from app.analyzers.findings import Confidence, Finding, Limitation, Severity, create_finding
from app.core.database import create_session_factory
from app.models.base import Base
from app.models.repository import TERMINAL_OUTCOMES as INGESTION_TERMINAL_OUTCOMES
from app.models.repository import Analysis
from app.models.results import TERMINAL_OUTCOMES as RESULTS_TERMINAL_OUTCOMES
from app.ncm import SourceLocation
from app.repositories import results as gateway
from app.repositories.indexing import save_index
from app.repositories.ingestion import (
    create_analysis,
    get_or_create_repository,
    mark_failed,
    record_context_resolution,
    record_workspace,
    set_stage,
    terminal_outcomes,
)
from app.repository.identity import RepositoryIdentity
from app.repository.index_types import IndexedFile
from app.results.aggregation import TERMINAL_OUTCOMES as AGGREGATION_TERMINAL_OUTCOMES

IDENTITY = RepositoryIdentity(owner="acme", name="web")

RULES = [
    gateway.RuleDefinition(
        rule_id="SEC-HARDCODED-SECRET", name="Hardcoded secret", category="security"
    ),
    gateway.RuleDefinition(
        rule_id="ARCH-HIGH-FAN-OUT", name="High fan-out", category="architecture"
    ),
    gateway.RuleDefinition(
        rule_id="DEP-KNOWN-VULNERABILITY", name="Known vulnerability", category="dependency"
    ),
    gateway.RuleDefinition(
        rule_id="CODE-HIGH-COMPLEXITY", name="High complexity", category="code_structure"
    ),
]

CONFIGURATION = {
    "generated_files": "Included",
    "architecture": {
        "coupling_definition": "coupling-def-1",
        "thresholds": {"ARCH-HIGH-FAN-OUT": {"fan_out": 3}},
    },
}


def _session() -> tuple[Engine, Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, create_session_factory(engine)()


def _indexed(path: str, file_type: str = "source", language: str | None = "python") -> IndexedFile:
    return IndexedFile(
        relative_path=path,
        file_type=file_type,
        extension=".py" if file_type == "source" else ".txt",
        size=100,
        language=language,
        support_status="supported" if language == "python" else "unrecognized",
        is_binary=False,
        is_generated=False,
        excluded=False,
        exclusion_reason=None,
        eligibility="eligible",
        eligibility_reason="",
        indexing_limitation=None,
    )


def _setup(session: Session) -> Analysis:
    repo = get_or_create_repository(session, IDENTITY, default_branch="main")
    analysis = create_analysis(
        session,
        repo,
        requested_branch="main",
        requested_commit=None,
        analyzer_version="1.0.0",
        rule_set_version="1.0.0",
    )
    analysis.resolved_branch = "main"
    analysis.branch_origin = "defaulted"
    analysis.resolved_commit_sha = "a" * 40
    analysis.commit_origin = "defaulted"
    save_index(
        session,
        analysis.id,
        [
            _indexed("app/main.py"),
            _indexed("app/util.py"),
            _indexed("requirements.txt", file_type="manifest", language=None),
        ],
        [],
    )
    return analysis


def _arch_finding(identity: str = "arch-1", path: str = "app/main.py"):
    return create_finding(
        rule_id="ARCH-HIGH-FAN-OUT",
        analyzer_id="architecture",
        category="architecture",
        title="Elevated fan-out",
        description="Module app/main.py has fan_out 5 > 3 (strict).",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        location=SourceLocation(path, 1, 1, 0, 0),
        recommendation="Review.",
        analysis_id="",
        subject_key=f"fan-out:{path}",
        applied_thresholds=(("fan_out", 3),),
        severity_factors=("value 5 against threshold 3",),
        confidence_factors=("direct count",),
        identity_key=identity,
    )


def _real_finding(analysis_id: str, path: str = "app/main.py", line: int = 1):
    """One architecture finding through the real identity computation.

    No explicit identity key: the key is computed from the logical
    components with the owning analysis id, exactly as analyzers emit it.
    """
    return create_finding(
        rule_id="ARCH-HIGH-FAN-OUT",
        analyzer_id="architecture",
        category="architecture",
        title="Elevated fan-out",
        description="Module app/main.py has fan_out 5 > 3 (strict).",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        location=SourceLocation(path, line, line, 0, 0),
        recommendation="Review.",
        analysis_id=analysis_id,
        subject_key=f"fan-out:{path}",
        applied_thresholds=(("fan_out", 3),),
        severity_factors=("value 5 against threshold 3",),
        confidence_factors=("direct count",),
    )


def _persist_full(
    session: Session,
    analysis: Analysis,
    findings: list[Finding] | None = None,
    limitations: list[Limitation] | None = None,
    outcome: str = "Completed",
    explanation: str = "",
) -> None:
    rules = gateway.ensure_rules(session, "1.0.0", RULES)
    gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
    gateway.persist_modules(
        session,
        analysis.id,
        [
            gateway.ModuleInput(
                module_id="app/main.py",
                file_path="app/main.py",
                dependencies=(
                    gateway.ModuleDepInput(
                        target="app/util.py",
                        target_text="app.util",
                        resolution="internal",
                        file_path="app/main.py",
                        line=3,
                        column=0,
                        locations=(("app/main.py", 3, 0),),
                    ),
                ),
            ),
            gateway.ModuleInput(module_id="app/util.py", file_path="app/util.py"),
        ],
    )
    gateway.persist_metrics(
        session,
        analysis.id,
        [
            gateway.MetricInput(
                area="architecture", metric_name="fan_out", subject_path="app/main.py", value=5
            )
        ],
    )
    gateway.persist_findings(
        session, analysis, rules, [_arch_finding()] if findings is None else findings
    )
    gateway.persist_domain_states(
        session,
        analysis.id,
        [
            gateway.DomainStateInput("security", "No findings detected"),
            gateway.DomainStateInput("architecture", None),
            gateway.DomainStateInput("dependency", "No findings detected"),
            gateway.DomainStateInput("code_structure", "No findings detected"),
        ],
    )
    gateway.persist_rule_evaluations(
        session,
        analysis,
        rules,
        [gateway.RuleEvaluationInput(rule.rule_id, "Evaluated") for rule in RULES],
    )
    gateway.persist_file_coverages(session, analysis.id, [])
    gateway.persist_limitations(
        session, analysis, rules, [] if limitations is None else limitations
    )
    gateway.mark_completed(session, analysis, outcome=outcome, explanation=explanation)
    gateway.seal_snapshot(session, analysis.id)


def test_full_round_trip_seal_and_canonical() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        _persist_full(session, analysis)
        result = gateway.canonical_result(session, analysis.id)
        assert result["analysis"]["analysis_id"] == analysis.id
        status = result["status"]
        assert isinstance(status, dict)
        assert status["stage"] is None and status["outcome"] == "Completed"
        architecture = result["architecture"]
        assert isinstance(architecture, dict)
        assert architecture["findings"][0]["finding_id"] == "F-0001"
        assert architecture["findings"][0]["subject"]["modules"] == ["app/main.py"]
        assert architecture["graph"]["edges"] == [
            {
                "source": "app/main.py",
                "target": "app/util.py",
                "relationship_type": "import",
                "locations": [{"path": "app/main.py", "line": 3, "column": 0}],
            }
        ]
        summary = result["summary"]
        assert isinstance(summary, dict)
        assert summary["architecture"]["module_count"] == 2
        assert summary["architecture"]["module_dependency_count"] == 1
        session.commit()
    finally:
        session.close()
        engine.dispose()


def test_finding_ids_deterministic_and_preserved() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        rules = gateway.ensure_rules(session, "1.0.0", RULES)
        gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
        gateway.persist_modules(
            session,
            analysis.id,
            [gateway.ModuleInput(module_id="app/main.py", file_path="app/main.py")],
        )
        rows = gateway.persist_findings(
            session, analysis, rules, [_arch_finding(identity="arch-9")]
        )
        assert rows[0].finding_id == "F-0001"
        assert rows[0].subject_key == "fan-out:app/main.py"
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_seal_guard_and_double_persist_rejected() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        _persist_full(session, analysis)
        with session.no_autoflush:
            pass
        with pytest.raises(gateway.SealedSnapshotError):
            gateway.persist_metrics(
                session,
                analysis.id,
                [
                    gateway.MetricInput(
                        area="architecture",
                        metric_name="fan_out",
                        subject_path="app/main.py",
                        value=1,
                    )
                ],
            )
        with pytest.raises(gateway.SealedSnapshotError):
            gateway.seal_snapshot(session, analysis.id)
        # Load of an unknown analysis raises instead of returning partial data.
        with pytest.raises(ValueError):
            gateway.load_snapshot_data(session, "0" * 32)
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_double_persist_before_seal_rejected() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        gateway.ensure_rules(session, "1.0.0", RULES)
        gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
        modules = [gateway.ModuleInput(module_id="app/main.py", file_path="app/main.py")]
        gateway.persist_modules(session, analysis.id, modules)
        with pytest.raises(ValueError):
            gateway.persist_modules(session, analysis.id, modules)
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_unknown_references_rejected() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        rules = gateway.ensure_rules(session, "1.0.0", RULES)
        gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
        with pytest.raises(ValueError):
            gateway.persist_modules(
                session,
                analysis.id,
                [gateway.ModuleInput(module_id="ghost.py", file_path="ghost.py")],
            )
        with pytest.raises(ValueError):
            gateway.persist_metrics(
                session,
                analysis.id,
                [
                    gateway.MetricInput(
                        area="architecture",
                        metric_name="mystery",
                        subject_path="app/main.py",
                        value=1,
                    )
                ],
            )
        gateway.persist_modules(
            session,
            analysis.id,
            [gateway.ModuleInput(module_id="app/main.py", file_path="app/main.py")],
        )
        with pytest.raises(ValueError):
            gateway.persist_findings(session, analysis, rules, [_arch_finding(path="ghost.py")])
        with pytest.raises(ValueError):
            gateway.persist_domain_states(
                session, analysis.id, [gateway.DomainStateInput("security", "Nope")]
            )
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_rule_registry_immutable_and_seal_validation() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        gateway.ensure_rules(session, "1.0.0", RULES)
        drifted = [
            gateway.RuleDefinition(
                rule_id="SEC-HARDCODED-SECRET", name="Changed", category="security"
            )
        ]
        with pytest.raises(ValueError, match="immutable"):
            gateway.ensure_rules(session, "1.0.0", drifted)
        # Failed analyses never seal.
        gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
        gateway.mark_completed(session, analysis, outcome="Failed", explanation="boom")
        with pytest.raises(gateway.IncompleteSnapshotError):
            gateway.seal_snapshot(session, analysis.id)
        # Completed with limitations requires an explanation.
        analysis.outcome = None
        with pytest.raises(ValueError, match="explanation"):
            gateway.mark_completed(
                session, analysis, outcome="Completed with limitations", explanation="  "
            )
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_duplicate_identity_rejected_and_limitation_mapping() -> None:
    engine, session = _session()
    try:
        analysis = _setup(session)
        rules = gateway.ensure_rules(session, "1.0.0", RULES)
        gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
        gateway.persist_modules(
            session,
            analysis.id,
            [gateway.ModuleInput(module_id="app/main.py", file_path="app/main.py")],
        )
        with pytest.raises(ValueError, match="Duplicate finding identities"):
            gateway.persist_findings(
                session, analysis, rules, [_arch_finding("dup"), _arch_finding("dup")]
            )
        gateway.persist_limitations(
            session,
            analysis,
            rules,
            [
                Limitation(scope="analysis", reason="Global note."),
                Limitation(
                    scope="architecture:ARCH-HIGH-FAN-OUT",
                    reason="Graph note.",
                    rule_id="ARCH-HIGH-FAN-OUT",
                ),
                Limitation(
                    scope="security:SEC-HARDCODED-SECRET", reason="File note.", path="app/main.py"
                ),
            ],
        )
        rows = None
        with pytest.raises(gateway.IncompleteSnapshotError):
            gateway.load_snapshot_data(session, analysis.id)
        assert rows is None  # unsealed snapshots are not loadable units
        from app.models.indexing import Limitation as LimitationRow

        stored = session.scalars(
            select(LimitationRow).where(LimitationRow.analysis_id == analysis.id)
        ).all()
        kinds = sorted(row.scope_kind for row in stored)
        assert kinds == ["analysis", "file", "rule"]
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_compare_two_sealed_snapshots() -> None:
    engine, session = _session()
    try:
        first = _setup(session)
        _persist_full(session, first)
        second = _setup(session)
        rules = gateway.ensure_rules(session, "1.0.0", RULES)
        gateway.record_results_context(session, second, configuration=dict(CONFIGURATION))
        gateway.persist_modules(
            session,
            second.id,
            [gateway.ModuleInput(module_id="app/main.py", file_path="app/main.py")],
        )
        gateway.persist_findings(session, second, rules, [_arch_finding(identity="arch-2")])
        gateway.persist_domain_states(
            session,
            second.id,
            [
                gateway.DomainStateInput("security", "No findings detected"),
                gateway.DomainStateInput("architecture", None),
                gateway.DomainStateInput("dependency", "No findings detected"),
                gateway.DomainStateInput("code_structure", "No findings detected"),
            ],
        )
        gateway.persist_rule_evaluations(
            session,
            second,
            rules,
            [gateway.RuleEvaluationInput(rule.rule_id, "Evaluated") for rule in RULES],
        )
        gateway.persist_file_coverages(session, second.id, [])
        gateway.persist_limitations(session, second, rules, [])
        gateway.mark_completed(session, second, outcome="Completed", explanation="")
        gateway.seal_snapshot(session, second.id)
        result = gateway.compare_analyses(session, first.id, second.id)
        assert result.comparable
        assert [entry.identity_key for entry in result.resolved] == ["arch-1"]
        assert [entry.identity_key for entry in result.new] == ["arch-2"]
        assert result.unchanged == ()
        session.commit()
    finally:
        session.close()
        engine.dispose()


def test_compare_real_identities_across_analyses() -> None:
    """Same logical finding via the real path compares as Unchanged.

    Both snapshots are built from analyzer-emitted findings whose identity
    keys are computed with their own (different) analysis ids and never
    injected. A shared finding is Unchanged; single-sided findings are
    New/Resolved; the mix exercises all three categories at once.
    """
    engine, session = _session()
    try:
        base = _setup(session)
        _persist_full(
            session,
            base,
            findings=[
                _real_finding(base.id, path="app/main.py"),
                _real_finding(base.id, path="app/util.py"),
            ],
        )
        target = _setup(session)
        _persist_full(
            session,
            target,
            findings=[
                _real_finding(target.id, path="app/main.py"),
                _real_finding(target.id, path="app/main.py", line=9),
            ],
        )
        base_keys = sorted(
            row.identity_key for row in gateway.load_snapshot_data(session, base.id).findings
        )
        target_keys = sorted(
            row.identity_key for row in gateway.load_snapshot_data(session, target.id).findings
        )
        # The shared logical finding survived persistence with one stable key.
        assert len(set(base_keys)) == 2 and len(set(target_keys)) == 2
        shared = set(base_keys) & set(target_keys)
        assert len(shared) == 1
        result = gateway.compare_analyses(session, base.id, target.id)
        assert result.comparable
        assert [entry.identity_key for entry in result.unchanged] == sorted(shared)
        assert len(result.resolved) == 1 and len(result.new) == 1
        assert result.resolved[0].identity_key not in target_keys
        assert result.new[0].identity_key not in base_keys
        session.commit()
    finally:
        session.close()
        engine.dispose()


def test_terminal_outcome_vocabulary_agrees() -> None:
    """All terminal-state definitions use the canonical contract vocabulary.

    The frozen contract (docs/12 §4.2/§6.2, docs/13 §6.1, docs/17 §4.1)
    defines exactly Completed, Completed with limitations, Failed. No
    unspaced alternate spelling is a valid state.
    """
    canonical = {"Completed", "Completed with limitations", "Failed"}
    assert set(INGESTION_TERMINAL_OUTCOMES) == canonical
    assert set(RESULTS_TERMINAL_OUTCOMES) == canonical
    assert set(AGGREGATION_TERMINAL_OUTCOMES) == canonical
    assert set(terminal_outcomes()) == canonical
    assert set(gateway.SEALABLE_OUTCOMES) == {"Completed", "Completed with limitations"}
    assert "CompletedWithLimitations" not in terminal_outcomes()


def test_terminal_checks_recognize_completed_with_limitations() -> None:
    """Lifecycle checks treat the spaced limitations outcome as terminal."""
    engine, session = _session()
    try:
        analysis = _setup(session)
        gateway.ensure_rules(session, "1.0.0", RULES)
        gateway.record_results_context(session, analysis, configuration=dict(CONFIGURATION))
        gateway.mark_completed(
            session, analysis, outcome="Completed with limitations", explanation="Partial."
        )
        assert analysis.outcome == "Completed with limitations"
        # Terminal analyses reject further lifecycle transitions.
        with pytest.raises(ValueError):
            set_stage(session, analysis, "RunningAnalysis")
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_completed_with_limitation_record_rejected_at_seal() -> None:
    """Strict Completed cannot seal alongside a recorded limitation (§6.6).

    The failed seal leaves no snapshot row: nothing misleading is stored.
    """
    engine, session = _session()
    try:
        analysis = _setup(session)
        with pytest.raises(gateway.IncompleteSnapshotError, match="must not coexist"):
            _persist_full(
                session,
                analysis,
                limitations=[Limitation(scope="analysis", reason="Partial coverage.")],
                outcome="Completed",
                explanation="",
            )
        assert gateway.get_snapshot(session, analysis.id) is None
        assert analysis.outcome == "Completed"
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_completed_with_limitations_outcome_seals() -> None:
    """The limitations outcome seals with an explanation and valid coverage."""
    engine, session = _session()
    try:
        analysis = _setup(session)
        _persist_full(
            session,
            analysis,
            limitations=[Limitation(scope="analysis", reason="Partial coverage.")],
            outcome="Completed with limitations",
            explanation="Partial coverage in one area.",
        )
        snapshot = gateway.get_snapshot(session, analysis.id)
        assert snapshot is not None and snapshot.outcome == "Completed with limitations"
        result = gateway.canonical_result(session, analysis.id)
        status = result["status"]
        assert isinstance(status, dict)
        assert status["outcome"] == "Completed with limitations"
        assert len(status["limitations"]) == 1
        session.commit()
    finally:
        session.close()
        engine.dispose()


def test_post_seal_context_and_workspace_rejected() -> None:
    """Sealed snapshots freeze provenance: context/workspace writes fail.

    Rejected mutations leave the commit SHA, workspace metadata, and the
    snapshot itself unchanged.
    """
    engine, session = _session()
    try:
        analysis = _setup(session)
        record_workspace(session, analysis, "/tmp/ws-before-seal")
        _persist_full(session, analysis)
        assert gateway.get_snapshot(session, analysis.id) is not None
        with pytest.raises(ValueError):
            record_context_resolution(
                session,
                analysis,
                resolved_branch="other",
                branch_origin="requested",
                resolved_commit_sha="b" * 40,
                commit_origin="requested",
            )
        with pytest.raises(ValueError):
            record_workspace(session, analysis, "/tmp/ws-after-seal")
        session.refresh(analysis)
        assert analysis.resolved_commit_sha == "a" * 40
        assert analysis.workspace_path == "/tmp/ws-before-seal"
        assert gateway.get_snapshot(session, analysis.id) is not None
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_terminal_without_snapshot_rejects_context_writes() -> None:
    """Terminal state alone blocks context mutation (no snapshot needed)."""
    engine, session = _session()
    try:
        analysis = _setup(session)
        mark_failed(session, analysis, "boom")
        assert gateway.get_snapshot(session, analysis.id) is None
        with pytest.raises(ValueError):
            record_context_resolution(
                session,
                analysis,
                resolved_branch="main",
                branch_origin="defaulted",
                resolved_commit_sha="c" * 40,
                commit_origin="defaulted",
            )
        with pytest.raises(ValueError):
            record_workspace(session, analysis, "/tmp/ws-terminal")
        session.refresh(analysis)
        assert analysis.resolved_commit_sha == "a" * 40
        assert analysis.workspace_path is None
        session.rollback()
    finally:
        session.close()
        engine.dispose()
