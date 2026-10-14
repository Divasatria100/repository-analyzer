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

from app.analyzers.findings import Confidence, Limitation, Severity, create_finding
from app.core.database import create_session_factory
from app.models.base import Base
from app.models.repository import Analysis
from app.ncm import SourceLocation
from app.repositories import results as gateway
from app.repositories.indexing import save_index
from app.repositories.ingestion import create_analysis, get_or_create_repository
from app.repository.identity import RepositoryIdentity
from app.repository.index_types import IndexedFile

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


def _persist_full(session: Session, analysis: Analysis) -> None:
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
    gateway.persist_findings(session, analysis, rules, [_arch_finding()])
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
    gateway.persist_limitations(session, analysis, rules, [])
    gateway.mark_completed(session, analysis, outcome="Completed", explanation="")
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
