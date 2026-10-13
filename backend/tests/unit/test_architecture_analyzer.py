"""Architecture analyzer integration tests (TASK-132).

Nine registered rules through the Phase 6 foundation; common Finding model;
deterministic identities; bounded redacted evidence; isolated failures;
observation framing without defect claims.
"""

from app.analyzers.architecture.analyzer import ArchitectureAnalyzer, build_architecture_rules
from app.analyzers.security.source import DictSourceProvider
from tests.fixtures.helpers.architecture_helpers import analyze_arch, rule_result

EXPECTED_RULES = [
    "ARCH-CIRCULAR-DEPENDENCY",
    "ARCH-HIGH-COUPLING",
    "ARCH-HIGH-FAN-IN",
    "ARCH-HIGH-FAN-OUT",
    "ARCH-LARGE-CLASS",
    "ARCH-LARGE-FUNCTION",
    "ARCH-LARGE-MODULE",
    "ARCH-LAYER-VIOLATION",
    "ARCH-MULTIPLE-RESPONSIBILITY",
]


def test_nine_rules_registered_in_order() -> None:
    analyzer = ArchitectureAnalyzer(DictSourceProvider({}))
    assert analyzer.id == "architecture"
    assert [rule.metadata.rule_id for rule in analyzer.rules()] == EXPECTED_RULES
    assert [rule.metadata.rule_id for rule in build_architecture_rules(analyzer)] == EXPECTED_RULES
    assert all(rule.metadata.analyzer_id == "architecture" for rule in analyzer.rules())


def test_analyzer_runs_only_architecture_rules() -> None:
    result, _, _ = analyze_arch({"a.py": "import b\n", "b.py": "import a\n"})
    assert {item.rule_id for item in result.rule_results} == set(EXPECTED_RULES)
    assert all(finding.category == "architecture" for finding in result.findings)
    assert {finding.rule_id for finding in result.findings} == {"ARCH-CIRCULAR-DEPENDENCY"}


def test_finding_identities_are_deterministic() -> None:
    files = {"a.py": "import b\n", "b.py": "import a\n"}
    first, _, _ = analyze_arch(files)
    second, _, _ = analyze_arch(files)
    assert {item.identity_key for item in first.findings} == {
        item.identity_key for item in second.findings
    }
    assert len(first.findings) == 1


def test_evidence_window_is_bounded() -> None:
    from tests.fixtures.helpers.architecture_helpers import lines_of

    imports = "".join(f"import leaf{i}\n" for i in range(8))
    source = f"{imports}{lines_of(100, indent='')}\n"
    result, _, _ = analyze_arch({"hub.py": source, **{f"leaf{i}.py": "X = 1\n" for i in range(8)}})
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert finding.evidence is not None
    # Single-line focus: at most 10 before + 1 + 40 after = 51 lines.
    assert len(finding.evidence.lines) <= 51
    assert finding.evidence.start_line == 1


def test_evidence_redacts_planted_secret() -> None:
    # Shape covered by the frozen redaction machinery (bare `password = ...`).
    source = 'password = "FAKE-EXAMPLE-PASSWORD-NOT-REAL-12345"\nimport b\n'
    result, _, _ = analyze_arch(
        {"a.py": source, "b.py": "X = 1\n", **{f"u{i}.py": "import a\n" for i in range(11)}}
    )
    findings = rule_result(result, "ARCH-HIGH-FAN-IN").findings
    assert len(findings) == 1
    (finding,) = findings
    assert finding.location.file_path == "a.py"
    if finding.evidence is not None:
        for line in finding.evidence.lines:
            assert "FAKE-EXAMPLE-PASSWORD-NOT-REAL-12345" not in line
        assert finding.evidence.redacted is True


def test_partial_analysis_is_not_clean() -> None:
    result, _, _ = analyze_arch({"good.py": "X = 1\n", "broken.py": "def broken(:\n"})
    for rule_id in EXPECTED_RULES:
        outcome = rule_result(result, rule_id)
        assert any("broken.py" in item.reason for item in outcome.limitations)


def test_rule_failure_isolation() -> None:
    from app.analyzers.rules import RegisteredRule, RuleOutcome
    from tests.fixtures.helpers.analyzer_helpers import make_rule

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("rule boom")

    class FlakyArchitecture(ArchitectureAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            return [
                *super().rules(),
                RegisteredRule(metadata=make_rule("ARCH-TEST-999", "architecture"), execute=_boom),
            ]

    result, _, _ = analyze_arch(
        {"a.py": "import b\n", "b.py": "import a\n"},
        analyzer=FlakyArchitecture(DictSourceProvider({"a.py": "x", "b.py": "y"})),
    )
    by_rule = {item.rule_id: item for item in result.rule_results}
    assert by_rule["ARCH-TEST-999"].failure is not None
    assert by_rule["ARCH-TEST-999"].findings == ()
    assert result.failed is False
    assert "ARCH-CIRCULAR-DEPENDENCY" in {item.rule_id for item in result.findings}


def test_observation_framing_never_claims_defects() -> None:
    files = {"a.py": "import b\n", "b.py": "import a\n"}
    result, _, _ = analyze_arch(files)
    for finding in result.findings:
        text = f"{finding.title} {finding.description}".lower()
        assert "defect" not in text or "does not assert a defect" in text
        assert "poorly designed" not in text
        assert "violating a principle" not in text


def test_severity_never_critical() -> None:
    files = {f"leaf{i}.py": "X = 1\n" for i in range(30)}
    files["hub.py"] = "".join(f"import leaf{i}\n" for i in range(30))
    result, _, _ = analyze_arch(files)
    assert result.findings
    assert all(finding.severity.value != "Critical" for finding in result.findings)


def test_coverage_states_are_explicit() -> None:
    _, context, analyzer = analyze_arch({"a.py": "X = 1\n"})
    rows = {item.rule_id: item.status.value for item in analyzer.coverage(context.ncm)}
    assert set(rows) == set(EXPECTED_RULES)
    # Single module without layer keywords: layer rule not applicable, rest covered.
    assert rows["ARCH-LAYER-VIOLATION"] == "not_applicable"
    assert rows["ARCH-HIGH-FAN-OUT"] == "covered"


def test_empty_repository_coverage_is_unsupported() -> None:
    _, context, analyzer = analyze_arch({})
    rows = {item.rule_id: item.status.value for item in analyzer.coverage(context.ncm)}
    assert set(rows.values()) == {"unsupported"}


def test_findings_carry_versions_and_thresholds() -> None:
    result, _, _ = analyze_arch(
        {f"leaf{i}.py": "X = 1\n" for i in range(8)}
        | {"hub.py": "".join(f"import leaf{i}\n" for i in range(8))}
    )
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert finding.analyzer_version == "0.1.0"
    assert finding.rule_set_version == "1.0"
    assert finding.recommendation
    assert "fan_out > 7" in finding.description


def test_circular_crossing_boundary_is_medium() -> None:
    result, _, _ = analyze_arch(
        {"pkg/a.py": "from other import b\n", "other/b.py": "from pkg import a\n"}
    )
    (finding,) = rule_result(result, "ARCH-CIRCULAR-DEPENDENCY").findings
    assert finding.severity.value == "Medium"
    assert "package boundaries" in finding.description


def test_circular_through_conditional_lowers_confidence() -> None:
    result, _, _ = analyze_arch({"a.py": "import b\n", "b.py": "def f():\n    import a\n"})
    (finding,) = rule_result(result, "ARCH-CIRCULAR-DEPENDENCY").findings
    assert finding.confidence.value == "Medium"
    assert "conditional or deferred" in finding.description


def test_layer_violation_medium_with_consistent_direction() -> None:
    files = {
        "domain/orders.py": "from services import billing\n",
        "services/billing.py": "from domain import types\n",
        "services/extra.py": "from domain import types\n",
        "services/more.py": "from domain import types\n",
        "services/other.py": "from domain import types\n",
        "services/last.py": "from domain import types\n",
        "domain/types.py": "X = 1\n",
        "services/__init__.py": "",
        "domain/__init__.py": "",
    }
    result, _, _ = analyze_arch(files)
    (finding,) = rule_result(result, "ARCH-LAYER-VIOLATION").findings
    assert finding.severity.value == "Medium"
    assert "domain/orders.py" in finding.title


def test_class_lines_boundary_at_analyzer_level() -> None:
    filler = "\n".join(f"    step_{i} = {i}" for i in range(199))
    result, _, _ = analyze_arch({"m.py": f"class Big:\n{filler}\n"})
    assert rule_result(result, "ARCH-LARGE-CLASS").findings == ()
    filler = "\n".join(f"    step_{i} = {i}" for i in range(200))
    result, _, _ = analyze_arch({"m.py": f"class Big:\n{filler}\n"})
    assert len(rule_result(result, "ARCH-LARGE-CLASS").findings) == 1


def test_module_declarations_boundary_at_analyzer_level() -> None:
    body = "\n".join(f"def f{i}():\n    pass" for i in range(30))
    result, _, _ = analyze_arch({"m.py": body + "\n"})
    assert rule_result(result, "ARCH-LARGE-MODULE").findings == ()
    body = "\n".join(f"def f{i}():\n    pass" for i in range(31))
    result, _, _ = analyze_arch({"m.py": body + "\n"})
    assert len(rule_result(result, "ARCH-LARGE-MODULE").findings) == 1
