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


def test_layer_violation_stays_low_with_consistent_direction() -> None:
    """FND-02: naming-inferred violations never escalate on edge counts."""
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
    assert finding.severity.value == "Low"
    assert any("consistent edge(s) elsewhere" in factor for factor in finding.severity_factors)
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


def test_cycle_states_representative_path_limitation() -> None:
    """FND-01: the finding states the displayed path is representative."""
    result, _, _ = analyze_arch({"a.py": "import b\n", "b.py": "import a\n"})
    (finding,) = rule_result(result, "ARCH-CIRCULAR-DEPENDENCY").findings
    assert "representative" in finding.description
    assert "does not enumerate every cycle" in finding.description
    assert "all cycles" not in finding.description.lower()


def test_overlapping_scc_states_limited_presentation() -> None:
    """FND-01: a multi-cycle component carries the limitation explicitly."""
    files = {
        "a.py": "import b\nimport c\n",
        "b.py": "import a\n",
        "c.py": "import a\n",
    }
    result, _, _ = analyze_arch(files)
    (finding,) = rule_result(result, "ARCH-CIRCULAR-DEPENDENCY").findings
    assert "does not enumerate every cycle" in finding.description
    for member in ("a.py", "b.py", "c.py"):
        assert member in finding.description


def test_self_loop_description_makes_no_path_claim() -> None:
    """FND-01: a self-loop path is exhaustive, so no limitation is stated."""
    result, _, _ = analyze_arch({"a.py": "import a\n"})
    (finding,) = rule_result(result, "ARCH-CIRCULAR-DEPENDENCY").findings
    assert "does not enumerate every cycle" not in finding.description
    assert "depends on itself" in finding.title


def test_cycle_description_deterministic_under_reorder() -> None:
    """FND-01: wording and identity are stable regardless of input order."""
    files = {"a.py": "import b\n", "b.py": "import c\n", "c.py": "import a\n"}
    first, _, _ = analyze_arch(files)
    second, _, _ = analyze_arch(dict(reversed(list(files.items()))))
    first_findings = rule_result(first, "ARCH-CIRCULAR-DEPENDENCY").findings
    second_findings = rule_result(second, "ARCH-CIRCULAR-DEPENDENCY").findings
    assert len(first_findings) == len(second_findings) == 1
    assert first_findings[0].description == second_findings[0].description
    assert first_findings[0].identity_key == second_findings[0].identity_key


def test_fan_out_small_listing_is_complete() -> None:
    """FND-04: below the display limit, every neighbor is listed plainly."""
    result, _, _ = analyze_arch(
        {f"leaf{i}.py": "X = 1\n" for i in range(8)}
        | {"hub.py": "".join(f"import leaf{i}\n" for i in range(8))}
    )
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    for i in range(8):
        assert f"- leaf{i}.py (hub.py:{i + 1})" in finding.description
    assert "Showing the first" not in finding.description


def test_fan_out_large_listing_is_bounded_and_disclosed() -> None:
    """FND-04: 25 neighbors show the first 20 with exact totals stated."""
    leaves = {f"leaf{i:02d}.py": "X = 1\n" for i in range(25)}
    result, _, _ = analyze_arch(
        leaves | {"hub.py": "".join(f"import leaf{i:02d}\n" for i in range(25))}
    )
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert "Showing the first 20 of 25 outgoing neighbors." in finding.description
    assert "- leaf00.py (hub.py:1)" in finding.description
    assert "- leaf19.py (hub.py:20)" in finding.description
    assert "leaf20.py" not in finding.description
    assert len(finding.description) < 4000


def test_fan_out_bounded_description_stable_under_reorder() -> None:
    """FND-04: the displayed subset does not depend on input order."""
    leaves = {f"leaf{i:02d}.py": "X = 1\n" for i in range(25)}
    files = leaves | {"hub.py": "".join(f"import leaf{i:02d}\n" for i in range(25))}
    first, _, _ = analyze_arch(files)
    second, _, _ = analyze_arch(dict(reversed(list(files.items()))))
    first_description = rule_result(first, "ARCH-HIGH-FAN-OUT").findings[0].description
    second_description = rule_result(second, "ARCH-HIGH-FAN-OUT").findings[0].description
    assert first_description == second_description


def test_fan_out_metric_value_stays_exact() -> None:
    """FND-04: presentation bounds never change the computed metric."""
    leaves = {f"leaf{i:02d}.py": "X = 1\n" for i in range(25)}
    result, _, _ = analyze_arch(
        leaves | {"hub.py": "".join(f"import leaf{i:02d}\n" for i in range(25))}
    )
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert "depends on 25 distinct internal modules" in finding.description
    assert finding.applied_thresholds == (("fan_out", 7),)


def test_relationship_sites_are_bounded() -> None:
    """FND-04: one edge with seven sites shows five plus a remainder."""
    source = "".join("import leaf0\n" for _ in range(7)) + "".join(
        f"import leaf{i}\n" for i in range(1, 8)
    )
    result, _, _ = analyze_arch({"hub.py": source, **{f"leaf{i}.py": "X = 1\n" for i in range(8)}})
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert "(+2 more)" in finding.description
    assert "leaf0.py" in finding.description


def test_coupling_listing_bounded_with_totals() -> None:
    """FND-04: coupling blocks state displayed and true totals."""
    leaves = {f"leaf{i:02d}.py": "X = 1\n" for i in range(25)}
    result, _, _ = analyze_arch(
        leaves | {"hub.py": "".join(f"import leaf{i:02d}\n" for i in range(25))}
    )
    (finding,) = rule_result(result, "ARCH-HIGH-COUPLING").findings
    assert "Showing the first 20 of 25 outgoing neighbors." in finding.description
    assert "coupling-def-1 25" in finding.description
    assert len(finding.description) < 4000


def test_fan_in_listing_bounded_with_totals() -> None:
    """FND-04: incoming listings follow the same bounded contract."""
    files = {f"user{i:02d}.py": "import shared\n" for i in range(25)}
    result, _, _ = analyze_arch(files | {"shared.py": "X = 1\n"})
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-IN").findings
    assert "Showing the first 20 of 25 incoming neighbors." in finding.description
    assert "depended on by 25 distinct internal modules" in finding.description


def test_bounded_descriptions_serialize_fully_and_redacted() -> None:
    """FND-04: serialization keeps every edge; findings stay redacted."""
    from tests.fixtures.helpers.architecture_helpers import graph_for

    secret = 'password = "FAKE-BOUNDED-PASSWORD-NOT-REAL-1"\n'
    leaves = {f"leaf{i:02d}.py": "X = 1\n" for i in range(25)}
    files = leaves | {"hub.py": secret + "".join(f"import leaf{i:02d}\n" for i in range(25))}
    result, _, _ = analyze_arch(files)
    (finding,) = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert "FAKE-BOUNDED-PASSWORD-NOT-REAL-1" not in finding.description
    if finding.evidence is not None:
        assert all(
            "FAKE-BOUNDED-PASSWORD-NOT-REAL-1" not in line for line in finding.evidence.lines
        )
    report = graph_for(files)
    assert len(report.graph.edges) == 25
