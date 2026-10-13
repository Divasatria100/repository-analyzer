"""Multiple-responsibility signal tests (TASK-130).

Candidates need signals from more than one category and are always
potential structures with Low confidence — never verdicts.
"""

from app.analyzers.architecture.responsibility import (
    ResponsibilitySignal,
    build_candidate,
    is_candidate,
)
from tests.fixtures.helpers.architecture_helpers import analyze_arch, rule_result


def _size(text: str) -> ResponsibilitySignal:
    return ResponsibilitySignal(category="size", description=text)


def _breadth(text: str) -> ResponsibilitySignal:
    return ResponsibilitySignal(category="dependency_breadth", description=text)


def test_single_category_is_not_candidate() -> None:
    assert is_candidate([_size("big"), _size("huge")]) is False
    assert is_candidate([]) is False


def test_two_categories_are_candidate() -> None:
    assert is_candidate([_size("big"), _breadth("wide")]) is True


def test_candidate_orders_signals_deterministically() -> None:
    first = build_candidate("m.py", [_breadth("b"), _size("a")])
    second = build_candidate("m.py", [_size("a"), _breadth("b")])
    assert first == second
    assert first.categories == ("dependency_breadth", "size")


def test_clear_candidate_through_analyzer() -> None:
    hub_imports = "\n".join(f"import leaf{i}" for i in range(8))
    leaves = {f"leaf{i}.py": "X = 1\n" for i in range(8)}
    big_class = "class God:\n" + "\n".join(
        f"    def m{i}(self):\n        return {i}" for i in range(11)
    )
    result, _, _ = analyze_arch({"hub.py": f"{hub_imports}\n{big_class}\n", **leaves})
    findings = rule_result(result, "ARCH-MULTIPLE-RESPONSIBILITY").findings
    assert len(findings) == 1
    (finding,) = findings
    assert "hub.py" in finding.title
    assert finding.severity.value == "Low"
    assert finding.confidence.value == "Low"
    assert "potential" in finding.description.lower()
    assert "more than one category" in finding.description


def test_non_candidate_has_no_finding() -> None:
    result, _, _ = analyze_arch({"tiny.py": "X = 1\n"})
    assert rule_result(result, "ARCH-MULTIPLE-RESPONSIBILITY").findings == ()


def test_large_only_is_insufficient_evidence() -> None:
    """Size alone (one category) never produces a candidate."""
    from app.analyzers.architecture.metrics import module_declaration_count
    from app.analyzers.architecture.responsibility import collect_signals
    from app.analyzers.thresholds import default_thresholds
    from tests.fixtures.helpers.architecture_helpers import graph_for
    from tests.fixtures.helpers.security_helpers import parse_files

    body = "\n".join(f"def f{i}():\n    pass" for i in range(31))
    (module,) = parse_files({"big.py": body + "\n"}).modules
    assert module_declaration_count(module) == 31
    report = graph_for({"big.py": body + "\n"})
    signals = collect_signals(
        module_path="big.py",
        module=module,
        fan_out_value=0,
        coupling_value=0,
        large_module=True,
        large_class_names=(),
        large_functions=(),
        complex_functions=(),
        thresholds=default_thresholds(),
    )
    assert {signal.category for signal in signals} == {"size"}
    assert is_candidate(signals) is False
    _ = report
