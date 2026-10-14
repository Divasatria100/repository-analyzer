"""Measurement tests: complexity, nesting, parameters (TASK-135/136/137)."""

import pytest

from app.analyzers.code_structure.measurements import (
    COMPLEXITY_BASIS,
    NESTING_BASIS,
    PARAMETER_BASIS,
    mccabe_complexity,
    nesting_depth,
    parameter_count,
)
from tests.fixtures.helpers.code_structure_helpers import decision_body, nested_body, sig_function
from tests.fixtures.helpers.security_helpers import parse_files


def _function(files: dict[str, str], path: str = "m.py", index: int = 0):  # type: ignore[no-untyped-def]
    (module,) = parse_files(files).modules
    return module, module.functions[index]


def test_complexity_no_decisions_is_one() -> None:
    module, fun = _function({"m.py": "def work():\n    return 1\n"})
    metric = mccabe_complexity(module, fun)
    assert metric.measurement.value == 1
    assert metric.decisions == ()
    assert "lower bound" in metric.measurement.basis
    assert COMPLEXITY_BASIS in metric.measurement.basis


def test_complexity_single_decision() -> None:
    module, fun = _function({"m.py": "def work(x):\n    if x:\n        return 1\n    return 0\n"})
    metric = mccabe_complexity(module, fun)
    assert metric.measurement.value == 2
    assert [(point.kind, point.line) for point in metric.decisions] == [("if", 2)]


def test_complexity_counts_each_kind_once() -> None:
    source = (
        "def work(x):\n"
        "    if x:\n"
        "        return 1\n"
        "    elif x > 1:\n"
        "        return 2\n"
        "    for i in range(3):\n"
        "        print(i)\n"
        "    while x:\n"
        "        x -= 1\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError:\n"
        "        pass\n"
        "    except TypeError:\n"
        "        pass\n"
        "    return 0\n"
    )
    module, fun = _function({"m.py": source})
    metric = mccabe_complexity(module, fun)
    # 1 + if + elif(if) + for + while + except + except = 7.
    assert metric.measurement.value == 7
    assert sorted(point.kind for point in metric.decisions) == [
        "except",
        "except",
        "for",
        "if",
        "if",
        "while",
    ]


def test_complexity_nested_and_sequential() -> None:
    module, fun = _function({"m.py": f"def work(x):\n{decision_body(3)}"})
    assert mccabe_complexity(module, fun).measurement.value == 4
    module, fun = _function(
        {"m.py": "def work(x):\n    if x:\n        if y:\n            return 1\n    return 0\n"}
    )
    assert mccabe_complexity(module, fun).measurement.value == 3


def test_complexity_boundary_10_silent_11_fires() -> None:
    module, fun = _function({"m.py": f"def work(x):\n{decision_body(9)}"})
    assert mccabe_complexity(module, fun).measurement.value == 10
    module, fun = _function({"m.py": f"def work(x):\n{decision_body(10)}"})
    assert mccabe_complexity(module, fun).measurement.value == 11


def test_complexity_missing_constructs_documented() -> None:
    """Boolean ops/ternary/comprehensions/asserts are not NCM decisions."""
    module, fun = _function({"m.py": "def work(a, b):\n    return a and b or (1 if a else 2)\n"})
    metric = mccabe_complexity(module, fun)
    assert metric.measurement.value == 1
    assert metric.measurement.potentially_incomplete is True


def test_complexity_nested_functions_measured_separately() -> None:
    source = (
        "def outer():\n    if a:\n        pass\n    def inner():\n        if b:\n            pass\n"
    )
    module, _ = _function({"m.py": source})
    by_name = {fun.qualified_name: fun for fun in module.functions}
    assert mccabe_complexity(module, by_name["m.outer"]).measurement.value == 2
    assert mccabe_complexity(module, by_name["m.outer.inner"]).measurement.value == 2


def test_complexity_methods_use_function_scope() -> None:
    source = (
        "class C:\n    def m(self, x):\n        if x:\n            return 1\n        return 0\n"
    )
    module, fun = _function({"m.py": source})
    assert fun.kind == "method"
    assert mccabe_complexity(module, fun).measurement.value == 2


def test_nesting_zero_without_control() -> None:
    module, fun = _function({"m.py": "def work():\n    return 1\n"})
    metric = nesting_depth(module, fun)
    assert metric.measurement.value == 0
    assert metric.measurement.basis == NESTING_BASIS


def test_nesting_single_level() -> None:
    module, fun = _function({"m.py": "def work(x):\n    if x:\n        return 1\n    return 0\n"})
    metric = nesting_depth(module, fun)
    assert metric.measurement.value == 1
    assert (metric.deepest_path, metric.deepest_line) == ("m.py", 2)


def test_nesting_sequential_does_not_accumulate() -> None:
    module, fun = _function({"m.py": f"def work(x):\n{decision_body(4)}"})
    assert nesting_depth(module, fun).measurement.value == 1


@pytest.mark.parametrize("depth", [2, 3, 4, 5, 6])
def test_nesting_depth_values(depth: int) -> None:
    module, fun = _function({"m.py": f"def work(x):\n{nested_body(depth)}"})
    assert nesting_depth(module, fun).measurement.value == depth


def test_nesting_with_try_except_same_level() -> None:
    """Handlers sit level with their try body; nested content goes deeper."""
    source = (
        "def work():\n"
        "    try:\n"
        "        if a:\n"
        "            pass\n"
        "    except ValueError:\n"
        "        if b:\n"
        "            pass\n"
    )
    module, fun = _function({"m.py": source})
    assert nesting_depth(module, fun).measurement.value == 2


def test_nesting_with_statement_counts() -> None:
    module, fun = _function(
        {"m.py": "def work():\n    with open('f') as fh:\n        return fh.read()\n"}
    )
    assert nesting_depth(module, fun).measurement.value == 1


def test_nesting_nested_function_adds_level() -> None:
    source = "def outer():\n    def inner():\n        if x:\n            pass\n"
    module, _ = _function({"m.py": source})
    by_name = {fun.qualified_name: fun for fun in module.functions}
    assert nesting_depth(module, by_name["m.outer"]).measurement.value == 1
    assert nesting_depth(module, by_name["m.outer.inner"]).measurement.value == 1


def test_nesting_class_body_hierarchy_ignored() -> None:
    """A method's depth comes from control flow, not the enclosing class."""
    source = "class C:\n    def m(self):\n        if x:\n            pass\n"
    module, fun = _function({"m.py": source})
    assert nesting_depth(module, fun).measurement.value == 1


def test_nesting_empty_function_is_zero() -> None:
    module, fun = _function({"m.py": "def work():\n    pass\n"})
    assert nesting_depth(module, fun).measurement.value == 0


def test_nesting_match_does_not_add_depth() -> None:
    """`match` is not a listed depth construct; its arms sit at its level."""
    source = (
        "def work(x):\n    match x:\n        case 1:\n            if y:\n                pass\n"
    )
    module, fun = _function({"m.py": source})
    assert nesting_depth(module, fun).measurement.value == 1


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("", 0),
        ("x", 1),
        ("a, b, c, d, e", 5),
        ("a, b, c, d, e, f", 6),
        ("a, b=1, c='x'", 3),
        ("*args", 1),
        ("**kwargs", 1),
        ("a, *args, **kwargs", 3),
        ("a, *, key", 2),
        ("a, *, key=None", 2),
    ],
)
def test_parameter_counts(signature: str, expected: int) -> None:
    module, fun = _function({"m.py": sig_function(signature)})
    metric = parameter_count("m.py", fun)
    assert metric.value == expected
    assert metric.path == "m.py"
    assert metric.basis == PARAMETER_BASIS


def test_parameter_self_cls_excluded_for_methods() -> None:
    module, fun = _function({"m.py": "class C:\n    def m(self, a, b):\n        pass\n"})
    assert parameter_count("m.py", fun).value == 2
    module, fun = _function(
        {"m.py": "class C:\n    @classmethod\n    def m(cls, a):\n        pass\n"}
    )
    assert parameter_count("m.py", fun).value == 1


def test_parameter_self_named_function_kept() -> None:
    """A top-level function whose first parameter is named `self` still counts it."""
    module, fun = _function({"m.py": "def work(self, a):\n    pass\n"})
    assert fun.kind == "function"
    assert parameter_count("m.py", fun).value == 2


def test_parameter_boundary_five_silent_six_fires() -> None:
    from app.analyzers.thresholds import default_thresholds

    assert default_thresholds().parameters == 5
    module, fun = _function({"m.py": sig_function("a, b, c, d, e")})
    assert parameter_count("m.py", fun).value == 5
    module, fun = _function({"m.py": sig_function("a, b, c, d, e, f")})
    assert parameter_count("m.py", fun).value == 6
