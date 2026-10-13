"""Architecture metric tests (TASK-125/126/127).

Fan-in/out count distinct neighbors; coupling-def-1 is the union size;
sizes use strict `>` with exact-boundary coverage; complexity is an
NCM-derived lower bound with a documented basis.
"""

import pytest

from app.analyzers.architecture.metrics import (
    COMPLEXITY_BASIS,
    class_line_count,
    class_method_count,
    coupling_def_1,
    fan_in,
    fan_out,
    function_complexity_lower_bound,
    function_line_count,
    module_declaration_count,
    module_line_count,
)
from tests.fixtures.helpers.architecture_helpers import graph_for
from tests.fixtures.helpers.security_helpers import parse_files


def _degrees(files: dict[str, str], module: str) -> tuple[int, int, int]:
    report = graph_for(files)
    return (
        fan_out(report.graph, module).value or 0,
        fan_in(report.graph, module).value or 0,
        coupling_def_1(report.graph, module).value or 0,
    )


def test_zero_degrees_for_isolated_module() -> None:
    assert _degrees({"solo.py": "X = 1\n"}, "solo.py") == (0, 0, 0)


def test_single_dependency_counts_once() -> None:
    assert _degrees({"a.py": "import b\nimport b\n", "b.py": "X = 1\n"}, "a.py") == (1, 0, 1)


def test_multiple_distinct_dependencies() -> None:
    files = {"hub.py": "import a\nimport b\nimport c\n", "a.py": "", "b.py": "", "c.py": ""}
    assert _degrees(files, "hub.py") == (3, 0, 3)
    assert _degrees(files, "a.py") == (0, 1, 1)


def test_fan_directions_are_not_reversed() -> None:
    """A module importing others has fan-out, not fan-in, and vice versa."""
    files = {"a.py": "import b\n", "b.py": "X = 1\n"}
    out_a, in_a, _ = _degrees(files, "a.py")
    out_b, in_b, _ = _degrees(files, "b.py")
    assert (out_a, in_a) == (1, 0)
    assert (out_b, in_b) == (0, 1)


def test_coupling_union_counts_overlap_once() -> None:
    """A -> B, B -> A, C -> B: In(B)={A,C}, Out(B)={A}, union is 2 not 3."""
    files = {"a.py": "import b\n", "b.py": "import a\n", "c.py": "import b\n"}
    assert _degrees(files, "b.py") == (1, 2, 2)
    assert _degrees(files, "a.py") == (1, 1, 1)


def test_self_loop_excluded_from_degrees() -> None:
    assert _degrees({"a.py": "import a\n"}, "a.py") == (0, 0, 0)


def test_module_size_boundaries() -> None:
    from app.analyzers.thresholds import default_thresholds

    thresholds = default_thresholds()
    assert thresholds.module_lines == 500
    assert thresholds.module_declarations == 30

    def declarations(n_classes: int, n_functions: int) -> int:
        body = "\n".join(f"class C{i}:\n    pass" for i in range(n_classes))
        body += "\n" + "\n".join(f"def f{i}():\n    pass" for i in range(n_functions))
        (module,) = parse_files({"m.py": body + "\n"}).modules
        return module_declaration_count(module)

    assert declarations(0, 30) == 30  # equal: no fire
    assert declarations(0, 31) == 31  # above: fires
    assert declarations(10, 21) == 31


def test_module_lines_use_physical_source_length() -> None:
    (module,) = parse_files({"m.py": "import os\n\n\nX = 1  # comment\n"}).modules
    assert module_line_count(module, ("import os", "", "", "X = 1  # comment")) == 4


def test_class_size_boundaries() -> None:
    from app.analyzers.thresholds import default_thresholds

    thresholds = default_thresholds()
    assert thresholds.class_lines == 200
    assert thresholds.class_methods == 10

    def make_class(n_methods: int, n_body_lines: int) -> object:
        methods = "\n".join(f"    def m{i}(self):\n        return {i}" for i in range(n_methods))
        filler = "\n".join(f"    step_{i} = {i}" for i in range(n_body_lines))
        source = f"class Big:\n{methods}\n{filler}\n" if methods else f"class Big:\n{filler}\n"
        (module,) = parse_files({"m.py": source}).modules
        return module, module.classes[0]

    module, cls = make_class(10, 0)
    assert class_method_count(module, cls) == 10  # equal: no fire
    module, cls = make_class(11, 0)
    assert class_method_count(module, cls) == 11  # above: fires
    module, cls = make_class(0, 199)
    assert class_line_count(cls) == 200  # class header + 199 = 200: no fire
    module, cls = make_class(0, 200)
    assert class_line_count(cls) == 201  # above: fires


def test_function_size_boundaries() -> None:
    from app.analyzers.thresholds import default_thresholds

    thresholds = default_thresholds()
    assert thresholds.function_lines == 50
    assert thresholds.function_complexity == 10

    def make_function(n_lines: int) -> object:
        from tests.fixtures.helpers.architecture_helpers import lines_of

        source = f"def work():\n{lines_of(n_lines, indent='    ')}\n"
        (module,) = parse_files({"m.py": source}).modules
        return module, module.functions[0]

    module, fun = make_function(49)
    assert function_line_count(fun) == 50  # def + 49 = 50: no fire
    module, fun = make_function(50)
    assert function_line_count(fun) == 51  # above: fires


def test_complexity_lower_bound_counts_decisions() -> None:
    source = (
        "def work(x):\n"
        "    if x:\n"
        "        return 1\n"
        "    for i in range(3):\n"
        "        print(i)\n"
        "    while x:\n"
        "        break\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    (module,) = parse_files({"m.py": source}).modules
    (fun,) = module.functions
    metric = function_complexity_lower_bound(module, fun)
    assert metric.value == 5  # 1 + if + for + while + except
    assert metric.potentially_incomplete is True
    assert "lower bound" in metric.basis
    assert COMPLEXITY_BASIS in metric.basis


def test_complexity_boundary_values() -> None:
    branches = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(9))
    (module,) = parse_files({"m.py": f"def work(x):\n{branches}    return -1\n"}).modules
    (fun,) = module.functions
    assert function_complexity_lower_bound(module, fun).value == 10  # equal: no fire
    branches = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(10))
    (module,) = parse_files({"m.py": f"def work(x):\n{branches}    return -1\n"}).modules
    (fun,) = module.functions
    assert function_complexity_lower_bound(module, fun).value == 11  # fires


def test_complexity_missing_operators_documented() -> None:
    """Boolean operators are not in NCM: the bound understates honestly."""
    source = "def work(a, b):\n    return a and b or a\n"
    (module,) = parse_files({"m.py": source}).modules
    (fun,) = module.functions
    assert function_complexity_lower_bound(module, fun).value == 1
    assert function_complexity_lower_bound(module, fun).potentially_incomplete is True


@pytest.mark.parametrize("start,end,expected", [(1, 1, 1), (5, 10, 6), (3, 2, None), (0, 4, None)])
def test_span_edge_cases(start: int, end: int, expected: int | None) -> None:
    from app.analyzers.architecture.metrics import _span_lines

    assert _span_lines(start, end) == expected
