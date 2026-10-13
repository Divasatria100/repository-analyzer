"""Cycle detection tests (TASK-128).

Iterative Tarjan SCCs: one group per mutually reachable set, canonical
single-path evidence, self-loops distinguished, insertion-order independent.
"""

from app.analyzers.architecture.cycles import find_cycles, strongly_connected_components
from tests.fixtures.helpers.architecture_helpers import graph_for


def _members(files: dict[str, str]) -> list[tuple[str, ...]]:
    return [group.members for group in find_cycles(graph_for(files).graph)]


def test_simple_two_module_cycle() -> None:
    groups = find_cycles(graph_for({"a.py": "import b\n", "b.py": "import a\n"}).graph)
    assert len(groups) == 1
    (group,) = groups
    assert group.members == ("a.py", "b.py")
    assert group.path[0] == group.path[-1] == "a.py"  # canonical rotation
    assert group.self_loop is False


def test_acyclic_graph_has_no_cycles() -> None:
    assert _members({"a.py": "import b\n", "b.py": "X = 1\n"}) == []


def test_multiple_disconnected_cycles_stay_separate() -> None:
    files = {
        "a.py": "import b\n",
        "b.py": "import a\n",
        "c.py": "import d\n",
        "d.py": "import c\n",
    }
    assert _members(files) == [("a.py", "b.py"), ("c.py", "d.py")]


def test_overlapping_cycles_share_one_group() -> None:
    """Figure-eight through one hub is one mutually reachable group."""
    files = {
        "a.py": "import b\nimport c\n",
        "b.py": "import a\n",
        "c.py": "import a\n",
    }
    groups = find_cycles(graph_for(files).graph)
    assert len(groups) == 1
    assert groups[0].members == ("a.py", "b.py", "c.py")


def test_self_loop_is_single_node_cycle() -> None:
    (group,) = find_cycles(graph_for({"a.py": "import a\n"}).graph)
    assert group.members == ("a.py",)
    assert group.path == ("a.py", "a.py")
    assert group.self_loop is True


def test_no_rotation_duplicates() -> None:
    files = {"a.py": "import b\n", "b.py": "import c\n", "c.py": "import a\n"}
    groups = find_cycles(graph_for(files).graph)
    assert len(groups) == 1
    assert groups[0].path == ("a.py", "b.py", "c.py", "a.py")


def test_reordered_insertion_same_result() -> None:
    files = {"a.py": "import b\n", "b.py": "import c\n", "c.py": "import a\n"}
    first = find_cycles(graph_for(files).graph)
    second = find_cycles(graph_for(dict(reversed(list(files.items())))).graph)
    assert [(g.members, g.path) for g in first] == [(g.members, g.path) for g in second]


def test_scc_sizes_and_sorting() -> None:
    files = {
        "z.py": "import y\n",
        "y.py": "import z\n",
        "m.py": "import n\n",
        "n.py": "import m\n",
        "solo.py": "X = 1\n",
    }
    components = strongly_connected_components(graph_for(files).graph)
    assert ["m.py", "n.py"] in components
    assert ["y.py", "z.py"] in components
    assert ["solo.py"] in components
    assert components == sorted(components)


def test_cycle_path_uses_real_edges() -> None:
    files = {"a.py": "import b\n", "b.py": "import c\n", "c.py": "import a\n"}
    report = graph_for(files)
    (group,) = find_cycles(report.graph)
    for step in range(len(group.path) - 1):
        assert (group.path[step], group.path[step + 1]) in report.graph.edges


def test_large_sparse_graph_stays_bounded() -> None:
    files = {f"m{i}.py": f"import m{i + 1}\n" for i in range(200)}
    files["m200.py"] = "X = 1\n"
    groups = find_cycles(graph_for(files).graph)
    assert groups == []
