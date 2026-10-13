"""Architecture graph tests (TASK-124).

Direction is frozen: importing module → imported module. Edges deduplicate
per ordered pair while preserving every establishing site; external and
unresolved references never become edges; budgets truncate deterministically
with recorded incompleteness.
"""

from app.analyzers.architecture.graph import GRAPH_MAX_EDGES, GRAPH_MAX_NODES, build_graph
from tests.fixtures.helpers.architecture_helpers import graph_for
from tests.fixtures.helpers.security_helpers import parse_files


def test_edge_direction_importer_to_imported() -> None:
    report = graph_for({"a.py": "import b\n", "b.py": "X = 1\n"})
    assert set(report.graph.edges) == {("a.py", "b.py")}
    assert report.graph.successors("a.py") == ("b.py",)
    assert report.graph.predecessors("b.py") == ("a.py",)
    assert report.graph.successors("b.py") == ()


def test_duplicate_imports_are_one_edge_with_all_sites() -> None:
    report = graph_for({"a.py": "import b\nimport b\nfrom b import X\n", "b.py": "X = 1\n"})
    assert set(report.graph.edges) == {("a.py", "b.py")}
    edge = report.graph.edges[("a.py", "b.py")]
    assert len(edge.locations) == 3


def test_relative_import_resolves_within_package() -> None:
    report = graph_for(
        {
            "pkg/__init__.py": "",
            "pkg/core.py": "from .helpers import run\n",
            "pkg/helpers.py": "X = 1\n",
        }
    )
    assert ("pkg/core.py", "pkg/helpers.py") in report.graph.edges


def test_relative_bare_import_resolves_sibling() -> None:
    report = graph_for(
        {"pkg/__init__.py": "from .core import run\n", "pkg/core.py": "def run(): ...\n"}
    )
    assert ("pkg/__init__.py", "pkg/core.py") in report.graph.edges


def test_from_package_import_prefers_submodule() -> None:
    report = graph_for(
        {
            "pkg/__init__.py": "VALUE = 1\n",
            "pkg/sub.py": "Y = 2\n",
            "user.py": "from pkg import sub\n",
        }
    )
    assert ("user.py", "pkg/sub.py") in report.graph.edges


def test_from_package_import_falls_back_to_initializer() -> None:
    report = graph_for({"pkg/__init__.py": "VALUE = 1\n", "user.py": "from pkg import VALUE\n"})
    assert ("user.py", "pkg/__init__.py") in report.graph.edges


def test_external_imports_never_become_edges() -> None:
    report = graph_for({"app.py": "import os\nimport sys\nimport requests\n"})
    assert report.graph.edges == {}
    assert report.external_count == 2  # os, sys (stdlib)
    # Third-party absolute imports are unresolved, never internal edges.
    assert len(report.unresolved) == 1
    assert report.unresolved[0].target_text == "requests"


def test_unresolved_imports_recorded_not_converted() -> None:
    report = graph_for({"app.py": "import missing_lib\nfrom ghost import thing\n"})
    assert report.graph.edges == {}
    assert len(report.unresolved) == 2
    assert all(item.reason == "unresolved" for item in report.unresolved)
    assert any("potentially incomplete" in reason for reason in report.limitation_reasons)


def test_self_import_is_preserved_edge() -> None:
    report = graph_for({"a.py": "import a\n"})
    assert ("a.py", "a.py") in report.graph.edges
    assert report.graph.has_self_loop("a.py") is True
    # Self-loops carry no inter-module information for neighbor metrics.
    assert report.graph.successors("a.py") == ()
    assert report.graph.predecessors("a.py") == ()


def test_graph_is_deterministic_regardless_of_insertion() -> None:
    files = {"c.py": "import a\n", "b.py": "import a\nimport c\n", "a.py": "X = 1\n"}
    first = graph_for(files)
    second = graph_for(dict(reversed(list(files.items()))))
    assert [e.source for e in first.graph.sorted_edges()] == [
        e.source for e in second.graph.sorted_edges()
    ]
    assert [(e.source, e.target) for e in first.graph.sorted_edges()] == [
        ("b.py", "a.py"),
        ("b.py", "c.py"),
        ("c.py", "a.py"),
    ]


def test_node_budget_truncates_with_record() -> None:
    files = {f"m{i}.py": "X = 1\n" for i in range(5)}
    report = build_graph(parse_files(files), max_nodes=3)
    assert len(report.graph.nodes) == 3
    assert report.graph.truncated is True
    assert report.limited is True
    assert any("node budget" in reason for reason in report.limitation_reasons)


def test_edge_budget_truncates_with_record() -> None:
    files = {"hub.py": "import a\nimport b\nimport c\n", "a.py": "", "b.py": "", "c.py": ""}
    report = build_graph(parse_files(files), max_edges=2)
    assert len(report.graph.edges) == 2
    assert report.graph.truncated is True
    assert any("edge budget" in reason for reason in report.limitation_reasons)


def test_budgets_mirror_operational_settings() -> None:
    from app.core.config import OperationalSettings

    assert GRAPH_MAX_NODES == OperationalSettings().graph_max_nodes == 10000
    assert GRAPH_MAX_EDGES == OperationalSettings().graph_max_edges == 50000


class _CountingEdges(dict):
    """Edge collection counting full iterations (structural cost probe)."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.iterations = 0

    def __iter__(self):  # type: ignore[no-untyped-def]
        self.iterations += 1
        return super().__iter__()


def test_frozen_index_serves_neighbors_without_edge_scans() -> None:
    """FND-03: metric sweeps over all nodes trigger zero full edge scans."""
    from app.analyzers.architecture.metrics import coupling_def_1, fan_in, fan_out

    report = graph_for({"hub.py": "import a\nimport b\n", "a.py": "X = 1\n", "b.py": "X = 1\n"})
    assert report.graph.index_frozen is True
    expected = {
        path: (
            fan_out(report.graph, path).value,
            fan_in(report.graph, path).value,
            coupling_def_1(report.graph, path).value,
        )
        for path in sorted(report.graph.nodes)
    }
    report.graph.edges = _CountingEdges(report.graph.edges)
    counting = report.graph.edges
    assert isinstance(counting, _CountingEdges)
    for path in sorted(report.graph.nodes):
        assert (
            fan_out(report.graph, path).value,
            fan_in(report.graph, path).value,
            coupling_def_1(report.graph, path).value,
        ) == expected[path]
        assert report.graph.successors(path) == report.graph.successors(path)
        assert report.graph.predecessors(path) == report.graph.predecessors(path)
    assert counting.iterations == 0


def test_cycles_use_shared_index_without_rescanning() -> None:
    """FND-03: Tarjan and path walks reuse the index (no per-node scans)."""
    from app.analyzers.architecture.cycles import find_cycles

    report = graph_for({"a.py": "import b\n", "b.py": "import a\n"})
    report.graph.edges = _CountingEdges(report.graph.edges)
    counting = report.graph.edges
    assert isinstance(counting, _CountingEdges)
    groups = find_cycles(report.graph)
    assert len(groups) == 1
    assert counting.iterations == 0


def test_unfrozen_graph_falls_back_with_identical_results() -> None:
    """FND-03: directly constructed graphs keep working without an index."""
    from app.analyzers.architecture.metrics import coupling_def_1, fan_in, fan_out
    from app.analyzers.architecture.models import ArchEdge, ArchGraph, ArchModule

    edges = {
        ("a.py", "b.py"): ArchEdge(source="a.py", target="b.py", locations=(("a.py", 1, 0),)),
        ("b.py", "a.py"): ArchEdge(source="b.py", target="a.py", locations=(("b.py", 1, 0),)),
    }
    nodes = {path: ArchModule(id=path, path=path) for path in ("a.py", "b.py")}
    graph = ArchGraph(nodes=nodes, edges=dict(edges))
    assert graph.index_frozen is False
    assert fan_out(graph, "a.py").value == 1
    assert fan_in(graph, "a.py").value == 1
    assert coupling_def_1(graph, "a.py").value == 1
    graph.freeze_index()
    assert graph.index_frozen is True
    assert fan_out(graph, "a.py").value == 1
    assert fan_in(graph, "a.py").value == 1
    assert coupling_def_1(graph, "a.py").value == 1


def test_index_identical_under_reordered_construction() -> None:
    """FND-03: the frozen index does not depend on insertion order."""
    files = {"c.py": "import a\n", "b.py": "import a\nimport c\n", "a.py": "X = 1\n"}
    first = graph_for(files)
    second = graph_for(dict(reversed(list(files.items()))))
    assert first.graph._successor_index == second.graph._successor_index
    assert first.graph._predecessor_index == second.graph._predecessor_index


def test_large_sparse_graph_single_pass_index() -> None:
    """FND-03: a 2000-node chain builds one index; sweeps scan nothing."""
    from app.analyzers.architecture.metrics import coupling_def_1, fan_in, fan_out
    from app.analyzers.architecture.models import ArchEdge, ArchGraph, ArchModule

    size = 2000
    nodes = {f"m{i}.py": ArchModule(id=f"m{i}.py", path=f"m{i}.py") for i in range(size)}
    edges = {
        (f"m{i}.py", f"m{i + 1}.py"): ArchEdge(
            source=f"m{i}.py", target=f"m{i + 1}.py", locations=((f"m{i}.py", 1, 0),)
        )
        for i in range(size - 1)
    }
    graph = ArchGraph(nodes=nodes, edges=_CountingEdges(edges))
    counting = graph.edges
    assert isinstance(counting, _CountingEdges)
    built = counting.iterations
    graph.freeze_index()
    # One bounded pass over edges for the index itself.
    assert counting.iterations - built <= 2
    for i in (0, size // 2, size - 1):
        assert fan_out(graph, f"m{i}.py").value == (0 if i == size - 1 else 1)
        assert fan_in(graph, f"m{i}.py").value == (0 if i == 0 else 1)
        assert coupling_def_1(graph, f"m{i}.py").value == (1 if i in (0, size - 1) else 2)
    after = counting.iterations
    for i in range(size):
        fan_out(graph, f"m{i}.py")
        fan_in(graph, f"m{i}.py")
        coupling_def_1(graph, f"m{i}.py")
    assert counting.iterations == after


def test_truncated_graph_keeps_frozen_index_and_flag() -> None:
    """FND-03: truncation still freezes a consistent, flagged index."""
    files = {f"m{i}.py": "X = 1\n" for i in range(5)}
    report = build_graph(parse_files(files), max_nodes=3)
    assert report.graph.index_frozen is True
    assert report.graph.truncated is True
    assert report.graph.successors("m0.py") == ()
