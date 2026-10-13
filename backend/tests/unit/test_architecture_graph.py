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
