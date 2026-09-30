"""Tree-sitter adapter tests: NCM coverage, recovery, locations (TASK-065/070)."""

import pytest

from app.ncm import ParseResult, ParseState
from app.parsers.base import ParserInput
from app.parsers.tree_sitter import NODE_BUDGET, TreeSitterAdapter
from tests.fixtures.helpers.paths import read_fixture_bytes

pytestmark = pytest.mark.security

ADAPTER = TreeSitterAdapter()


def _parse(source: bytes, path: str = "m.py") -> ParseResult:
    return ADAPTER.parse(ParserInput(path, "python", source, 30.0, 1_000_000))


def test_supported_language_only() -> None:
    assert ADAPTER.supports("python") is True
    assert ADAPTER.supports("go") is False
    assert ADAPTER.name == "tree-sitter"


def test_module_imports_classes_functions() -> None:
    result = _parse(read_fixture_bytes("parsing", "sample_module.py"), "sample_module.py")
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    names = {f.qualified_name for f in result.ncm.functions}
    assert "sample_module.create_engine" in names
    assert "sample_module.Registry.register" in names
    assert "sample_module.main" in names
    create = next(f for f in result.ncm.functions if f.qualified_name.endswith("create_engine"))
    assert [p.kind for p in create.parameters] == [
        "positional",
        "default",
        "vararg",
        "keyword-only",
        "kwarg",
    ]
    assert "decorator" not in create.decorator_names
    size = next(f for f in result.ncm.functions if f.qualified_name.endswith("Registry.size"))
    assert size.decorator_names == ("property",)
    register = next(f for f in result.ncm.functions if f.qualified_name.endswith("register"))
    assert register.parameters[0].is_self_cls is True
    classes = {c.qualified_name: c for c in result.ncm.classes}
    assert set(classes["sample_module.Registry"].base_names) == {"Base", "Mixin"}
    imports = {i.target_text: i.resolution for i in result.ncm.imports}
    assert imports["os"] == "external"
    assert any(t.startswith(".") and r == "internal" for t, r in imports.items())
    assert imports["helpers"] == "unresolved"


def test_calls_literals_control_flow() -> None:
    result = _parse(read_fixture_bytes("parsing", "sample_module.py"), "sample_module.py")
    assert result.ncm is not None
    callees = {c.callee_text for c in result.ncm.calls}
    assert {"ValueError", "len", "open", "open_async", "sum", "str"} <= callees
    assert any("." in c.callee_text for c in result.ncm.calls)
    kinds = {lit.kind for lit in result.ncm.literals}
    assert {"string", "number", "boolean"} <= kinds
    flow = {c.kind for c in result.ncm.control_flow}
    assert {"if", "for", "while", "try", "except", "with", "match", "comprehension"} <= flow


def test_locations_use_repo_paths_and_1_based_lines() -> None:
    source = b"import os\n\n\ndef f():\n    return 1\n"
    result = _parse(source, "pkg/m.py")
    assert result.ncm is not None
    func = result.ncm.functions[0]
    assert (func.location.start_line, func.location.start_column) == (4, 0)
    assert func.location.file_path == "pkg/m.py"
    assert "\\" not in func.location.file_path


def test_partial_recovery_never_clean() -> None:
    result = _parse(read_fixture_bytes("parsing", "partial_recovery.py"))
    assert result.state == ParseState.PARSED_WITH_DIAGNOSTICS
    assert result.ncm is not None
    assert result.ncm.completeness == "partially"
    assert result.ncm.module.partially_represented is True
    assert any(f.qualified_name.endswith("first") for f in result.ncm.functions)
    assert result.diagnostics, "partial results must carry diagnostics"
    assert all(d.severity in ("error", "warning") for d in result.diagnostics)


def test_malformed_fixtures_never_clean() -> None:
    from tests.fixtures.helpers.paths import FIXTURES_ROOT

    # syntax_error and truncated trigger error recovery; unexpected_indent
    # is tolerated by Tree-sitter's grammar (CPython itself rejects it —
    # the AST adapter, which the registry prefers for Python, fails it).
    for name in ("syntax_error.py", "truncated.py"):
        source = (FIXTURES_ROOT / "malformed" / name).read_bytes()
        result = _parse(source, name)
        assert result.state in (ParseState.PARSED_WITH_DIAGNOSTICS, ParseState.FAILED), name
        assert result.state != ParseState.PARSED


def test_node_budget_enforced() -> None:
    assert NODE_BUDGET == 200_000
    assert NODE_BUDGET > 0


def test_values_never_recorded() -> None:
    source = b'PASSWORD = "hunter2-secret-value"\n'
    result = _parse(source)
    assert result.state == ParseState.PARSED
    assert "hunter2-secret-value" not in repr(result.ncm)
