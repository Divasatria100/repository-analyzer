"""Python AST adapter tests: NCM coverage, locations, errors (TASK-066/070)."""

import pytest

from app.ncm import ParseResult, ParseState
from app.parsers.base import ParserInput
from app.parsers.python_ast import PythonAstAdapter
from tests.fixtures.helpers.paths import read_fixture_bytes

pytestmark = pytest.mark.security

ADAPTER = PythonAstAdapter()


def _parse(source: bytes, path: str = "m.py") -> ParseResult:
    return ADAPTER.parse(ParserInput(path, "python", source, 30.0, 1_000_000))


def test_module_imports_classes_functions() -> None:
    result = _parse(read_fixture_bytes("parsing", "sample_module.py"), "sample_module.py")
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    names = {f.qualified_name for f in result.ncm.functions}
    assert {"sample_module.create_engine", "sample_module.Registry.register"} <= names
    methods = [f for f in result.ncm.functions if f.kind == "method"]
    assert {f.qualified_name for f in methods} >= {
        "sample_module.Registry.register",
        "sample_module.Registry.size",
    }
    classes = {c.qualified_name: c for c in result.ncm.classes}
    assert classes["sample_module.Registry"].base_names == ("Base", "Mixin")
    imports = {i.target_text: i.resolution for i in result.ncm.imports}
    assert imports["os"] == "external"
    assert imports[".sibling"] == "internal"
    assert imports["helpers"] == "unresolved"


def test_parameters_decorators_and_self_cls() -> None:
    result = _parse(read_fixture_bytes("parsing", "sample_module.py"), "sample_module.py")
    assert result.ncm is not None
    register = next(
        f for f in result.ncm.functions if f.qualified_name == "sample_module.Registry.register"
    )
    kinds = [(p.name, p.kind, p.is_self_cls) for p in register.parameters]
    assert kinds[0] == ("self", "positional", True)
    assert ("priority", "default", False) in kinds
    create = next(
        f for f in result.ncm.functions if f.qualified_name == "sample_module.create_engine"
    )
    assert [p.kind for p in create.parameters] == [
        "positional",
        "default",
        "vararg",
        "keyword-only",
        "kwarg",
    ]
    size = next(
        f for f in result.ncm.functions if f.qualified_name == "sample_module.Registry.size"
    )
    assert size.decorator_names == ("property",)


def test_calls_assignments_literals_control_flow() -> None:
    result = _parse(read_fixture_bytes("parsing", "sample_module.py"), "sample_module.py")
    assert result.ncm is not None
    callees = {c.callee_text for c in result.ncm.calls}
    assert {"ValueError", "len", "open", "open_async", "sum", "str"} <= callees
    assert all(c.argument_count >= 0 for c in result.ncm.calls)
    targets = {name for a in result.ncm.assignments for name in a.target_names}
    assert {"total", "label", "code", "args", "count"} <= targets
    kinds = {lit.kind for lit in result.ncm.literals}
    assert {"string", "number", "boolean"} <= kinds
    assert not any("total=" in lit.kind for lit in result.ncm.literals)
    flow = {c.kind for c in result.ncm.control_flow}
    assert {"if", "for", "while", "try", "except", "with", "match", "comprehension"} <= flow


def test_values_never_recorded() -> None:
    source = b'PASSWORD = "hunter2-secret-value"\nTAG = "abc"\n'
    result = _parse(source)
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    dumped = repr(result.ncm)
    assert "hunter2-secret-value" not in dumped
    assert all("hunter2" not in name for a in result.ncm.assignments for name in a.target_names)


def test_locations_are_normalized() -> None:
    source = b"import os\n\n\ndef f():\n    return 1\n"
    result = _parse(source, "pkg/m.py")
    assert result.ncm is not None
    func = result.ncm.functions[0]
    assert (func.location.start_line, func.location.start_column) == (4, 0)
    assert func.location.end_line == 5
    assert func.body_location.start_line == 5
    assert func.location.file_path == "pkg/m.py"
    imp = result.ncm.imports[0]
    assert (imp.location.start_line, imp.location.start_column) == (1, 0)


def test_syntax_error_is_failed_with_location() -> None:
    source = b"def broken(:\n    pass\n"
    result = _parse(source, "broken.py")
    assert result.state == ParseState.FAILED
    assert result.ncm is None
    (diagnostic,) = result.diagnostics
    assert diagnostic.severity == "error"
    assert diagnostic.code == "SyntaxError"
    assert diagnostic.location is not None
    assert diagnostic.location.start_line == 1
    assert "def broken(:" not in diagnostic.message


def test_malformed_fixtures_fail() -> None:
    from tests.fixtures.helpers.paths import FIXTURES_ROOT

    for name in ("syntax_error.py", "truncated.py", "unexpected_indent.py"):
        source = (FIXTURES_ROOT / "malformed" / name).read_bytes()
        result = _parse(source, name)
        assert result.state == ParseState.FAILED, name
        assert result.ncm is None


def test_undecodable_bytes_fail() -> None:
    result = _parse(b"\xff\xfe\x00bad", "bad.py")
    assert result.state == ParseState.FAILED
    assert result.diagnostics[0].code == "decode"


def test_oversized_input_rejected() -> None:
    result = ADAPTER.parse(ParserInput("big.py", "python", b"x = 1\n", 30.0, 2))
    assert result.state == ParseState.FAILED
    assert result.diagnostics[0].code == "limit"


def test_input_limit_boundaries() -> None:
    source = b"x = 1\n"  # 6 bytes
    assert ADAPTER.parse(ParserInput("a.py", "python", source, 30.0, 5)).state == ParseState.FAILED
    assert ADAPTER.parse(ParserInput("a.py", "python", source, 30.0, 6)).state == ParseState.PARSED
    assert ADAPTER.parse(ParserInput("a.py", "python", source, 30.0, 7)).state == ParseState.PARSED
