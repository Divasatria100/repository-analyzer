"""Parser interface contract tests (TASK-064).

A minimal stub adapter proves the ABC binds input to normalized output;
concrete adapters prove the contract holds for real parsers.
"""

import pytest

from app.ncm import NCM_SCHEMA_VERSION, NormalizedModule, ParseResult, ParseState, SourceLocation
from app.parsers.base import ParserAdapter, ParserInput


class StubAdapter(ParserAdapter):
    """Smallest possible adapter: echoes emptiness, never fails silently."""

    name = "stub"
    parser_version = "stub-1"
    supported_languages = frozenset({"stub-lang"})

    def parse(self, data: ParserInput) -> ParseResult:
        """Return an empty but well-formed module."""
        from app.ncm import NcmModule

        assert len(data.source) <= data.max_bytes
        module = NcmModule(
            id=data.relative_path,
            file_path=data.relative_path,
            language=data.language,
            name="stub",
        )
        return ParseResult(
            state=ParseState.PARSED,
            ncm=NormalizedModule(
                file_path=data.relative_path,
                language=data.language,
                module=module,
                parser=self.name,
                parser_version=self.parser_version,
            ),
            parser_name=self.name,
            parser_version=self.parser_version,
        )


def test_interface_binds_and_supports() -> None:
    adapter = StubAdapter()
    assert adapter.supports("stub-lang") is True
    assert adapter.supports("python") is False
    result = adapter.parse(
        ParserInput("a.py", "stub-lang", b"x = 1\n", timeout_s=5.0, max_bytes=100)
    )
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    assert result.ncm.module.id == "a.py"
    assert result.ncm.ncm_version == NCM_SCHEMA_VERSION


def test_state_vocabulary_is_lowercase() -> None:
    assert {s.value for s in ParseState} == {
        "parsed",
        "parsed_with_diagnostics",
        "failed",
        "unsupported",
    }


def test_result_roundtrip_preserves_ncm() -> None:
    from app.ncm import (
        FunctionDef,
        ImportRef,
        NcmModule,
        NormalizedModule,
    )
    from app.ncm import ParseResult as Result

    location = SourceLocation("a.py", 1, 0, 2, 5)
    ncm = NormalizedModule(
        file_path="a.py",
        language="python",
        module=NcmModule(id="a.py", file_path="a.py", language="python", name="a"),
        imports=[
            ImportRef(
                id="a.py:import:os:1:0",
                module_id="a.py",
                target_text="os",
                resolution="external",
                location=location,
            )
        ],
        functions=[
            FunctionDef(
                id="a.py:func:f:3:0",
                module_id="a.py",
                class_id=None,
                qualified_name="f",
                kind="function",
                location=location,
                body_location=location,
            )
        ],
        parser="stub",
        parser_version="stub-1",
    )
    result = Result(state=ParseState.PARSED, ncm=ncm, parser_name="stub", parser_version="stub-1")
    rebuilt = Result.from_dict(result.to_dict())
    assert rebuilt.state == ParseState.PARSED
    assert rebuilt.ncm is not None
    assert rebuilt.ncm.functions[0].qualified_name == "f"
    assert rebuilt.ncm.imports[0].target_text == "os"
    assert rebuilt.ncm.imports[0].location.start_line == 1
    assert rebuilt.parser_name == "stub"


def test_ncm_ids_are_deterministic() -> None:
    from app.parsers.python_ast import PythonAstAdapter

    source = b"def f():\n    return g(1)\n"
    first = PythonAstAdapter().parse(ParserInput("m.py", "python", source, 30.0, 100000))
    second = PythonAstAdapter().parse(ParserInput("m.py", "python", source, 30.0, 100000))
    assert first.state == ParseState.PARSED
    assert second.state == ParseState.PARSED
    assert first.ncm is not None and second.ncm is not None
    assert [f.id for f in first.ncm.functions] == [f.id for f in second.ncm.functions]
    assert [c.id for c in first.ncm.calls] == [c.id for c in second.ncm.calls]
    assert "m.py" in first.ncm.functions[0].id


def test_failed_result_carries_no_ncm() -> None:
    from app.parsers.python_ast import PythonAstAdapter

    result = PythonAstAdapter().parse(
        ParserInput("bad.py", "python", b"def broken(:\n", 30.0, 100000)
    )
    assert result.state == ParseState.FAILED
    assert result.ncm is None
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].severity == "error"


def test_abstract_adapter_cannot_instantiate() -> None:
    with pytest.raises(TypeError):
        ParserAdapter()  # type: ignore[abstract]
