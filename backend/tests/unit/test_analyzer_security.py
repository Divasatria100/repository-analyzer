"""Analyzer-foundation security tests (canary, network, logging).

The foundation treats canary repository content as inert data end to end:
parse it, build NCM, run mock analyzers over it, extract evidence from it
— and no marker, side effect, import, shell command, or network access
may occur.
"""

import sys

import pytest

from app.analyzers.base import Analyzer
from app.analyzers.rules import RegisteredRule, RuleOutcome
from app.analyzers.runner import run_analyzer
from tests.fixtures.helpers.analyzer_helpers import make_context, make_ncm_repository, make_rule

pytestmark = pytest.mark.security


def _ncm_from_canary():
    """Parse the canary fixture into an NCM repository (bytes in, never executed)."""
    from app.ncm import NcmFileEntry, NcmRepository
    from app.parsers.base import ParserInput
    from app.parsers.registry import get_adapter
    from tests.fixtures.helpers.canary import fixture_contains_canary_payload
    from tests.fixtures.helpers.paths import read_fixture_bytes

    source = read_fixture_bytes("security", "execution_canary.py")
    assert fixture_contains_canary_payload(source.decode("utf-8"))
    adapter = get_adapter("python")
    assert adapter is not None
    result = adapter.parse(ParserInput("canary_check.py", "python", source, 30.0, 1_000_000))
    assert result.ncm is not None
    return NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(
                path="canary_check.py",
                language="python",
                parse_state=result.state.value,
                module=result.ncm,
            )
        ],
    )


class ScanningAnalyzer(Analyzer):
    """Test analyzer that walks every NCM string field (never executes)."""

    id = "scanner"
    name = "Scanner"
    version = "0.1.0"

    def rules(self) -> list[RegisteredRule]:
        """One rule that inspects NCM text without executing anything."""
        from tests.fixtures.helpers.analyzer_helpers import make_finding

        def execute(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
            seen: list[str] = []
            for module in execution_context.context.ncm.modules:
                seen.append(module.file_path)
                for function in module.functions:
                    seen.append(function.qualified_name)
                for call in module.calls:
                    seen.append(call.callee_text)
            assert seen, "NCM walker observed repository content as data"
            return RuleOutcome(
                findings=[
                    make_finding(
                        rule_id="SEC-TEST-001",
                        path="canary_check.py",
                        subject_key="scan",
                        analysis_id=execution_context.context.analysis_id,
                    )
                ]
            )

        return [RegisteredRule(metadata=make_rule(), execute=execute)]


def test_canary_never_executes_through_foundation() -> None:
    """Parse → NCM → analyzer → evidence over canary bytes, marker absent."""
    from tests.fixtures.helpers.canary import assert_canary_absent

    ncm = _ncm_from_canary()
    context = make_context(ncm=ncm)
    result = run_analyzer(ScanningAnalyzer(), context)
    assert result.failed is False
    assert len(result.findings) == 1
    assert_canary_absent()
    assert "canary_check" not in sys.modules
    assert "execution_canary" not in sys.modules


def test_no_non_loopback_network_during_analysis() -> None:
    """The tripwire guards analyzer execution (explicit proof)."""
    import socket

    ncm = _ncm_from_canary()
    result = run_analyzer(ScanningAnalyzer(), make_context(ncm=ncm))
    assert result.failed is False
    with pytest.raises(RuntimeError, match="External network blocked"):
        socket.socket().connect(("example.test", 443))


def test_no_source_content_in_foundation_logs() -> None:
    """Analyzer logging carries counts/IDs only, never source lines."""
    import logging as logging_module

    from app.core.logging import get_logger

    captured: list[str] = []
    secret_line = 'password = "hunter2-hunter2"'

    class Capture(logging_module.Handler):
        def emit(self, record: logging_module.LogRecord) -> None:
            captured.append(self.format(record))

    logger = get_logger("analyzers")
    handler = Capture()
    logger.addHandler(handler)
    try:
        ncm = make_ncm_repository("src/app.py")
        context = make_context(ncm=ncm)
        result = run_analyzer(ScanningAnalyzer(), context)
        assert result.failed is False
    finally:
        logger.removeHandler(handler)
    assert secret_line not in "".join(captured)
    assert "hunter2" not in "".join(captured)


def test_no_shell_or_subprocess_in_foundation() -> None:
    """The foundation package spawns nothing (worker lives in parsers)."""
    import ast as stdlib_ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "app" / "analyzers"
    assert root.is_dir(), f"analyzer root is missing: {root}"
    paths = sorted(root.rglob("*.py"))
    assert paths, "security boundary scan found no files"

    forbidden_imports = {
        "subprocess",
        "socket",
        "urllib",
        "http.client",
        "http",
        "httpx",
        "requests",
        "importlib",
        "runpy",
    }
    forbidden_bare_calls = {"eval", "exec", "compile", "__import__"}
    forbidden_receivers = {"os", "subprocess", "socket", "requests", "httpx", "urllib"}
    forbidden_methods = {
        "system",
        "popen",
        "run",
        "call",
        "Popen",
        "check_call",
        "check_output",
        "connect",
        "urlopen",
    }
    violations = []
    for path in paths:
        tree = stdlib_ast.parse(path.read_text(encoding="utf-8"))
        for node in stdlib_ast.walk(tree):
            if isinstance(node, stdlib_ast.Import):
                for alias in node.names:
                    if alias.name in forbidden_imports or alias.name.split(".")[0] in (
                        "subprocess",
                        "socket",
                        "httpx",
                        "requests",
                        "importlib",
                        "runpy",
                    ):
                        violations.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, stdlib_ast.ImportFrom):
                if node.module and (
                    node.module in forbidden_imports
                    or node.module.split(".")[0]
                    in ("subprocess", "socket", "httpx", "requests", "importlib", "runpy")
                ):
                    violations.append(f"{path.name}: from {node.module} import ...")
            elif isinstance(node, stdlib_ast.Call):
                func = node.func
                if isinstance(func, stdlib_ast.Name) and func.id in forbidden_bare_calls:
                    violations.append(f"{path.name}: call {func.id}()")
                elif (
                    isinstance(func, stdlib_ast.Attribute)
                    and isinstance(func.value, stdlib_ast.Name)
                    and func.value.id in forbidden_receivers
                    and func.attr in forbidden_methods
                ):
                    violations.append(f"{path.name}: call {func.value.id}.{func.attr}()")
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, stdlib_ast.Constant):
                        if keyword.value.value is True:
                            violations.append(f"{path.name}: shell=True")
    assert violations == []
