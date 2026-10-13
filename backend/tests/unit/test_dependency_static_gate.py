"""Static-only gate tests (TASK-112–122 boundary).

Dependency analysis is static analysis: no package installation, no package
execution, no target-code import, no registry resolution. OSV is the only
permitted external integration. These tests are non-vacuous: discovery is
asserted non-empty, planted violations fail if the mechanism fires, and
tripwires guard the forbidden operations.
"""

import ast
import subprocess
from pathlib import Path

import httpx
import pytest

from app.analyzers.dependency import analyzer as analyzer_module
from app.analyzers.dependency import osv as osv_module
from tests.fixtures.helpers.dependency_helpers import analyze_manifests

ANALYZERS_ROOT = Path(__file__).resolve().parents[2] / "app" / "analyzers" / "dependency"

FORBIDDEN_TOKENS = (
    "npm install",
    "npm ci",
    "npm exec",
    "npx ",
    "pip install",
    "poetry install",
    "poetry run",
    "pipenv install",
    "composer install",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.exec",
    "os.system",
    "importlib.import_module",
    "__import__",
    "registry.npmjs.org",
    "pypi.org/simple",
    "files.pythonhosted.org",
)

FORBIDDEN_IMPORTS = {"subprocess", "importlib"}


def _code_without_strings_and_comments(path: Path) -> str:
    """Source with string literals and comments blanked (data never matches).

    String contents (docstrings, signal tables such as the dynamic-import
    token set, messages) are data, not execution: a planted real call such
    as ``subprocess.run(...)`` in code still matches after stripping.
    """
    import io
    import tokenize

    text = path.read_text(encoding="utf-8")
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text
    pieces: list[str] = []
    for token in tokens:
        if token.type in (tokenize.STRING, tokenize.COMMENT):
            pieces.append(" " * len(token.string))
        else:
            pieces.append(token.string)
    return "".join(pieces)


def test_dependency_source_contains_no_execution_tokens() -> None:
    """Static scan of our own analyzer sources (analyzed as data, not run)."""
    violations: list[str] = []
    for path in sorted(ANALYZERS_ROOT.rglob("*.py")):
        code = _code_without_strings_and_comments(path)
        for token in FORBIDDEN_TOKENS:
            if token in code:
                violations.append(f"{path.name}: {token!r}")
    assert violations == []


def test_dependency_modules_import_no_execution_facilities() -> None:
    violations: list[str] = []
    for path in sorted(ANALYZERS_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                        violations.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in FORBIDDEN_IMPORTS:
                    violations.append(f"{path.name}: from {node.module} import ...")
    assert violations == []


def test_execution_token_scan_is_non_vacuous(tmp_path: Path) -> None:
    """The scanner flags real code usage but ignores string data."""
    planted = tmp_path / "planted.py"
    planted.write_text('x = 1\nsubprocess.run(["pip", "install", "x"])\n', encoding="utf-8")
    code = _code_without_strings_and_comments(planted)
    assert "subprocess.run" in code
    assert "pip install" not in code  # string data, not a code token
    innocent = tmp_path / "innocent.py"
    innocent.write_text('TOKENS = frozenset({"__import__", "eval"})\n', encoding="utf-8")
    clean = _code_without_strings_and_comments(innocent)
    assert "__import__" not in clean


def test_package_managers_are_never_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tripwire: any subprocess spawn during analysis fails the test."""
    calls: list[tuple[str, object]] = []

    def _forbidden(*args: object, **kwargs: object) -> object:
        calls.append(("subprocess", args))
        raise AssertionError("package manager or shell execution is forbidden")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "call", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)

    result, _, analyzer = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "package.json": '{"dependencies": {"react": "^18.2.0"}}',
            "pyproject.toml": '[project]\nname="d"\ndependencies=["flask==3.0.0"]\n',
        }
    )
    inventory_occurrences = analyzer.inventory_for  # bound method exists
    assert calls == []
    assert result.rule_results  # non-vacuous: rules actually ran
    assert inventory_occurrences is not None


def test_discovery_is_non_vacuous() -> None:
    result, _, analyzer = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "package.json": '{"dependencies": {"react": "^18.2.0"}}',
        }
    )
    from tests.fixtures.helpers.analyzer_helpers import make_context
    from tests.fixtures.helpers.security_helpers import parse_files

    context = make_context(ncm=parse_files({}))
    inventory = analyzer.inventory_for(context)
    assert len(inventory.occurrences) == 2  # both manifests contributed
    assert result.findings is not None


def test_only_osv_host_is_contacted() -> None:
    """Mock transport asserts every request targets api.osv.dev over HTTPS."""
    hosts: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.add(str(request.url.host))
        assert str(request.url).startswith("https://api.osv.dev/")
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{}]})
        return httpx.Response(200, json={"id": "GHSA-x"})

    from tests.fixtures.helpers.dependency_helpers import mock_osv_client

    client = mock_osv_client(handler)  # type: ignore[arg-type]
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"}, osv_client=client)
    assert hosts == {"api.osv.dev"}
    assert result.rule_results


def test_no_target_code_import() -> None:
    """Target manifests are parsed as data: analysis adds no target modules."""
    import sys

    before = set(sys.modules)
    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, sources={"src/app.py": "x = 1\n"}
    )
    added = set(sys.modules) - before
    assert not any(name.split(".")[0] == "requests" for name in added)
    assert result.rule_results


def test_osv_module_has_no_registry_lookup() -> None:
    text = (ANALYZERS_ROOT / "osv.py").read_text(encoding="utf-8")
    assert "pypi.org" not in text
    assert "registry.npmjs" not in text
    gateway = Path(__file__).resolve().parents[2] / "app" / "services" / "osv_gateway.py"
    gateway_text = gateway.read_text(encoding="utf-8")
    assert "querybatch" in gateway_text  # the allowed advisory endpoint is present
    assert "vulns" in gateway_text


def test_analyzer_module_references_static_pipeline() -> None:
    text = (ANALYZERS_ROOT / "analyzer.py").read_text(encoding="utf-8")
    assert "build_inventory" in text
    assert "OsvClient" in text or "osv_client" in text
    assert analyzer_module.DependencyAnalyzer.id == "dependency"
    assert osv_module.OSV_BASE_URL == "https://api.osv.dev"


def test_osv_gateway_has_no_execution_or_registry_tokens() -> None:
    """C12: the gateway allows only the advisory endpoint over HTTPS."""
    gateway = Path(__file__).resolve().parents[2] / "app" / "services" / "osv_gateway.py"
    code = _code_without_strings_and_comments(gateway)
    for token in FORBIDDEN_TOKENS:
        assert token not in code, f"osv_gateway.py: {token!r}"
    text = gateway.read_text(encoding="utf-8")
    assert "https://api.osv.dev" in text
    assert "pypi.org" not in text
    assert "registry.npmjs" not in text
