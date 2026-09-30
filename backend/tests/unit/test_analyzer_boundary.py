"""Analyzer dependency-direction test (TASK-081, NCM gate 3).

Analyzers must consume NCM (``app.ncm``) and never parser internals:
no ``ast``/``tree_sitter`` imports, no ``app.parsers`` implementation
modules (adapters, worker, runner, registry, pipeline, base).

Scans every ``.py`` file under ``backend/app/analyzers/`` with the stdlib
``ast`` module (analyzing our own code structure as data — this is not
repository content). Currently vacuous (no analyzer code exists yet) and
guards all future analyzer work.
"""

import ast
from pathlib import Path

ANALYZERS_ROOT = Path(__file__).resolve().parents[2] / "app" / "analyzers"

FORBIDDEN_TOP_LEVEL = {"ast", "tree_sitter"}
FORBIDDEN_PARSERS_SUBMODULES = frozenset(
    {
        "app.parsers.base",
        "app.parsers.pipeline",
        "app.parsers.python_ast",
        "app.parsers.registry",
        "app.parsers.runner",
        "app.parsers.tree_sitter",
        "app.parsers.worker",
    }
)


def _imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.append(node.module)
    return names


def _analyzer_files() -> list[Path]:
    return sorted(ANALYZERS_ROOT.rglob("*.py"))


def test_analyzers_directory_exists() -> None:
    assert ANALYZERS_ROOT.is_dir()


def test_no_parser_specific_imports_in_analyzers() -> None:
    """Fail if any analyzer reaches past NCM into parser internals."""
    violations: list[str] = []
    for path in _analyzer_files():
        for name in _imported_modules(path):
            top = name.split(".")[0]
            if top in FORBIDDEN_TOP_LEVEL or name in FORBIDDEN_PARSERS_SUBMODULES:
                violations.append(f"{path.name}: {name}")
    assert violations == []


def test_ncm_contract_is_importable_without_parsers() -> None:
    """The contract package stands alone (no adapter imports)."""
    import app.ncm as contract

    assert contract.NCM_SCHEMA_VERSION == "1"
    assert "Relationship" in contract.__all__
    assert "NcmRepository" in contract.__all__
