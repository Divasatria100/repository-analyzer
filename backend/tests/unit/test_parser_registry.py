"""Parser selection tests: deterministic, centralized (TASK-067)."""

import pytest

from app.parsers.registry import get_adapter, get_adapter_by_name, registered_adapters

pytestmark = pytest.mark.security


def test_python_selects_ast_adapter() -> None:
    adapter = get_adapter("python")
    assert adapter is not None
    assert adapter.name == "python-ast"


def test_unsupported_languages_select_nothing() -> None:
    assert get_adapter("go") is None
    assert get_adapter("javascript") is None
    assert get_adapter("") is None
    assert get_adapter(None) is None


def test_explicit_lookup_by_name() -> None:
    assert get_adapter_by_name("python-ast") is not None
    assert get_adapter_by_name("tree-sitter") is not None
    assert get_adapter_by_name("nope") is None


def test_registry_is_deterministic() -> None:
    assert registered_adapters() == ["python-ast", "tree-sitter"]
    assert get_adapter("python") is get_adapter("python")
