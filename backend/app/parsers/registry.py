"""Centralized parser selection (TASK-067).

Deterministic mapping from indexed language to adapter. Python resolves to
the stdlib AST adapter (primary); the Tree-sitter adapter is available by
explicit name for its installed grammars. Anything else — unsupported,
unrecognized, binary, ineligible — resolves to no adapter, which the
pipeline records as ``unsupported``, never as a parse failure.
"""

from __future__ import annotations

from app.parsers.base import ParserAdapter
from app.parsers.python_ast import PythonAstAdapter
from app.parsers.tree_sitter import TreeSitterAdapter

_ADAPTERS: dict[str, ParserAdapter] = {
    PythonAstAdapter.name: PythonAstAdapter(),
    TreeSitterAdapter.name: TreeSitterAdapter(),
}

# Primary adapter per language: the deterministic production choice.
_PRIMARY: dict[str, str] = {
    "python": PythonAstAdapter.name,
}


def get_adapter(language: str | None) -> ParserAdapter | None:
    """Return the primary adapter for a language, or None when unsupported."""
    if language is None:
        return None
    name = _PRIMARY.get(language)
    if name is None:
        return None
    return _ADAPTERS[name]


def get_adapter_by_name(name: str) -> ParserAdapter | None:
    """Return an adapter by explicit name (tests, future languages)."""
    return _ADAPTERS.get(name)


def registered_adapters() -> list[str]:
    """Sorted adapter names (deterministic introspection)."""
    return sorted(_ADAPTERS)
