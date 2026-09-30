"""Normalized Code Model (NCM): the mandatory analyzer contract.

Dependency direction (docs/11 §4.2, §16; docs/12 §11.4)::

    parser-specific code (``app.parsers.*``)
            ↓
        NCM (this package)
            ↑
        analyzers (``app.analyzers.*``)

Rules enforced by ``tests/unit/test_analyzer_boundary.py``:

* Analyzer modules MUST NOT import ``ast``, ``tree_sitter``, or any
  ``app.parsers`` module except through this package. The only supported
  path is ``Parser → NCM → Analyzer``.
* NCM value objects are plain data: no ``tree_sitter.Node``, no
  ``ast.AST``, no object identity, no memory addresses. Entity identity
  is deterministic within an analysis (analysis + file + kind +
  location + name).
* Locations are repository-relative paths with 1-based lines and
  0-based columns. Host, workspace, and container paths never appear.
* Failure semantics are explicit and never clean: ``complete`` vs
  ``incomplete`` at repository level; ``parsed`` vs
  ``parsed_with_diagnostics`` vs ``failed`` vs ``unsupported`` per file;
  ``internal`` vs ``external`` vs ``unresolved`` per reference.
* No numeric confidence scores exist in V1.0. Reduced completeness is
  observed through ``partially_represented`` flags, ``unresolved``
  references, and ``incomplete`` repository state — never invented.
"""

from app.ncm.model import (
    NCM_SCHEMA_VERSION,
    Assignment,
    CallSite,
    ClassDef,
    ControlFlow,
    Diagnostic,
    FunctionDef,
    ImportRef,
    LiteralValue,
    NcmFileEntry,
    NcmModule,
    NcmRepository,
    NormalizedModule,
    Parameter,
    Relationship,
    SourceLocation,
    UnresolvedRef,
    derive_relationships,
    ncm_from_dict,
    ncm_to_dict,
    repository_from_dict,
    repository_to_dict,
)
from app.ncm.result import ParseResult, ParseState

__all__ = [
    "NCM_SCHEMA_VERSION",
    "Assignment",
    "CallSite",
    "ClassDef",
    "ControlFlow",
    "Diagnostic",
    "FunctionDef",
    "ImportRef",
    "LiteralValue",
    "NcmFileEntry",
    "NcmModule",
    "NcmRepository",
    "NormalizedModule",
    "Parameter",
    "ParseResult",
    "ParseState",
    "Relationship",
    "SourceLocation",
    "UnresolvedRef",
    "derive_relationships",
    "ncm_from_dict",
    "ncm_to_dict",
    "repository_from_dict",
    "repository_to_dict",
]
