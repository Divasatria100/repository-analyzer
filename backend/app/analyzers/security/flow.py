"""Bounded value-origin analysis for security rules (TASK-097–100 support).

Implements the docs/07 §3.3 origin categories (constant, configurable,
externally influenced, unresolved) over a narrow, evidence-based scope:

* assignments are collected from bounded source lines preceding a sink
  (same file; function scope from NCM ``body_location`` when available),
* right-hand sides are classified with framework-independent markers
  (``sys.argv``, ``input()``, ``os.environ``, literals, ...),
* propagation follows direct assignment chains with a small depth cap.

This is intentionally not an interprocedural taint engine: anything not
established locally is reported as unresolved with lowered confidence,
never assumed safe. No ``ast``, no tree-sitter, no ``app.parsers`` —
only bounded string inspection around NCM-located sinks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from app.analyzers.security.source import MAX_SCOPE_LINES, mask_strings, scope_lines, strip_comment

#: Maximum assignment-chain depth followed before declaring unresolved.
MAX_FLOW_DEPTH = 8


class Origin(StrEnum):
    """Where static analysis can place a value (docs/07 §3.3)."""

    CONSTANT = "constant"
    CONFIGURABLE = "configurable"
    EXTERNAL = "externally_influenced"
    UNRESOLVED = "unresolved"


_EXTERNAL_PATTERNS = (
    re.compile(r"\bsys\.argv\b"),
    re.compile(r"\binput\s*\("),
    re.compile(r"\bsys\.stdin\b"),
    re.compile(r"\.recv\s*\("),
    re.compile(r"\bsys\.environ\b"),
    re.compile(
        r"\brequest\.(args|form|values|data|json|query_params|params|GET|POST|body|headers|cookies|path_params)\b"
    ),
    re.compile(r"\bargv\s*\["),
    re.compile(r"\bgetattr\s*\(\s*request\b"),
)

_CONFIGURABLE_PATTERNS = (
    re.compile(r"\bos\.environ\b"),
    re.compile(r"\bos\.getenv\b"),
    re.compile(r"\bgetenv\s*\("),
    re.compile(r"\benviron\s*\["),
    re.compile(r"\bconfig\.\w+"),
    re.compile(r"\bsettings\.\w+"),
    re.compile(r"\bCONFIG\b"),
)

_FSTRING_RE = re.compile(r"(?<![A-Za-z0-9_])(?:[rRbBuU]{0,2}[fF]|[fF][rRbB]?)\s*['\"]")

_FORMAT_CALL_RE = re.compile(r"\.\s*format\s*\(")

#: Names that never count as dynamic identifiers in an expression.
_BUILTIN_NAMES = frozenset(
    {
        "True",
        "False",
        "None",
        "str",
        "int",
        "float",
        "bool",
        "len",
        "repr",
        "format",
        "join",
        "upper",
        "lower",
        "strip",
        "encode",
        "decode",
        "range",
        "list",
        "dict",
        "tuple",
        "set",
        "open",
        "print",
        "text",
    }
)

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?<!==)(?<![<>!])=(?![=>])")


@dataclass
class ExpressionInfo:
    """Shape of one sink-argument expression (bounded static view)."""

    text: str
    is_dynamic: bool
    identifiers: tuple[str, ...]
    has_fstring: bool
    has_concat: bool
    has_format: bool


def classify_rhs_origin(rhs: str) -> Origin:
    """Classify a right-hand-side snippet by framework-independent markers."""
    masked = mask_strings(rhs)
    for pattern in _EXTERNAL_PATTERNS:
        if pattern.search(masked):
            return Origin.EXTERNAL
    for pattern in _CONFIGURABLE_PATTERNS:
        if pattern.search(masked):
            return Origin.CONFIGURABLE
    return Origin.UNRESOLVED


def analyze_expression(text: str) -> ExpressionInfo:
    """Describe dynamic construction in one expression snippet.

    A snippet is dynamic when it interpolates, concatenates, formats, or
    otherwise combines a non-builtin identifier into the value. Pure
    literals (and literal-only operations) are constant.
    """
    masked = mask_strings(text)
    stripped = strip_comment(masked)
    has_fstring = bool(_FSTRING_RE.search(text))
    has_format = bool(_FORMAT_CALL_RE.search(masked) or "%" in stripped)
    concat_outside = bool(re.search(r"(?<![=!<>])\+(?![=])", stripped))
    identifiers = tuple(
        dict.fromkeys(name for name in _IDENTIFIER_RE.findall(masked) if name not in _BUILTIN_NAMES)
    )
    is_dynamic = has_fstring or has_format or concat_outside or bool(identifiers)
    if not identifiers and not (has_fstring or has_format or concat_outside):
        is_dynamic = False
    has_concat = concat_outside or has_format or has_fstring
    return ExpressionInfo(
        text=text.strip(),
        is_dynamic=is_dynamic,
        identifiers=identifiers,
        has_fstring=has_fstring,
        has_concat=has_concat,
        has_format=has_format,
    )


@dataclass
class AssignmentMap:
    """Local ``name -> rhs text`` facts for one file (bounded, same-file)."""

    facts: dict[str, str]
    parameters: dict[str, frozenset[str]]

    def origin_of(self, name: str, function_id: str | None) -> Origin:
        """Resolve one name to an origin category (bounded chain walk)."""
        seen: set[str] = set()
        current: str | None = name
        for _ in range(MAX_FLOW_DEPTH):
            if current is None or current in seen:
                return Origin.UNRESOLVED
            seen.add(current)
            rhs = self.facts.get(current)
            if rhs is None:
                # No local fact (parameter or out-of-scope value): unresolved.
                return Origin.UNRESOLVED
            origin = classify_rhs_origin(rhs)
            if origin in (Origin.EXTERNAL, Origin.CONFIGURABLE):
                return origin
            if _looks_literal(rhs):
                return Origin.CONSTANT
            info = analyze_expression(rhs)
            if not info.is_dynamic:
                return Origin.UNRESOLVED
            nested = [ident for ident in info.identifiers if ident not in seen]
            if not nested:
                return Origin.UNRESOLVED
            sub_origins = [self._origin_single(ident, seen) for ident in nested]
            return worst_origin(sub_origins)
        return Origin.UNRESOLVED

    def _origin_single(self, name: str, seen: set[str]) -> Origin:
        if name in seen:
            return Origin.UNRESOLVED
        rhs = self.facts.get(name)
        if rhs is None:
            # Unknown names (including parameters) are unresolved —
            # never assumed safe, never assumed external.
            return Origin.UNRESOLVED
        origin = classify_rhs_origin(rhs)
        if origin in (Origin.EXTERNAL, Origin.CONFIGURABLE):
            return origin
        if _looks_literal(rhs):
            return Origin.CONSTANT
        info = analyze_expression(rhs)
        if not info.is_dynamic:
            return Origin.UNRESOLVED
        for ident in info.identifiers:
            if ident == name or ident in seen:
                continue
            sub = self._origin_single(ident, seen | {name})
            if sub == Origin.EXTERNAL:
                return Origin.EXTERNAL
        return Origin.UNRESOLVED


def _looks_literal(rhs: str) -> bool:
    masked = mask_strings(strip_comment(rhs)).strip()
    if not masked:
        return False
    if re.fullmatch(r"[\"']{2}|[\"'][^\"']*[\"']|\d[\d._]*|True|False|None", masked):
        return True
    if re.fullmatch(r"[\[\(\{][\"'\d\s,\.\-+:TrueFalsNone]*[\]\)\}]", masked):
        return True
    return False


def _collect_assignments(scope: list[str], top_level_only: bool) -> dict[str, str]:
    """Collect ``name = rhs`` facts from scope lines (bounded, last wins)."""
    facts: dict[str, str] = {}
    index = 0
    while index < len(scope):
        line = scope[index]
        if top_level_only and line[:1] in (" ", "\t"):
            index += 1
            continue
        match = _ASSIGN_RE.match(strip_comment(mask_strings(line)))
        if not match:
            index += 1
            continue
        name = match.group(1)
        rhs_first = line.split("=", 1)[1]
        rhs_lines = [rhs_first]
        depth = 0
        for char in mask_strings(rhs_first):
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
        extra = 0
        while depth > 0 and extra < 15 and index + 1 + extra < len(scope):
            extra += 1
            nxt = scope[index + extra]
            rhs_lines.append(nxt)
            for char in mask_strings(nxt):
                if char in "([":
                    depth += 1
                elif char in ")]":
                    depth -= 1
        facts[name] = "\n".join(rhs_lines).strip()
        index += 1 + extra
    return facts


def build_assignment_map(
    lines: list[str],
    focus_line: int,
    function_start: int | None = None,
    parameters: dict[str, frozenset[str]] | None = None,
) -> AssignmentMap:
    """Collect ``name = rhs`` facts from bounded lines before a sink.

    Function-local assignments are collected first; module-top-level
    assignments (column 0, e.g. constants) supplement them without
    overriding locals. Multi-line right-hand sides are joined by
    parenthesis balance (capped).
    """
    scope = scope_lines(lines, focus_line, MAX_SCOPE_LINES)
    base_line = focus_line - len(scope)
    if function_start is not None:
        local = [ln for idx, ln in enumerate(scope) if base_line + idx >= function_start]
    else:
        local = scope
    facts = _collect_assignments(local, top_level_only=False)
    if function_start is not None:
        module_lines = lines[max(0, function_start - 1 - MAX_SCOPE_LINES) : function_start - 1]
        module_facts = _collect_assignments(module_lines, top_level_only=True)
        facts = {**module_facts, **facts}
    return AssignmentMap(facts=facts, parameters=parameters or {})


def worst_origin(origins: list[Origin]) -> Origin:
    """Most concerning origin wins (external > unresolved > configurable)."""
    if Origin.EXTERNAL in origins:
        return Origin.EXTERNAL
    if Origin.UNRESOLVED in origins:
        return Origin.UNRESOLVED
    if Origin.CONFIGURABLE in origins:
        return Origin.CONFIGURABLE
    return Origin.CONSTANT
