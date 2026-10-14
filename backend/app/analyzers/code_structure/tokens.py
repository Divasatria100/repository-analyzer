"""Function-body token sequences for duplicate detection (TASK-138 support).

Token streams come from bounded source lines (read as data through the
existing source provider) sliced to the NCM body span — the comparison
unit and every location stay canonical NCM. The standard-library
``tokenize`` module performs lexical scanning only: no parsing, no AST,
no execution, no imports of ``ast``/``tree_sitter``/``app.parsers.*``.

Normalization follows CODE-REQ-004: comments and blank lines are stripped,
whitespace is normalized away by the token stream itself, and identifier
names positively identified as local (supplied by the caller from NCM
parameters and assignment targets) become positional placeholders in
first-seen order, while keywords, attribute names (following ``.``), and
string/numeric literals are preserved. ``match``/``case`` are kept as
keywords (soft keywords with structural meaning).

Names that cannot be positively identified as local — globals, imports,
builtins, loop variables, ``with``/``as`` and ``except``/``as`` names,
comprehension variables, nested definition names — are preserved verbatim
(conservative: distinguishable, never force-matched). NCM records
parameters and plain assignment targets per function scope; the remaining
binding forms are not represented in NCM, which callers must record as a
limitation rather than treat every identifier as local.
"""

from __future__ import annotations

import io
import keyword
import tokenize

#: Token types dropped from every sequence (structure and comments carry no
#: normalized-token signal for duplication purposes).
_DROPPED_TYPES = frozenset(
    {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
    }
)

#: Keywords preserved verbatim (hard keywords plus structural soft keywords).
_KEPT_KEYWORDS = frozenset(keyword.kwlist) | frozenset({"match", "case"})

#: Bodies whose normalized stream is only one of these carry no signal.
_TRIVIAL_SEQUENCES = frozenset({(), ("pass",), ("...",)})


def normalize_body_tokens(text: str, *, local_names: frozenset[str]) -> tuple[str, ...] | None:
    """Tokenize one function body and normalize per CODE-REQ-004.

    Only names in ``local_names`` (NCM parameters and assignment targets for
    the function) become positional placeholders; every other identifier is
    preserved verbatim. Returns the normalized token tuple, or ``None`` when
    the text cannot be tokenized (callers record a limitation instead of
    guessing).
    """
    try:
        raw = tokenize.generate_tokens(io.StringIO(text).readline)
        tokens = [(token.type, token.string) for token in raw]
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    normalized: list[str] = []
    placeholders: dict[str, str] = {}
    previous = ""
    for token_type, spelling in tokens:
        if token_type in _DROPPED_TYPES:
            continue
        if (
            token_type == tokenize.NAME
            and spelling not in _KEPT_KEYWORDS
            and spelling in local_names
        ):
            if previous == ".":
                normalized.append(spelling)  # attribute name: preserved
            else:
                placeholder = placeholders.get(spelling)
                if placeholder is None:
                    placeholder = f"VAR{len(placeholders)}"
                    placeholders[spelling] = placeholder
                normalized.append(placeholder)
        else:
            normalized.append(spelling)
        previous = spelling
    return tuple(normalized)


def is_trivial_sequence(sequence: tuple[str, ...]) -> bool:
    """True for empty, ``pass``-only, or ``...``-only bodies (excluded)."""
    return sequence in _TRIVIAL_SEQUENCES


def body_text(lines: tuple[str, ...] | list[str], start_line: int, end_line: int) -> str:
    """Slice 1-based body lines (inclusive) for tokenization."""
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        return ""
    return "\n".join(lines[start_line - 1 : end_line])
