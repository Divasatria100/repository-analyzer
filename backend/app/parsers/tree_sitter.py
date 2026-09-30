"""Tree-sitter parser adapter: syntax text in, NCM out, never execution.

Parses with the installed Tree-sitter grammars only (Python in V1.0 —
no fabricated language support). Error recovery produces partial results
with diagnostics; missing nodes are recorded, never silently completed.
The tree walk is iterative with a node budget so pathological inputs
cannot exhaust the worker.
"""

from __future__ import annotations

import sys
import time

from app.parsers.base import ParserAdapter, ParserInput
from app.parsers.ncm import (
    Assignment,
    CallSite,
    ClassDef,
    ControlFlow,
    Diagnostic,
    FunctionDef,
    ImportRef,
    LiteralValue,
    NcmModule,
    NormalizedModule,
    Parameter,
    SourceLocation,
    UnresolvedRef,
)
from app.parsers.result import ParseResult, ParseState

ADAPTER_NAME = "tree-sitter"
MAX_DIAGNOSTIC_MESSAGE = 500
NODE_BUDGET = 200_000


def _parser_version() -> str:
    try:
        from importlib.metadata import version

        return f"tree-sitter-{version('tree-sitter')}"
    except Exception:  # pragma: no cover - metadata always present in practice
        return "tree-sitter-unknown"


def _truncate(message: str) -> str:
    if len(message) > MAX_DIAGNOSTIC_MESSAGE:
        return message[:MAX_DIAGNOSTIC_MESSAGE] + "…"
    return message


def _grammar(language: str):  # type: ignore[no-untyped-def]
    """Load the installed Tree-sitter grammar for a language."""
    from tree_sitter import Language

    if language == "python":
        import tree_sitter_python

        return Language(tree_sitter_python.language())
    raise ValueError(f"No Tree-sitter grammar installed for: {language}")


def _location(file_path: str, node) -> SourceLocation:  # type: ignore[no-untyped-def]
    """Normalize Tree-sitter 0-based points to 1-based lines, 0-based columns."""
    return SourceLocation(
        file_path=file_path,
        start_line=node.start_point.row + 1,
        start_column=node.start_point.column,
        end_line=node.end_point.row + 1,
        end_column=node.end_point.column,
    )


def _node_text(node, source: bytes) -> str:  # type: ignore[no-untyped-def]
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", "replace")
    except Exception:
        return ""


class TreeSitterAdapter(ParserAdapter):
    """Tree-sitter adapter for installed grammars (Python in V1.0)."""

    name = ADAPTER_NAME
    supported_languages = frozenset({"python"})

    def __init__(self) -> None:
        self.parser_version = _parser_version()
        self._grammars: dict[str, object] = {}

    def _language(self, language: str):  # type: ignore[no-untyped-def]
        if language not in self._grammars:
            self._grammars[language] = _grammar(language)
        return self._grammars[language]

    def parse(self, data: ParserInput) -> ParseResult:
        """Parse bounded bytes; error nodes become partial diagnostics."""
        from tree_sitter import Parser

        started = time.perf_counter()
        if len(data.source) > data.max_bytes:
            return self._failed(
                data, "Parser input exceeds the configured per-file size limit.", "limit"
            )
        try:
            text = data.source.decode("utf-8-sig")
        except UnicodeDecodeError:
            return self._failed(data, "Source is not decodable as UTF-8.", "decode")
        try:
            grammar = self._language(data.language)
        except ValueError:
            return self._failed(
                data, f"No Tree-sitter grammar installed for: {data.language}.", "no-grammar"
            )
        try:
            parser = Parser(grammar)
            tree = parser.parse(text.encode("utf-8"))
        except Exception as exc:
            return self._failed(
                data, f"Tree-sitter parser rejected the input ({type(exc).__name__}).", "rejected"
            )
        try:
            ncm, diagnostics, complete = _normalize(
                data.relative_path,
                data.language,
                text.encode("utf-8"),
                tree.root_node,
                self.name,
                self.parser_version,
            )
        except RecursionError:
            return self._failed(
                data, "Source nesting exceeds parser recursion capacity.", "recursion"
            )
        duration_ms = (time.perf_counter() - started) * 1000.0
        state = ParseState.PARSED if complete else ParseState.PARSED_WITH_DIAGNOSTICS
        return ParseResult(
            state=state,
            ncm=ncm,
            diagnostics=diagnostics,
            parser_name=self.name,
            parser_version=self.parser_version,
            duration_ms=duration_ms,
        )

    def _failed(self, data: ParserInput, message: str, code: str) -> ParseResult:
        return ParseResult(
            state=ParseState.FAILED,
            ncm=None,
            diagnostics=[
                Diagnostic(
                    severity="error",
                    message=_truncate(message),
                    location=None,
                    parser=self.name,
                    code=code,
                )
            ],
            parser_name=self.name,
            parser_version=self.parser_version,
        )


def _normalize(file_path: str, language: str, source: bytes, root, parser: str, version: str):  # type: ignore[no-untyped-def]
    """Iterative walk: NCM lists, diagnostics, and completeness flag."""
    module_name = file_path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    module_id = file_path
    imports: list[ImportRef] = []
    classes: list[ClassDef] = []
    functions: list[FunctionDef] = []
    calls: list[CallSite] = []
    assignments: list[Assignment] = []
    literals: list[LiteralValue] = []
    control_flow: list[ControlFlow] = []
    unresolved_refs: list[UnresolvedRef] = []
    diagnostics: list[Diagnostic] = []
    counter = 0
    visited = 0
    complete = True

    def new_id(kind: str, qualified: str, line: int, column: int) -> str:
        nonlocal counter
        counter += 1
        return f"{file_path}:{kind}:{qualified}:{line}:{column}"

    def location(node) -> SourceLocation:  # type: ignore[no-untyped-def]
        return _location(file_path, node)

    def stdlib_top(name: str) -> str:
        if name.startswith("."):
            return "internal"
        if name.split(".")[0] in sys.stdlib_module_names:
            return "external"
        return "unresolved"

    def dotted(node) -> str | None:  # type: ignore[no-untyped-def]
        if node.type == "identifier":
            return _node_text(node, source)
        if node.type == "attribute":
            base = dotted(node.child_by_field_name("object"))
            attr = node.child_by_field_name("attribute")
            if base and attr is not None:
                return f"{base}.{_node_text(attr, source)}"
        return None

    def function_params(params_node, is_method: bool):  # type: ignore[no-untyped-def]
        # Identifiers after a bare `*` or `*args` are keyword-only. The bare
        # marker is an anonymous token, so all children (not just named ones)
        # are scanned in order to track it.
        parameters: list[Parameter] = []
        position = 0
        star_seen = False
        for child in params_node.children:
            if child.type in ("identifier", "typed_parameter", "default_parameter"):
                if child.type == "typed_parameter":
                    name_node = child.child_by_field_name("name")
                    name = _node_text(name_node, source) if name_node else "?"
                    has_default = False
                elif child.type == "default_parameter":
                    name_node = child.child_by_field_name("name")
                    name = _node_text(name_node, source) if name_node else "?"
                    has_default = True
                else:
                    name = _node_text(child, source)
                    has_default = False
                if star_seen:
                    kind = "keyword-only"
                else:
                    kind = "default" if has_default else "positional"
                parameters.append(
                    Parameter(
                        name=name,
                        position=position,
                        kind=kind,
                        is_self_cls=is_method and position == 0 and name in ("self", "cls"),
                    )
                )
                position += 1
            elif child.type == "list_splat_pattern":
                star_seen = True
                name_node = next((c for c in child.named_children if c.type == "identifier"), None)
                parameters.append(
                    Parameter(
                        name=_node_text(name_node, source) if name_node else "*args",
                        position=position,
                        kind="vararg",
                    )
                )
                position += 1
            elif child.type == "dictionary_splat_pattern":
                name_node = next((c for c in child.named_children if c.type == "identifier"), None)
                parameters.append(
                    Parameter(
                        name=_node_text(name_node, source) if name_node else "**kwargs",
                        position=position,
                        kind="kwarg",
                    )
                )
                position += 1
            elif _node_text(child, source) == "*":
                star_seen = True
        return parameters

    # Stack entries: (node, scope_kind, qualified_name, function_id, class_id,
    #                 deferred, conditional_depth). Explicit stack: no recursion.
    stack: list[tuple] = [(root, "module", module_name, None, None, False, 0)]

    def handle_function(node, decorator_names: tuple[str, ...], ctx: tuple) -> None:  # type: ignore[no-untyped-def]
        scope_kind, qualified, function_id, class_id, deferred, cond_depth = ctx
        name_node = node.child_by_field_name("name")
        name = _node_text(name_node, source) if name_node is not None else "<anonymous>"
        is_method = scope_kind == "class"
        child_qualified = f"{qualified}.{name}"
        params_node = node.child_by_field_name("parameters")
        parameters = function_params(params_node, is_method) if params_node is not None else []
        body_node = node.child_by_field_name("body")
        loc = location(node)
        body_loc = location(body_node) if body_node is not None else loc
        function_id_new = new_id("func", child_qualified, loc.start_line, loc.start_column)
        functions.append(
            FunctionDef(
                id=function_id_new,
                module_id=module_id,
                class_id=class_id if is_method else None,
                qualified_name=child_qualified,
                kind="method" if is_method else "function",
                location=loc,
                body_location=body_loc,
                parameters=tuple(parameters),
                decorator_names=decorator_names,
            )
        )
        if body_node is not None:
            stack.append(
                (
                    body_node,
                    "method" if is_method else "function",
                    child_qualified,
                    function_id_new,
                    class_id if is_method else None,
                    True,
                    cond_depth,
                )
            )

    def handle_class(node, ctx: tuple) -> None:  # type: ignore[no-untyped-def]
        scope_kind, qualified, function_id, class_id, deferred, cond_depth = ctx
        name_node = node.child_by_field_name("name")
        name = _node_text(name_node, source) if name_node is not None else "<anonymous>"
        child_qualified = f"{qualified}.{name}"
        loc = location(node)
        bases: list[str] = []
        superclass = node.child_by_field_name("superclass")
        if superclass is None:
            superclass = next((c for c in node.children if c.type == "argument_list"), None)
        if superclass is not None:
            for arg in superclass.named_children:
                text = dotted(arg)
                if text:
                    bases.append(text)
        class_id_new = new_id("class", child_qualified, loc.start_line, loc.start_column)
        classes.append(
            ClassDef(
                id=class_id_new,
                module_id=module_id,
                qualified_name=child_qualified,
                location=loc,
                base_names=tuple(bases),
            )
        )
        body_node = node.child_by_field_name("body")
        if body_node is not None:
            stack.append(
                (body_node, "class", child_qualified, None, class_id_new, True, cond_depth)
            )

    # Pre-scan the ENTIRE tree for error/missing nodes first. Extraction
    # below only descends selected subtrees (bodies, not signatures), so
    # without this pass, syntax problems hiding in parameters, decorators,
    # or annotations would be missed and the file misreported as clean.
    scan: list = [root]
    while scan:
        current = scan.pop()
        visited += 1
        if visited > NODE_BUDGET:
            complete = False
            diagnostics.append(
                Diagnostic(
                    severity="warning",
                    message="Node budget exceeded; remaining syntax not represented.",
                    location=None,
                    parser=parser,
                    code="node-budget",
                )
            )
            break
        if current.type == "ERROR" or current.is_missing:
            complete = False
            diagnostics.append(
                Diagnostic(
                    severity="error" if current.type == "ERROR" else "warning",
                    message="Unparsable syntax region recovered; representation incomplete.",
                    location=location(current),
                    parser=parser,
                    code="syntax-error" if current.type == "ERROR" else "missing-node",
                )
            )
        scan.extend(reversed(current.children))

    while stack:
        node, scope_kind, qualified, function_id, class_id, deferred, cond_depth = stack.pop()
        visited += 1
        if visited > NODE_BUDGET:
            complete = False
            diagnostics.append(
                Diagnostic(
                    severity="warning",
                    message="Node budget exceeded; remaining syntax not represented.",
                    location=None,
                    parser=parser,
                    code="node-budget",
                )
            )
            break
        node_type = node.type
        if node_type == "ERROR" or node.is_missing:
            # Already reported by the pre-scan; descend generically without
            # interpreting recovered fragments as valid syntax.
            for child in reversed(node.children):
                stack.append(
                    (child, scope_kind, qualified, function_id, class_id, deferred, cond_depth)
                )
            continue

        if node_type in ("function_definition",):
            handle_function(
                node, (), (scope_kind, qualified, function_id, class_id, deferred, cond_depth)
            )
            continue

        if node_type == "decorated_definition":
            decorator_names: list[str] = []
            inner: object = None
            for child in node.named_children:
                if child.type == "decorator":
                    target = child.named_children[0] if child.named_children else None
                    text = dotted(target) if target is not None else None
                    if text:
                        decorator_names.append(text)
                elif child.type in ("function_definition", "class_definition"):
                    inner = child
            if inner is not None and getattr(inner, "type", "") == "function_definition":
                handle_function(
                    inner,
                    tuple(decorator_names),
                    (scope_kind, qualified, function_id, class_id, deferred, cond_depth),
                )
            elif inner is not None:
                handle_class(
                    inner, (scope_kind, qualified, function_id, class_id, deferred, cond_depth)
                )
            else:
                for child in reversed(node.children):
                    stack.append(
                        (child, scope_kind, qualified, function_id, class_id, deferred, cond_depth)
                    )
            continue

        if node_type == "class_definition":
            handle_class(node, (scope_kind, qualified, function_id, class_id, deferred, cond_depth))
            continue

        if node_type in ("import_statement", "import_from_statement"):
            loc = location(node)
            if node_type == "import_statement":
                named = [c for c in node.named_children if c.type == "dotted_name"]
                if not named:
                    unresolved_refs.append(
                        UnresolvedRef(
                            id=new_id("unresolved", "import", loc.start_line, loc.start_column),
                            module_id=module_id,
                            ref_text="<unparsable import>",
                            location=loc,
                        )
                    )
                for child in named:
                    target = _node_text(child, source)
                    imports.append(
                        ImportRef(
                            id=new_id("import", target, loc.start_line, loc.start_column),
                            module_id=module_id,
                            target_text=target,
                            resolution=stdlib_top(target),
                            location=loc,
                            is_conditional=cond_depth > 0,
                            is_deferred=deferred,
                        )
                    )
            else:
                module_node = node.child_by_field_name("module_name")
                module_text = _node_text(module_node, source) if module_node is not None else ""
                relative = any(c.type == "relative_import" for c in node.children)
                imported: list[str] = []
                for child in node.named_children:
                    if child.type == "dotted_name":
                        imported.append(_node_text(child, source))
                    elif child.type == "aliased_import":
                        name_child = child.child_by_field_name("name")
                        if name_child is not None:
                            imported.append(_node_text(name_child, source))
                    elif child.type in ("import_list", "wildcard_import"):
                        imported.append("*")
                for name in imported:
                    target = f"{module_text}.{name}" if module_text else name
                    resolution = (
                        "internal"
                        if relative or module_text.startswith(".")
                        else stdlib_top(module_text.split(".")[0] if module_text else "")
                    )
                    imports.append(
                        ImportRef(
                            id=new_id("import", target, loc.start_line, loc.start_column),
                            module_id=module_id,
                            target_text=target,
                            resolution=resolution,
                            location=loc,
                            is_relative=relative or module_text.startswith("."),
                            is_conditional=cond_depth > 0,
                            is_deferred=deferred,
                        )
                    )
            for child in reversed(node.children):
                stack.append(
                    (child, scope_kind, qualified, function_id, class_id, deferred, cond_depth)
                )
            continue

        if node_type == "call":
            func_node = node.child_by_field_name("function")
            callee = dotted(func_node) if func_node is not None else None
            args_node = node.child_by_field_name("arguments")
            count = len(args_node.named_children) if args_node is not None else 0
            loc = location(node)
            calls.append(
                CallSite(
                    id=new_id("call", callee or "<complex>", loc.start_line, loc.start_column),
                    module_id=module_id,
                    function_id=function_id,
                    callee_text=callee or "<complex>",
                    argument_count=count,
                    location=loc,
                )
            )
            for child in reversed(node.children):
                stack.append(
                    (child, scope_kind, qualified, function_id, class_id, deferred, cond_depth)
                )
            continue

        if node_type == "assignment":
            left = node.child_by_field_name("left")
            names: list[str] = []
            if left is not None:
                text = dotted(left)
                if text:
                    names.append(text)
            loc = location(node)
            assignments.append(
                Assignment(
                    id=new_id(
                        "assign", ",".join(names[:3]) or "assign", loc.start_line, loc.start_column
                    ),
                    module_id=module_id,
                    function_id=function_id,
                    target_names=tuple(names),
                    location=loc,
                )
            )
            for child in reversed(node.children):
                stack.append(
                    (child, scope_kind, qualified, function_id, class_id, deferred, cond_depth)
                )
            continue

        if node_type in ("string", "integer", "float", "true", "false", "none"):
            kind = {
                "string": "string",
                "integer": "number",
                "float": "number",
                "true": "boolean",
                "false": "boolean",
                "none": "none",
            }[node_type]
            loc = location(node)
            literals.append(
                LiteralValue(
                    id=new_id("literal", kind, loc.start_line, loc.start_column),
                    module_id=module_id,
                    function_id=function_id,
                    kind=kind,
                    location=loc,
                )
            )
            continue

        if node_type in (
            "if_statement",
            "if_clause",
            "for_statement",
            "while_statement",
            "try_statement",
            "with_statement",
            "match_statement",
            "list_comprehension",
            "set_comprehension",
            "dictionary_comprehension",
            "generator_expression",
        ):
            kind = {
                "if_statement": "if",
                "if_clause": "if",
                "for_statement": "for",
                "while_statement": "while",
                "try_statement": "try",
                "with_statement": "with",
                "match_statement": "match",
                "list_comprehension": "comprehension",
                "set_comprehension": "comprehension",
                "dictionary_comprehension": "comprehension",
                "generator_expression": "comprehension",
            }[node_type]
            loc = location(node)
            control_flow.append(
                ControlFlow(
                    id=new_id("control", kind, loc.start_line, loc.start_column),
                    module_id=module_id,
                    function_id=function_id,
                    kind=kind,
                    location=loc,
                )
            )
            inner_depth = cond_depth + 1 if kind in ("if", "try") else cond_depth
            for child in reversed(node.children):
                stack.append(
                    (child, scope_kind, qualified, function_id, class_id, deferred, inner_depth)
                )
            if node_type == "try_statement":
                for child in node.children:
                    if child.type in ("except_clause", "finally_clause"):
                        except_loc = location(child)
                        control_flow.append(
                            ControlFlow(
                                id=new_id(
                                    "control",
                                    "except",
                                    except_loc.start_line,
                                    except_loc.start_column,
                                ),
                                module_id=module_id,
                                function_id=function_id,
                                kind="except",
                                location=except_loc,
                            )
                        )
            continue

        for child in reversed(node.children):
            stack.append(
                (child, scope_kind, qualified, function_id, class_id, deferred, cond_depth)
            )

    module = NcmModule(
        id=file_path,
        file_path=file_path,
        language=language,
        name=file_path.rsplit("/", 1)[-1].rsplit(".", 1)[0],
        partially_represented=not complete,
    )
    ncm = NormalizedModule(
        file_path=file_path,
        language=language,
        module=module,
        imports=imports,
        classes=classes,
        functions=functions,
        calls=calls,
        assignments=assignments,
        literals=literals,
        control_flow=control_flow,
        unresolved_refs=unresolved_refs,
        completeness="partially" if not complete else "fully",
        parser=parser,
        parser_version=version,
    )
    return ncm, diagnostics, complete
