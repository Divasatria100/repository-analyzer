"""Python AST parser adapter: source text in, NCM out, never execution.

Parses with stdlib ``ast`` only. Repository modules are never imported;
no ``importlib``/``exec``/``eval``/``compile``-for-execution/subprocess
appears here or anywhere on this path. Syntax errors become failed results
with structured diagnostics; one file never affects another (isolation is
enforced by the pipeline running each file independently).
"""

from __future__ import annotations

import ast
import platform
import sys
import time
from dataclasses import dataclass, field

from app.ncm import (
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
    ParseResult,
    ParseState,
    SourceLocation,
    UnresolvedRef,
)
from app.parsers.base import ParserAdapter, ParserInput

ADAPTER_NAME = "python-ast"
MAX_DIAGNOSTIC_MESSAGE = 500


def _parser_version() -> str:
    return f"python-{platform.python_version()}"


def _truncate(message: str) -> str:
    if len(message) > MAX_DIAGNOSTIC_MESSAGE:
        return message[:MAX_DIAGNOSTIC_MESSAGE] + "…"
    return message


@dataclass
class _Scope:
    kind: str  # module | class | function
    qualified_name: str
    function_id: str | None = None
    class_id: str | None = None
    conditional_depth: int = 0
    deferred: bool = False


@dataclass
class _Builder:
    file_path: str
    module_id: str
    module_name: str
    imports: list[ImportRef] = field(default_factory=list)
    classes: list[ClassDef] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    assignments: list[Assignment] = field(default_factory=list)
    literals: list[LiteralValue] = field(default_factory=list)
    control_flow: list[ControlFlow] = field(default_factory=list)
    unresolved_refs: list[UnresolvedRef] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    counter: int = 0

    def new_id(self, kind: str, qualified_name: str, line: int, column: int) -> str:
        """Deterministic analysis-scoped id (no object identity involved)."""
        self.counter += 1
        return f"{self.file_path}:{kind}:{qualified_name}:{line}:{column}"


def _location(file_path: str, node: ast.AST) -> SourceLocation:
    """1-based lines; ast columns are already 0-based."""
    lineno = getattr(node, "lineno", 1) or 1
    col = getattr(node, "col_offset", 0) or 0
    end_lineno = getattr(node, "end_lineno", None) or lineno
    end_col = getattr(node, "end_col_offset", None)
    if end_col is None:
        end_col = col
    return SourceLocation(
        file_path=file_path,
        start_line=int(lineno),
        start_column=int(col),
        end_line=int(end_lineno),
        end_column=int(end_col),
    )


def _dotted(node: ast.AST) -> str | None:
    """Dotted name for Name/Attribute chains; None when not statically named."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _stdlib_top_levels() -> frozenset[str]:
    return frozenset(sys.stdlib_module_names)


class _Walker:
    """Recursive AST visitor building NCM (runs inside the timeout worker)."""

    def __init__(self, builder: _Builder) -> None:
        self._builder = builder
        self._stdlib = _stdlib_top_levels()

    def _scope_child(
        self, scope: _Scope, kind: str, name: str, *, deferred: bool | None = None
    ) -> _Scope:
        qualified = f"{scope.qualified_name}.{name}" if scope.qualified_name else name
        return _Scope(
            kind=kind,
            qualified_name=qualified,
            deferred=True if deferred is None and scope.kind != "module" else bool(deferred),
            conditional_depth=scope.conditional_depth,
        )

    def _resolution(self, top_level: str, is_relative: bool) -> str:
        if is_relative:
            return "internal"
        if top_level in self._stdlib:
            return "external"
        return "unresolved"

    def visit_module(self, tree: ast.Module) -> None:
        """Walk top-level statements in source order (deterministic)."""
        scope = _Scope(kind="module", qualified_name=self._builder.module_name)
        for statement in tree.body:
            self.visit_statement(statement, scope)

    def visit_statement(self, node: ast.AST, scope: _Scope) -> None:
        """Dispatch one statement; unknown forms are skipped, never executed."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.visit_function(node, scope, is_async=isinstance(node, ast.AsyncFunctionDef))
        elif isinstance(node, ast.ClassDef):
            self.visit_class(node, scope)
        elif isinstance(node, ast.Import):
            self.visit_import(node, scope)
        elif isinstance(node, ast.ImportFrom):
            self.visit_import_from(node, scope)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            self.visit_assignment(node, scope)
            self.visit_expression(getattr(node, "value", None), scope)
            if isinstance(node, ast.AnnAssign):
                self.visit_expression(node.annotation, scope)
                if node.target is not None:
                    self.visit_expression(node.target, scope)
        elif isinstance(node, ast.Expr):
            self.visit_expression(node.value, scope)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.visit_expression(node.value, scope)
        elif isinstance(node, ast.If):
            self._control(node, scope, "if")
            self._visit_test(node, scope)
            for child in node.body + node.orelse:
                self.visit_statement(child, scope)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._control(node, scope, "for")
            self.visit_expression(node.iter, scope)
            for child in node.body + node.orelse:
                self.visit_statement(child, scope)
        elif isinstance(node, ast.While):
            self._control(node, scope, "while")
            self.visit_expression(node.test, scope)
            for child in node.body + node.orelse:
                self.visit_statement(child, scope)
        elif isinstance(node, ast.Try):
            self._control(node, scope, "try")
            for child in node.body + node.orelse + node.finalbody:
                self.visit_statement(child, scope)
            for handler in node.handlers:
                self._control(handler, scope, "except")
                inner = _Scope(
                    kind=scope.kind,
                    qualified_name=scope.qualified_name,
                    function_id=scope.function_id,
                    class_id=scope.class_id,
                    conditional_depth=scope.conditional_depth + 1,
                    deferred=scope.deferred,
                )
                for child in handler.body:
                    self.visit_statement(child, inner)
        elif isinstance(node, ast.TryStar):
            self._control(node, scope, "try")
            for child in node.body + node.orelse + node.finalbody:
                self.visit_statement(child, scope)
            for handler in node.handlers:
                self._control(handler, scope, "except")
                inner = _Scope(
                    kind=scope.kind,
                    qualified_name=scope.qualified_name,
                    function_id=scope.function_id,
                    class_id=scope.class_id,
                    conditional_depth=scope.conditional_depth + 1,
                    deferred=scope.deferred,
                )
                for child in handler.body:
                    self.visit_statement(child, inner)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self._control(node, scope, "with")
            for item in node.items:
                self.visit_expression(item.context_expr, scope)
            for child in node.body:
                self.visit_statement(child, scope)
        elif isinstance(node, ast.Match):
            self._control(node, scope, "match")
            self.visit_expression(node.subject, scope)
            for case in node.cases:
                for child in case.body:
                    self.visit_statement(child, scope)
        elif isinstance(node, (ast.Delete, ast.Assert)):
            for sub in ast.iter_child_nodes(node):
                if isinstance(sub, ast.expr):
                    self.visit_expression(sub, scope)
        else:
            for sub in ast.iter_child_nodes(node):
                if isinstance(sub, ast.stmt):
                    self.visit_statement(sub, scope)
                elif isinstance(sub, ast.expr):
                    self.visit_expression(sub, scope)

    def _visit_test(self, node: ast.AST, scope: _Scope) -> None:
        test = getattr(node, "test", None)
        if test is not None:
            self.visit_expression(test, scope)

    def _control(self, node: ast.AST, scope: _Scope, kind: str) -> None:
        builder = self._builder
        location = _location(builder.file_path, node)
        builder.control_flow.append(
            ControlFlow(
                id=builder.new_id("control", kind, location.start_line, location.start_column),
                module_id=builder.module_id,
                function_id=scope.function_id,
                kind=kind,
                location=location,
            )
        )

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        scope: _Scope,
        *,
        is_async: bool = False,
    ) -> None:
        """Record function/method/lambda with signature shape (never called)."""
        builder = self._builder
        if isinstance(node, ast.Lambda):
            name, kind, class_id = "<lambda>", "function", None
            decorators: list[str] = []
            args = node.args
            location = _location(builder.file_path, node)
            body_location = location
        else:
            name = node.name
            in_class = scope.kind == "class"
            kind = "method" if in_class else "function"
            class_id = scope.class_id if in_class else None
            decorators = [
                dotted for decorator in node.decorator_list if (dotted := _dotted(decorator))
            ]
            args = node.args
            location = _location(builder.file_path, node)
            body_location = self._body_span(node)
        child = self._scope_child(scope, "method" if kind == "method" else "function", name)
        parameters = self._parameters(args, kind == "method")
        function_id = builder.new_id(
            "func", child.qualified_name, location.start_line, location.start_column
        )
        builder.functions.append(
            FunctionDef(
                id=function_id,
                module_id=builder.module_id,
                class_id=class_id,
                qualified_name=child.qualified_name,
                kind=kind,
                location=location,
                body_location=body_location,
                parameters=tuple(parameters),
                decorator_names=tuple(decorators),
            )
        )
        inner = _Scope(
            kind=child.kind,
            qualified_name=child.qualified_name,
            function_id=function_id,
            class_id=class_id,
            conditional_depth=scope.conditional_depth,
            deferred=True,
        )
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        for child_node in body:
            self.visit_statement(child_node, inner)

    def _body_span(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> SourceLocation:
        if not node.body:
            return _location(self._builder.file_path, node)
        first = _location(self._builder.file_path, node.body[0])
        last = _location(self._builder.file_path, node.body[-1])
        return SourceLocation(
            file_path=self._builder.file_path,
            start_line=first.start_line,
            start_column=first.start_column,
            end_line=last.end_line,
            end_column=last.end_column,
        )

    def _parameters(self, args: ast.arguments, is_method: bool) -> list[Parameter]:
        """Parameter presence/kinds; first self/cls flagged, values never kept."""
        parameters: list[Parameter] = []
        position = 0

        def add(name: str, kind: str) -> None:
            nonlocal position
            parameters.append(
                Parameter(
                    name=name,
                    position=position,
                    kind=kind,
                    is_self_cls=is_method and position == 0 and name in ("self", "cls"),
                )
            )
            position += 1

        plain = list(args.posonlyargs) + list(args.args)
        # Defaults align to the LAST N positional parameters (identity of
        # value nodes is meaningless here — position is what counts).
        defaulted_positions = set(range(len(plain) - len(args.defaults), len(plain)))
        for index, argument in enumerate(plain):
            add(
                argument.arg,
                "default" if index in defaulted_positions else "positional",
            )
        if args.vararg is not None:
            add(args.vararg.arg, "vararg")
        for argument in args.kwonlyargs:
            add(argument.arg, "keyword-only")
        if args.kwarg is not None:
            add(args.kwarg.arg, "kwarg")
        return parameters

    def visit_class(self, node: ast.ClassDef, scope: _Scope) -> None:
        """Record class with statically visible bases (unknown bases skipped)."""
        builder = self._builder
        child = self._scope_child(scope, "class", node.name)
        location = _location(builder.file_path, node)
        bases = [dotted for base in node.bases for dotted in [_dotted(base)] if dotted]
        class_id = builder.new_id(
            "class", child.qualified_name, location.start_line, location.start_column
        )
        builder.classes.append(
            ClassDef(
                id=class_id,
                module_id=builder.module_id,
                qualified_name=child.qualified_name,
                location=location,
                base_names=tuple(bases),
            )
        )
        inner = _Scope(
            kind="class",
            qualified_name=child.qualified_name,
            class_id=class_id,
            conditional_depth=scope.conditional_depth,
            deferred=True,
        )
        for child_node in node.body:
            self.visit_statement(child_node, inner)

    def visit_import(self, node: ast.Import, scope: _Scope) -> None:
        """Record absolute imports; stdlib is external, rest unresolved."""
        builder = self._builder
        location = _location(builder.file_path, node)
        for alias in node.names:
            top = alias.name.split(".")[0]
            builder.imports.append(
                ImportRef(
                    id=builder.new_id(
                        "import", alias.name, location.start_line, location.start_column
                    ),
                    module_id=builder.module_id,
                    target_text=alias.name,
                    resolution=self._resolution(top, is_relative=False),
                    location=location,
                    is_relative=False,
                    is_conditional=scope.conditional_depth > 0,
                    is_deferred=scope.deferred,
                )
            )

    def visit_import_from(self, node: ast.ImportFrom, scope: _Scope) -> None:
        """Record from-imports; relative imports resolve internally."""
        builder = self._builder
        location = _location(builder.file_path, node)
        dots = "." * node.level
        dotted_module = f"{dots}{node.module}" if node.module else dots
        for alias in node.names:
            if alias.name == "*":
                target = dotted_module
            elif dotted_module.endswith(".") or not dotted_module:
                target = f"{dotted_module}{alias.name}"
            else:
                target = f"{dotted_module}.{alias.name}"
            if node.level and node.level > 0:
                resolution = "internal"
            else:
                top = (node.module or "").split(".")[0]
                resolution = self._resolution(top, is_relative=False)
            builder.imports.append(
                ImportRef(
                    id=builder.new_id("import", target, location.start_line, location.start_column),
                    module_id=builder.module_id,
                    target_text=target,
                    resolution=resolution,
                    location=location,
                    is_relative=node.level > 0,
                    is_conditional=scope.conditional_depth > 0,
                    is_deferred=scope.deferred,
                )
            )

    def visit_assignment(
        self, node: ast.Assign | ast.AnnAssign | ast.AugAssign, scope: _Scope
    ) -> None:
        """Record assigned target names (values never recorded)."""
        builder = self._builder
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            targets = [node.target]
        names: list[str] = []
        for target in targets:
            names.extend(self._target_names(target))
        location = _location(builder.file_path, node)
        builder.assignments.append(
            Assignment(
                id=builder.new_id(
                    "assign",
                    ",".join(names[:3]) or "assign",
                    location.start_line,
                    location.start_column,
                ),
                module_id=builder.module_id,
                function_id=scope.function_id,
                target_names=tuple(names),
                location=location,
            )
        )

    def _target_names(self, target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            dotted = _dotted(target)
            return [dotted] if dotted else []
        if isinstance(target, ast.Starred):
            return self._target_names(target.value)
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for element in target.elts:
                names.extend(self._target_names(element))
            return names
        return []

    def visit_expression(self, node: ast.AST | None, scope: _Scope) -> None:
        """Walk expressions for calls, literals, comprehensions (never evaluate)."""
        if node is None:
            return
        builder = self._builder
        if isinstance(node, ast.Call):
            callee = _dotted(node.func) or "<complex>"
            location = _location(builder.file_path, node)
            builder.calls.append(
                CallSite(
                    id=builder.new_id("call", callee, location.start_line, location.start_column),
                    module_id=builder.module_id,
                    function_id=scope.function_id,
                    callee_text=callee,
                    argument_count=len(node.args) + len(node.keywords),
                    location=location,
                )
            )
            self.visit_expression(node.func, scope)
            for argument in node.args:
                self.visit_expression(argument, scope)
            for keyword in node.keywords:
                self.visit_expression(keyword.value, scope)
            return
        if isinstance(node, ast.Lambda):
            self.visit_function(node, scope)
            return
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, str):
                kind = "string"
            elif isinstance(value, bool):
                kind = "boolean"
            elif value is None:
                kind = "none"
            elif isinstance(value, (int, float, complex)):
                kind = "number"
            else:
                kind = "other"
            location = _location(builder.file_path, node)
            builder.literals.append(
                LiteralValue(
                    id=builder.new_id("literal", kind, location.start_line, location.start_column),
                    module_id=builder.module_id,
                    function_id=scope.function_id,
                    kind=kind,
                    location=location,
                )
            )
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            location = _location(builder.file_path, node)
            builder.control_flow.append(
                ControlFlow(
                    id=builder.new_id(
                        "control", "comprehension", location.start_line, location.start_column
                    ),
                    module_id=builder.module_id,
                    function_id=scope.function_id,
                    kind="comprehension",
                    location=location,
                )
            )
            for generator in node.generators:
                self.visit_expression(generator.iter, scope)
                for condition in generator.ifs:
                    if_location = _location(builder.file_path, condition)
                    builder.control_flow.append(
                        ControlFlow(
                            id=builder.new_id(
                                "control", "if", if_location.start_line, if_location.start_column
                            ),
                            module_id=builder.module_id,
                            function_id=scope.function_id,
                            kind="if",
                            location=if_location,
                        )
                    )
                    self.visit_expression(condition, scope)
            if isinstance(node, ast.DictComp):
                self.visit_expression(node.key, scope)
                self.visit_expression(node.value, scope)
            else:
                self.visit_expression(node.elt, scope)
            return
        if isinstance(node, ast.NamedExpr):
            builder.assignments.append(
                Assignment(
                    id=builder.new_id(
                        "assign",
                        node.target.id if isinstance(node.target, ast.Name) else "walrus",
                        _location(builder.file_path, node).start_line,
                        _location(builder.file_path, node).start_column,
                    ),
                    module_id=builder.module_id,
                    function_id=scope.function_id,
                    target_names=tuple(self._target_names(node.target)),
                    location=_location(builder.file_path, node),
                )
            )
            self.visit_expression(node.value, scope)
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.visit_expression(child, scope)


class PythonAstAdapter(ParserAdapter):
    """Stdlib ``ast`` adapter for Python (no import, no execution)."""

    name = "python-ast"
    supported_languages = frozenset({"python"})

    def __init__(self) -> None:
        self.parser_version = _parser_version()

    def parse(self, data: ParserInput) -> ParseResult:
        """Parse bounded bytes; syntax problems become failed diagnostics."""
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
            tree = ast.parse(text, filename=data.relative_path)
        except SyntaxError as exc:
            return self._failed_syntax(data, exc)
        except (RecursionError, MemoryError, ValueError) as exc:
            return self._failed(
                data, f"Python parser rejected the input ({type(exc).__name__}).", "rejected"
            )
        builder = _Builder(
            file_path=data.relative_path,
            module_id=data.relative_path,
            module_name=data.relative_path.rsplit("/", 1)[-1].rsplit(".", 1)[0],
        )
        try:
            _Walker(builder).visit_module(tree)
        except RecursionError:
            return self._failed(
                data, "Source nesting exceeds parser recursion capacity.", "recursion"
            )
        duration_ms = (time.perf_counter() - started) * 1000.0
        module = NcmModule(
            id=data.relative_path,
            file_path=data.relative_path,
            language=data.language,
            name=builder.module_name,
        )
        ncm = NormalizedModule(
            file_path=data.relative_path,
            language=data.language,
            module=module,
            imports=builder.imports,
            classes=builder.classes,
            functions=builder.functions,
            calls=builder.calls,
            assignments=builder.assignments,
            literals=builder.literals,
            control_flow=builder.control_flow,
            unresolved_refs=builder.unresolved_refs,
            completeness="fully",
            parser=self.name,
            parser_version=self.parser_version,
        )
        return ParseResult(
            state=ParseState.PARSED,
            ncm=ncm,
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

    def _failed_syntax(self, data: ParserInput, exc: SyntaxError) -> ParseResult:
        lineno = exc.lineno or 1
        column = max((exc.offset or 1) - 1, 0)
        end_line = exc.end_lineno or lineno
        end_column = max((exc.end_offset or exc.offset or 1) - 1, column)
        location = SourceLocation(
            file_path=data.relative_path,
            start_line=lineno,
            start_column=column,
            end_line=end_line,
            end_column=end_column,
        )
        return ParseResult(
            state=ParseState.FAILED,
            ncm=None,
            diagnostics=[
                Diagnostic(
                    severity="error",
                    message=_truncate(str(exc.msg)),
                    location=location,
                    parser=self.name,
                    code="SyntaxError",
                )
            ],
            parser_name=self.name,
            parser_version=self.parser_version,
        )
