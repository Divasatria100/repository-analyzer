"""Normalized Code Model (NCM) value objects (docs/12 §11.4).

Parser-independent representation consumed by future analyzers. No
``tree_sitter.Node`` or ``ast.AST`` objects appear here — only plain data
with deterministic, analysis-scoped identity (never object identity or
memory addresses).

Location convention (docs define fields, not numbering): 1-based lines,
0-based columns, matching Python ``ast`` and human-readable result formats.
Tree-sitter's 0-based rows are shifted by adapters. Repository-relative
file paths only — never host paths.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

NCM_SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class SourceLocation:
    """Normalized source span: 1-based lines, 0-based columns."""

    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def to_dict(self) -> dict[str, object]:
        """Serialize for worker transport and diagnostics."""
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SourceLocation:
        """Rebuild from serialized form."""
        return cls(
            file_path=str(data["file_path"]),
            start_line=_integer(data["start_line"]),
            start_column=_integer(data["start_column"]),
            end_line=_integer(data["end_line"]),
            end_column=_integer(data["end_column"]),
        )


@dataclass(frozen=True)
class Diagnostic:
    """Structured parser diagnostic (bounded, secret-free by construction).

    Messages describe syntax conditions (e.g. "invalid syntax"), never
    repository content: adapters must not copy source text into messages.
    """

    severity: str  # error | warning | info
    message: str
    location: SourceLocation | None
    parser: str
    code: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize for worker transport and persistence."""
        return {
            "severity": self.severity,
            "message": self.message,
            "location": self.location.to_dict() if self.location else None,
            "parser": self.parser,
            "code": self.code,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Diagnostic:
        """Rebuild from serialized form."""
        location = data.get("location")
        return cls(
            severity=str(data["severity"]),
            message=str(data["message"]),
            location=SourceLocation.from_dict(location) if isinstance(location, dict) else None,
            parser=str(data["parser"]),
            code=str(data["code"]) if data.get("code") is not None else None,
        )


@dataclass(frozen=True)
class NcmModule:
    """Source unit: one parsed file."""

    id: str
    file_path: str
    language: str
    name: str
    partially_represented: bool = False


@dataclass(frozen=True)
class ImportRef:
    """Directed module edge candidate with static resolution."""

    id: str
    module_id: str
    target_text: str
    resolution: str  # internal | external | unresolved
    location: SourceLocation
    is_relative: bool = False
    is_conditional: bool = False
    is_deferred: bool = False


@dataclass(frozen=True)
class ClassDef:
    """Class declaration with statically visible base names."""

    id: str
    module_id: str
    qualified_name: str
    location: SourceLocation
    base_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class Parameter:
    """One declared parameter (presence only, never default values)."""

    name: str
    position: int
    kind: str  # positional | default | vararg | kwarg | keyword-only
    is_self_cls: bool = False


@dataclass(frozen=True)
class FunctionDef:
    """Function or method declaration with signature shape."""

    id: str
    module_id: str
    class_id: str | None
    qualified_name: str
    kind: str  # function | method
    location: SourceLocation
    body_location: SourceLocation
    parameters: tuple[Parameter, ...] = ()
    decorator_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class CallSite:
    """Call expression: callee as written, never resolved or executed."""

    id: str
    module_id: str
    function_id: str | None
    callee_text: str
    argument_count: int
    location: SourceLocation


@dataclass(frozen=True)
class Assignment:
    """Assignment target names (values never recorded)."""

    id: str
    module_id: str
    function_id: str | None
    target_names: tuple[str, ...] = ()
    location: SourceLocation | None = None


@dataclass(frozen=True)
class LiteralValue:
    """Literal occurrence: kind only, never the value."""

    id: str
    module_id: str
    function_id: str | None
    kind: str  # string | number | boolean | none | other
    location: SourceLocation | None = None


@dataclass(frozen=True)
class ControlFlow:
    """Control-flow structure occurrence (shape only)."""

    id: str
    module_id: str
    function_id: str | None
    kind: str  # if | for | while | try | except | with | match
    location: SourceLocation | None = None


@dataclass(frozen=True)
class UnresolvedRef:
    """Reference the adapter could not resolve statically (never fabricated)."""

    id: str
    module_id: str
    ref_text: str
    location: SourceLocation | None = None


@dataclass
class NormalizedModule:
    """Per-file NCM root: the complete normalized parse product."""

    file_path: str
    language: str
    module: NcmModule
    imports: list[ImportRef] = field(default_factory=list)
    classes: list[ClassDef] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    assignments: list[Assignment] = field(default_factory=list)
    literals: list[LiteralValue] = field(default_factory=list)
    control_flow: list[ControlFlow] = field(default_factory=list)
    unresolved_refs: list[UnresolvedRef] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    completeness: str = "fully"  # fully | partially
    parser: str = ""
    parser_version: str = ""
    ncm_version: str = NCM_SCHEMA_VERSION


def _location_or_none(data: object) -> SourceLocation | None:
    if isinstance(data, dict):
        return SourceLocation.from_dict(data)
    return None


def _get(mapping: dict[str, object], key: str, default: object = None) -> object:
    return mapping.get(key, default)


def _string_list(value: object) -> tuple[str, ...]:
    assert isinstance(value, (list, tuple))
    return tuple(str(item) for item in value)


def _dict_list(value: object) -> list[dict[str, object]]:
    assert isinstance(value, (list, tuple))
    return [item for item in value if isinstance(item, dict)]


def _optional_string(value: object) -> str | None:
    return str(value) if value is not None else None


def _integer(value: object) -> int:
    assert isinstance(value, int)
    return value


def _number(value: object) -> float:
    assert isinstance(value, (int, float))
    return float(value)


def _location_field(mapping: dict[str, object], key: str) -> SourceLocation:
    value = mapping.get(key)
    assert isinstance(value, dict)
    return SourceLocation.from_dict(value)


def ncm_to_dict(module: NormalizedModule) -> dict[str, object]:
    """Serialize an NCM tree to plain JSON-compatible data."""
    return asdict(module)


def ncm_from_dict(data: dict[str, object]) -> NormalizedModule:
    """Rebuild an NCM tree; tuples restored, locations revalidated."""
    module_data = data["module"]
    assert isinstance(module_data, dict)
    module = NcmModule(
        id=str(module_data["id"]),
        file_path=str(module_data["file_path"]),
        language=str(module_data["language"]),
        name=str(module_data["name"]),
        partially_represented=bool(module_data.get("partially_represented", False)),
    )

    def items(key: str) -> list[dict[str, object]]:
        return _dict_list(data.get(key, []))

    imports = [
        ImportRef(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            target_text=str(v["target_text"]),
            resolution=str(v["resolution"]),
            location=_location_field(v, "location"),
            is_relative=bool(v.get("is_relative", False)),
            is_conditional=bool(v.get("is_conditional", False)),
            is_deferred=bool(v.get("is_deferred", False)),
        )
        for v in items("imports")
        if isinstance(v.get("location"), dict)
    ]
    classes = [
        ClassDef(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            qualified_name=str(v["qualified_name"]),
            location=_location_field(v, "location"),
            base_names=_string_list(v.get("base_names", [])),
        )
        for v in items("classes")
        if isinstance(v.get("location"), dict)
    ]
    functions = [
        FunctionDef(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            class_id=_optional_string(v.get("class_id")),
            qualified_name=str(v["qualified_name"]),
            kind=str(v["kind"]),
            location=_location_field(v, "location"),
            body_location=_location_field(v, "body_location"),
            parameters=tuple(
                Parameter(
                    name=str(p["name"]),
                    position=_integer(p["position"]),
                    kind=str(p["kind"]),
                    is_self_cls=bool(p.get("is_self_cls", False)),
                )
                for p in _dict_list(v.get("parameters", []))
            ),
            decorator_names=_string_list(v.get("decorator_names", [])),
        )
        for v in items("functions")
        if isinstance(v.get("location"), dict) and isinstance(v.get("body_location"), dict)
    ]
    calls = [
        CallSite(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            function_id=_optional_string(v.get("function_id")),
            callee_text=str(v["callee_text"]),
            argument_count=_integer(v["argument_count"]),
            location=_location_field(v, "location"),
        )
        for v in items("calls")
        if isinstance(v.get("location"), dict)
    ]
    assignments = [
        Assignment(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            function_id=_optional_string(v.get("function_id")),
            target_names=_string_list(v.get("target_names", [])),
            location=_location_or_none(v.get("location")),
        )
        for v in items("assignments")
    ]
    literals = [
        LiteralValue(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            function_id=_optional_string(v.get("function_id")),
            kind=str(v["kind"]),
            location=_location_or_none(v.get("location")),
        )
        for v in items("literals")
    ]
    control_flow = [
        ControlFlow(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            function_id=_optional_string(v.get("function_id")),
            kind=str(v["kind"]),
            location=_location_or_none(v.get("location")),
        )
        for v in items("control_flow")
    ]
    unresolved_refs = [
        UnresolvedRef(
            id=str(v["id"]),
            module_id=str(v["module_id"]),
            ref_text=str(v["ref_text"]),
            location=_location_or_none(v.get("location")),
        )
        for v in items("unresolved_refs")
    ]
    diagnostics = [Diagnostic.from_dict(v) for v in items("diagnostics") if "message" in v]
    return NormalizedModule(
        file_path=str(data["file_path"]),
        language=str(data["language"]),
        module=module,
        imports=imports,
        classes=classes,
        functions=functions,
        calls=calls,
        assignments=assignments,
        literals=literals,
        control_flow=control_flow,
        unresolved_refs=unresolved_refs,
        diagnostics=diagnostics,
        completeness=str(data.get("completeness", "fully")),
        parser=str(data.get("parser", "")),
        parser_version=str(data.get("parser_version", "")),
        ncm_version=str(data.get("ncm_version", NCM_SCHEMA_VERSION)),
    )
