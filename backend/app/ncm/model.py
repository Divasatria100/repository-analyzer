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
    """Source unit: one parsed file.

    ``layer`` is always ``"unknown"`` at parse time. Layer assignment is
    analyzer inference over NCM evidence (docs/08 §6.8, ARCH-REQ-065/066):
    parsers never invent framework layers, and no directory name becomes
    an authoritative architecture fact here.
    """

    id: str
    file_path: str
    language: str
    name: str
    partially_represented: bool = False
    layer: str = "unknown"


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
        layer=str(module_data.get("layer", "unknown")),
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


@dataclass(frozen=True)
class Relationship:
    """Unified static-reference edge derived from NCM concepts.

    This is a read-only view, not duplicate storage: ``import`` edges mirror
    ``ImportRef`` records, ``call`` edges mirror ``CallSite`` records.
    Class bases stay names-only on ``ClassDef`` (unresolvable bases are
    recorded as unknown, never fabricated into edges).
    Call targets are always ``unresolved`` here — a callee name is evidence
    text, not an established target (resolution belongs to graph analysis).
    """

    id: str
    source_id: str
    target_text: str
    kind: str  # import | call | reference
    location: SourceLocation | None
    resolution: str  # internal | external | unresolved


def derive_relationships(module: NormalizedModule) -> list[Relationship]:
    """Derive unified edges from one module, in stable encounter order.

    Only relationships that can actually be established are created;
    anything else stays an ``unresolved`` reference, never a fabricated
    target (docs/12 §11.4, ARCH-REQ-015).
    """
    relationships: list[Relationship] = []
    for index, imp in enumerate(module.imports):
        relationships.append(
            Relationship(
                id=f"{module.file_path}:rel:import:{index}",
                source_id=module.module.id,
                target_text=imp.target_text,
                kind="import",
                location=imp.location,
                resolution=imp.resolution,
            )
        )
    for index, call in enumerate(module.calls):
        relationships.append(
            Relationship(
                id=f"{module.file_path}:rel:call:{index}",
                source_id=call.function_id or module.module.id,
                target_text=call.callee_text,
                kind="call",
                location=call.location,
                resolution="unresolved",
            )
        )
    return relationships


@dataclass(frozen=True)
class NcmFileEntry:
    """One indexed file's parse outcome: module present iff successfully parsed."""

    path: str
    language: str | None
    parse_state: str  # parsed | parsed_with_diagnostics | failed | unsupported
    module: NormalizedModule | None


@dataclass
class NcmRepository:
    """Analysis-scoped NCM container: repository → files → modules.

    Identity resolves through ``analysis_id`` (no duplicated repository
    identity system, no host paths). ``completeness`` is ``"complete"``
    only when every file is fully represented; anything failed,
    unsupported, or partial makes the repository ``"incomplete"`` with
    explicit reasons — never clean by omission.
    """

    analysis_id: str
    files: list[NcmFileEntry] = field(default_factory=list)

    @property
    def modules(self) -> list[NormalizedModule]:
        """Modules actually represented (failed/unsupported files contribute none)."""
        return [entry.module for entry in self.files if entry.module is not None]

    @property
    def fully_represented_modules(self) -> list[NormalizedModule]:
        """Modules safe for full-confidence downstream use."""
        return [m for m in self.modules if m.completeness == "fully"]

    @property
    def completeness(self) -> str:
        """``complete`` or ``incomplete`` — never inferred from findings."""
        for entry in self.files:
            if entry.module is None or entry.module.completeness != "fully":
                return "incomplete"
        return "complete"

    @property
    def incomplete_reasons(self) -> list[str]:
        """Deterministic per-state reasons for incomplete representation."""
        reasons: list[str] = []
        for entry in sorted(self.files, key=lambda e: e.path):
            if entry.module is None:
                reasons.append(f"{entry.parse_state}: {entry.path}")
            elif entry.module.completeness != "fully":
                reasons.append(f"partial: {entry.path}")
        return reasons


def repository_to_dict(repository: NcmRepository) -> dict[str, object]:
    """Serialize a repository container (round-trips through JSON)."""
    return {
        "analysis_id": repository.analysis_id,
        "files": [
            {
                "path": entry.path,
                "language": entry.language,
                "parse_state": entry.parse_state,
                "module": ncm_to_dict(entry.module) if entry.module is not None else None,
            }
            for entry in repository.files
        ],
    }


def repository_from_dict(data: dict[str, object]) -> NcmRepository:
    """Rebuild a repository container (modules revalidated, never trusted raw)."""
    files_data = data.get("files", [])
    assert isinstance(files_data, list)
    files: list[NcmFileEntry] = []
    for item in files_data:
        assert isinstance(item, dict)
        module_data = item.get("module")
        files.append(
            NcmFileEntry(
                path=str(item["path"]),
                language=str(item["language"]) if item.get("language") is not None else None,
                parse_state=str(item["parse_state"]),
                module=ncm_from_dict(module_data) if isinstance(module_data, dict) else None,
            )
        )
    return NcmRepository(analysis_id=str(data["analysis_id"]), files=files)
