"""Architecture metrics over NCM and the architecture graph (TASK-125–127).

* Fan-out(M) = distinct internal successors; fan-in(M) = distinct internal
  predecessors (docs/08 §5.3/5.4). Self-loops are preserved in the graph
  but excluded from neighbor sets: a module importing itself reveals no
  inter-module structure. This exclusion is documented here and tested.
* Coupling-def-1(M) = |In(M) ∪ Out(M)| (docs/08 §11.1, ARCH-REQ-031/032):
  the size of the set union, never the sum. Overlap counts once.
* Sizes use the §11.1 counting basis: physical lines spanned by the unit's
  source range (module = whole file via bounded source lines when
  available, else the maximum NCM end line; class/function = location
  span); declaration_count = classes + functions (methods included once as
  functions); method_count = methods declared in the class.
* Complexity is a documented NCM-derived lower bound: 1 + the number of
  ``if``/``for``/``while``/``except`` control-flow nodes attributed to the
  function by the parser. Boolean operators, ternaries, comprehensions
  with conditions, and asserts are not represented in NCM (CODE-REQ-001
  lists them), so the true McCabe value is greater than or equal to this
  bound — never smaller. A firing complexity signal is therefore sound
  (no false positive from the bound); possibly-missed exceedances are
  recorded as limitations, and confidence reflects the incompleteness
  (ARCH-REQ-113). The basis string states this on every measurement so a
  future code-structure analyzer can align values (ARCH-REQ-035/064).

Unavailable metrics are ``None`` (ARCH-REQ-027), never zero.
"""

from __future__ import annotations

from app.analyzers.architecture.models import ArchGraph, MetricValue
from app.ncm import ClassDef, FunctionDef, NormalizedModule, SourceLocation

_DECISION_KINDS = frozenset({"if", "for", "while", "except"})

COMPLEXITY_BASIS = (
    "1 + NCM if/for/while/except control-flow nodes attributed to the function; "
    "lower bound (boolean operators, ternaries, comprehensions, asserts not in NCM)"
)

LINES_BASIS = "physical lines spanned by the unit's source range (including blank/comment lines)"


def fan_out(graph: ArchGraph, module: str) -> MetricValue:
    """Distinct internal modules the module depends on (ARCH-REQ-045)."""
    neighbors = graph.successors(module)
    return MetricValue(
        name="fan_out",
        subject=module,
        value=len(neighbors),
        basis="distinct internal successor modules over deduplicated edges",
    )


def fan_in(graph: ArchGraph, module: str) -> MetricValue:
    """Distinct internal modules depending on the module (ARCH-REQ-048)."""
    neighbors = graph.predecessors(module)
    return MetricValue(
        name="fan_in",
        subject=module,
        value=len(neighbors),
        basis="distinct internal predecessor modules over deduplicated edges",
    )


def coupling_def_1(graph: ArchGraph, module: str) -> MetricValue:
    """Union degree |In ∪ Out| over internal edges (ARCH-REQ-031/052)."""
    union = set(graph.successors(module)) | set(graph.predecessors(module))
    return MetricValue(
        name="coupling-def-1",
        subject=module,
        value=len(union),
        basis="coupling-def-1 = |In(M) union Out(M)| over internal edges only",
    )


def _span_lines(start_line: int, end_line: int) -> int | None:
    if start_line < 1 or end_line < start_line:
        return None
    return end_line - start_line + 1


def module_line_count(module: NormalizedModule, source_lines: tuple[str, ...] | None) -> int | None:
    """Module physical lines: source length when available, else NCM max end."""
    if source_lines is not None:
        return len(source_lines)
    maximum = 0
    for location in _iter_locations(module):
        if location.end_line > maximum:
            maximum = location.end_line
    return maximum or None


def _iter_locations(module: NormalizedModule):  # type: ignore[no-untyped-def]
    yield _location_of_module(module)
    for imp in module.imports:
        yield imp.location
    for cls in module.classes:
        yield cls.location
    for fun in module.functions:
        yield fun.location
        yield fun.body_location
    for call in module.calls:
        yield call.location


def _location_of_module(module: NormalizedModule) -> SourceLocation:
    return SourceLocation(
        file_path=module.file_path,
        start_line=1,
        start_column=0,
        end_line=1,
        end_column=0,
    )


def module_declaration_count(module: NormalizedModule) -> int:
    """Classes + functions (methods counted once, as functions)."""
    return len(module.classes) + len(module.functions)


def class_line_count(cls: ClassDef) -> int | None:
    """Physical lines spanned by the class source range."""
    return _span_lines(cls.location.start_line, cls.location.end_line)


def class_method_count(module: NormalizedModule, cls: ClassDef) -> int:
    """Methods declared in the class (FunctionDef with matching class_id)."""
    return sum(1 for fun in module.functions if fun.class_id == cls.id)


def function_line_count(fun: FunctionDef) -> int | None:
    """Physical lines spanned by the function source range."""
    return _span_lines(fun.location.start_line, fun.location.end_line)


def function_complexity_lower_bound(module: NormalizedModule, fun: FunctionDef) -> MetricValue:
    """Lower-bound McCabe complexity for one function (see module docstring)."""
    decisions = sum(
        1
        for node in module.control_flow
        if node.function_id == fun.id and node.kind in _DECISION_KINDS
    )
    return MetricValue(
        name="complexity",
        subject=fun.qualified_name,
        value=1 + decisions,
        potentially_incomplete=True,
        basis=COMPLEXITY_BASIS,
    )
