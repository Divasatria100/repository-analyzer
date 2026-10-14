"""Code-structure measurements over NCM (TASK-135/136/137).

* Complexity (TASK-135, CODE-REQ-001): ``M = 1 + D`` where ``D`` counts the
  decision points representable in NCM: ``if``/``elif`` branches,
  ``for``/``while`` loops, and ``except`` handlers attributed to the
  function by the parser. Boolean operators, ternary expressions,
  comprehensions with conditions, and ``assert`` statements are not
  represented in NCM, so the value is a lower bound of true McCabe
  complexity: sound when it exceeds the threshold (the true value can only
  be greater), never presented as a complete measurement. The basis string
  states this on every result, and findings carry an explicit limitation.
  Identical formula to architecture ``ARCH-LARGE-FUNCTION`` (PIPE-REQ-054);
  equality is asserted by cross-domain tests.
* Nesting (TASK-136, CODE-REQ-002): maximum block-nesting depth inside the
  function/method body from NCM location containment. Depth-increasing:
  ``if``, ``for``, ``while``, ``with``, ``try`` bodies, ``except`` bodies
  (same level as their ``try`` body — handlers add no further depth), and
  nested ``def``/``class`` bodies. ``match`` is not listed by the contract
  and adds no depth. Module-level code, class-body attribute hierarchy, and
  data-structure literals never count: only nodes attributed to the
  function (plus nested declarations located inside its body) participate.
* Parameters (TASK-137, CODE-REQ-003): each declared parameter counts 1,
  including defaults, ``*args``/``**kwargs`` (1 each), and keyword-only
  parameters. The first ``self``/``cls`` parameter of a method (NCM
  ``is_self_cls`` at position 0) is excluded. Default expressions, locals,
  and call-site arguments are never counted.

Unmeasurable values are ``None``, never zero. Everything is deterministic.
"""

from __future__ import annotations

from app.analyzers.code_structure.models import (
    ComplexityMetric,
    DecisionPoint,
    FunctionMeasurement,
    NestingMetric,
)
from app.ncm import FunctionDef, NormalizedModule

#: Control-flow kinds that are McCabe decision points in NCM.
DECISION_KINDS = frozenset({"if", "for", "while", "except"})

#: Control-flow kinds increasing block-nesting depth (CODE-REQ-002).
_NESTING_KINDS = frozenset({"if", "for", "while", "with", "try"})

COMPLEXITY_BASIS = (
    "McCabe M = 1 + NCM if/elif/for/while/except decisions attributed to the function; "
    "lower bound (boolean operators, ternaries, comprehensions with conditions, and "
    "asserts are not represented in NCM)"
)

NESTING_BASIS = (
    "maximum block-nesting depth from NCM location containment; "
    "if/for/while/with/try bodies and nested def/class bodies add depth, "
    "except bodies sit level with their try body"
)

PARAMETER_BASIS = (
    "each declared parameter counts 1 (defaults, *args/**kwargs, keyword-only included); "
    "first self/cls of a method excluded"
)


def mccabe_complexity(module: NormalizedModule, fun: FunctionDef) -> ComplexityMetric:
    """McCabe complexity over the NCM-representable decision set (TASK-135)."""
    decisions: list[DecisionPoint] = []
    for node in module.control_flow:
        if node.function_id != fun.id or node.kind not in DECISION_KINDS:
            continue
        if node.location is None:
            continue
        decisions.append(
            DecisionPoint(
                kind=node.kind,
                path=module.file_path,
                line=node.location.start_line,
                column=node.location.start_column,
            )
        )
    decisions.sort(key=lambda item: (item.line, item.column, item.kind))
    measurement = FunctionMeasurement(
        name="complexity",
        path=module.file_path,
        qualified_name=fun.qualified_name,
        value=1 + len(decisions),
        basis=COMPLEXITY_BASIS,
        potentially_incomplete=True,
    )
    return ComplexityMetric(measurement=measurement, decisions=tuple(decisions))


def _span_contains(outer_start: int, outer_end: int, inner_start: int, inner_end: int) -> bool:
    return outer_start <= inner_start and inner_end <= outer_end


def nesting_depth(module: NormalizedModule, fun: FunctionDef) -> NestingMetric:
    """Maximum block-nesting depth inside the function body (TASK-136)."""
    body = fun.body_location
    # Candidate nodes: attributed control flow with locations inside the body,
    # plus nested def/class declarations located inside the body.
    candidates: list[tuple[str, int, int, int]] = []
    for node in module.control_flow:
        if node.function_id != fun.id or node.location is None:
            continue
        if node.kind not in _NESTING_KINDS and node.kind != "except":
            continue
        start, end = node.location.start_line, node.location.end_line
        if _span_contains(body.start_line, body.end_line, start, end):
            candidates.append((node.kind, start, end, start))
    for cls in module.classes:
        start, end = cls.location.start_line, cls.location.end_line
        if (start, end) != (body.start_line, body.end_line) and _span_contains(
            body.start_line, body.end_line, start, end
        ):
            candidates.append(("class", start, end, start))
    for other in module.functions:
        if other.id == fun.id:
            continue
        start, end = other.location.start_line, other.location.end_line
        if _span_contains(body.start_line, body.end_line, start, end):
            candidates.append(("def", start, end, start))
    # Parent = smallest strictly containing span (or the body root); stable order.
    order = sorted(range(len(candidates)), key=lambda i: (candidates[i][1], -(candidates[i][2])))
    parent: dict[int, int | None] = {}
    for position, index in enumerate(order):
        _, start, end, _ = candidates[index]
        best: int | None = None
        best_span = body.end_line - body.start_line + 1
        for other_position in range(position):
            candidate_index = order[other_position]
            _, other_start, other_end, _ = candidates[candidate_index]
            if (
                other_start <= start
                and end <= other_end
                and (other_start, other_end)
                != (
                    start,
                    end,
                )
            ):
                span = other_end - other_start
                if span < best_span:
                    best_span = span
                    best = candidate_index
        parent[index] = best
    depth_of: dict[int, int] = {}
    max_depth = 0
    deepest_line = body.start_line
    for index in order:
        kind, _, _, line = candidates[index]
        ancestor = parent[index]
        if ancestor is None:
            # A top-level block (or an orphan handler) sits one level deep.
            depth = 1
        elif kind == "except":
            # Handlers sit level with their try body, never deeper.
            depth = depth_of[ancestor]
        else:
            depth = depth_of[ancestor] + 1
        depth_of[index] = depth
        if depth > max_depth:
            max_depth = depth
            deepest_line = line
    # An except node whose smallest container is not its try still sits level
    # with that container rather than adding depth: handled by the +0 rule.
    measurement = FunctionMeasurement(
        name="nesting_depth",
        path=module.file_path,
        qualified_name=fun.qualified_name,
        value=max_depth,
        basis=NESTING_BASIS,
        potentially_incomplete=False,
    )
    return NestingMetric(
        measurement=measurement, deepest_path=module.file_path, deepest_line=deepest_line
    )


def parameter_count(module_path: str, fun: FunctionDef) -> FunctionMeasurement:
    """Declared parameter count per CODE-REQ-003 (TASK-137)."""
    total = 0
    for parameter in fun.parameters:
        if parameter.position == 0 and parameter.is_self_cls and fun.kind == "method":
            continue
        total += 1
    return FunctionMeasurement(
        name="parameter_count",
        path=module_path,
        qualified_name=fun.qualified_name,
        value=total,
        basis=PARAMETER_BASIS,
        potentially_incomplete=False,
    )
