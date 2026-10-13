"""Multiple-responsibility heuristic signals (TASK-130).

Conservative, explainable, static-only. Signal categories (docs/08 §6.9/9.5):

* ``size`` — any large-module/class/function signal fires for the unit;
* ``dependency_breadth`` — fan-out or coupling-def-1 exceeds its threshold;
* ``structural_roles`` — the module mixes structural roles (e.g. it holds
  both classes and top-level functions, or several classes alongside
  several functions);
* ``complexity`` — any function in the unit exceeds the complexity signal.

A candidate requires signals from **more than one category**
(ARCH-REQ-072) and is always reported as a *potential* structure requiring
contextual review (ARCH-REQ-073/074), never as a design-principle
violation. Confidence is Low: responsibility boundaries cannot be inferred
reliably from structure (ARCH-REQ-075/076). Size alone never suffices —
and neither does any other single category.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.architecture.models import ArchGraph
from app.analyzers.thresholds import ThresholdSet
from app.ncm import NormalizedModule


@dataclass(frozen=True)
class ResponsibilitySignal:
    """One contributing signal with its category, describing text, and value."""

    category: str  # size | dependency_breadth | structural_roles | complexity
    description: str
    value: int | None = None


@dataclass(frozen=True)
class ResponsibilityCandidate:
    """A unit with multi-category signals (candidate, never a verdict)."""

    subject: str  # module path
    signals: tuple[ResponsibilitySignal, ...]
    categories: tuple[str, ...]


def collect_signals(
    *,
    module_path: str,
    module: NormalizedModule,
    fan_out_value: int | None,
    coupling_value: int | None,
    large_module: bool,
    large_class_names: tuple[str, ...],
    large_functions: tuple[tuple[str, int | None], ...],
    complex_functions: tuple[tuple[str, int | None], ...],
    thresholds: ThresholdSet,
) -> list[ResponsibilitySignal]:
    """Gather candidate signals for one module (pure, deterministic)."""
    signals: list[ResponsibilitySignal] = []
    if large_module:
        signals.append(
            ResponsibilitySignal(
                category="size",
                description="module exceeds a large-module size signal",
            )
        )
    if large_class_names:
        signals.append(
            ResponsibilitySignal(
                category="size",
                description=f"large classes: {', '.join(sorted(large_class_names))}",
                value=len(large_class_names),
            )
        )
    for name, _value in sorted(large_functions):
        signals.append(
            ResponsibilitySignal(
                category="size",
                description=f"large function: {name}",
            )
        )
    exceeded_breadth: list[str] = []
    if fan_out_value is not None and fan_out_value > thresholds.fan_out:
        exceeded_breadth.append(f"fan-out {fan_out_value} > {thresholds.fan_out}")
    if coupling_value is not None and coupling_value > thresholds.coupling:
        exceeded_breadth.append(f"coupling-def-1 {coupling_value} > {thresholds.coupling}")
    for text in exceeded_breadth:
        signals.append(ResponsibilitySignal(category="dependency_breadth", description=text))
    top_functions = sum(1 for fun in module.functions if fun.kind == "function")
    classes = len(module.classes)
    if classes >= 2 and top_functions >= 2:
        signals.append(
            ResponsibilitySignal(
                category="structural_roles",
                description=(
                    f"module mixes roles: {classes} classes alongside "
                    f"{top_functions} top-level functions"
                ),
                value=classes + top_functions,
            )
        )
    for name, _value in sorted(complex_functions):
        signals.append(
            ResponsibilitySignal(category="complexity", description=f"complex function: {name}")
        )
    return signals


def is_candidate(signals: list[ResponsibilitySignal]) -> bool:
    """True only with signals from more than one category (ARCH-REQ-072)."""
    return len({signal.category for signal in signals}) >= 2


def build_candidate(
    module_path: str, signals: list[ResponsibilitySignal]
) -> ResponsibilityCandidate:
    """Assemble a candidate (call only when :func:`is_candidate` holds)."""
    ordered = tuple(sorted(signals, key=lambda signal: (signal.category, signal.description)))
    categories = tuple(sorted({signal.category for signal in ordered}))
    return ResponsibilityCandidate(subject=module_path, signals=ordered, categories=categories)


def graph_context_for_candidate(graph: ArchGraph, module_path: str) -> str:
    """One-line neighbor context for the finding explanation."""
    successors = graph.successors(module_path)
    predecessors = graph.predecessors(module_path)
    return f"depends on {len(successors)} module(s); depended on by {len(predecessors)} module(s)"
