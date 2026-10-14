"""Code-structure value objects (Phase 10, TASK-135–144).

Pure data over the Normalized Code Model: per-function measurements with
explicit availability, duplicate-candidate groups, and hotspot records. No
parsers, no I/O, no network — deterministic transformations of NCM input
(plus bounded source lines supplied by callers for token evidence only).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FunctionMeasurement:
    """One measured value for one function/method with its basis."""

    name: str  # complexity | nesting_depth | parameter_count
    path: str  # repository-relative file path
    qualified_name: str
    value: int | None  # None means unmeasurable (never silent zero)
    basis: str = ""
    potentially_incomplete: bool = False


@dataclass(frozen=True)
class DecisionPoint:
    """One counted complexity decision with its source location."""

    kind: str  # if | for | while | except
    path: str
    line: int
    column: int = 0


@dataclass(frozen=True)
class ComplexityMetric:
    """McCabe measurement over the NCM-representable decision set."""

    measurement: FunctionMeasurement
    decisions: tuple[DecisionPoint, ...] = ()


@dataclass(frozen=True)
class NestingMetric:
    """Maximum block-nesting depth with the deepest location."""

    measurement: FunctionMeasurement
    deepest_path: str = ""
    deepest_line: int = 0


@dataclass(frozen=True)
class DuplicateLocation:
    """One member location of a duplicate-candidate group."""

    path: str
    qualified_name: str
    start_line: int
    end_line: int
    matched_tokens: int | None = None  # None when exact length was capped


@dataclass(frozen=True)
class DuplicateGroup:
    """One duplicate-candidate group (candidate, never a verdict)."""

    members: tuple[DuplicateLocation, ...]  # sorted, primary first
    matched_tokens: int  # longest shared run found (exact) or minimum (bound)
    exact: bool = True  # False when any member length is a lower bound


@dataclass(frozen=True)
class Hotspot:
    """One review-ordering entry: a symbol with notable measurements.

    A hotspot carries measurements side by side. It never carries a score,
    rank, weight, or grade (docs/14 §12.3, FR-065).
    """

    path: str
    symbol: str
    kind: str  # function | method
    signal_count: int
    measurements: tuple[dict[str, object], ...] = ()
    finding_ids: tuple[str, ...] = ()


@dataclass
class CodeReport:
    """Duplicate-detection outcome with explicit coverage records."""

    groups: list[DuplicateGroup] = field(default_factory=list)
    compared_bodies: int = 0
    skipped_bodies: int = 0
    pair_evaluations_capped: bool = False
    limited: bool = False
    limitation_reasons: tuple[str, ...] = ()
