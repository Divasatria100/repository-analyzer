"""Centralized rule-threshold infrastructure (TASK-091).

Frozen V1.0 defaults live here as the single source of truth
(docs/08 §11.1, docs/10 §5.14A/§5.11A). All comparisons are strict ``>``:
a value exactly at the threshold never exceeds it. Future rules read
thresholds from ``ThresholdSet`` — never magic numbers.

Thresholds are analysis-configuration values, not operator environment:
no new ``REPOLENS_*`` settings are introduced. Overrides construct a new
frozen set (validated, deterministic, serializable) whose effective values
are recorded per analysis.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThresholdSet:
    """Named rule thresholds with frozen V1.0 defaults (all strict ``>``)."""

    fan_out: int = 7
    fan_in: int = 10
    coupling: int = 12
    module_lines: int = 500
    module_declarations: int = 30
    class_lines: int = 200
    class_methods: int = 10
    function_lines: int = 50
    function_complexity: int = 10
    complexity: int = 10
    nesting: int = 4
    parameters: int = 5
    duplicate_tokens: int = 50
    dependencies: int = 200

    def __post_init__(self) -> None:
        """Fail fast on invalid thresholds (silently accepted values hide gaps)."""
        for name in (
            "fan_out",
            "fan_in",
            "coupling",
            "module_lines",
            "module_declarations",
            "class_lines",
            "class_methods",
            "function_lines",
            "function_complexity",
            "complexity",
            "nesting",
            "parameters",
            "duplicate_tokens",
            "dependencies",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"Threshold {name!r} must be a non-negative integer.")

    def exceeds(self, name: str, value: int | float) -> bool:
        """Strict ``>`` comparison against a named threshold."""
        try:
            threshold = getattr(self, name)
        except AttributeError:
            raise ValueError(f"Unknown threshold: {name!r}") from None
        if not isinstance(threshold, int) or isinstance(threshold, bool):
            raise ValueError(f"Unknown threshold: {name!r}")
        return value > threshold

    def effective(self) -> dict[str, object]:
        """Snapshot of effective values for per-analysis recording."""
        return {
            "fan_out": self.fan_out,
            "fan_in": self.fan_in,
            "coupling": self.coupling,
            "module_lines": self.module_lines,
            "module_declarations": self.module_declarations,
            "class_lines": self.class_lines,
            "class_methods": self.class_methods,
            "function_lines": self.function_lines,
            "function_complexity": self.function_complexity,
            "complexity": self.complexity,
            "nesting": self.nesting,
            "parameters": self.parameters,
            "duplicate_tokens": self.duplicate_tokens,
            "dependencies": self.dependencies,
        }


def default_thresholds() -> ThresholdSet:
    """Frozen V1.0 defaults (docs/08 §11.1, docs/10 §5.14A/§5.11A)."""
    return ThresholdSet()
