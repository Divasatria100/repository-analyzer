"""Threshold tests (TASK-091): frozen defaults, strict > boundaries, validation."""

import pytest

from app.analyzers.thresholds import ThresholdSet, default_thresholds
from tests.fixtures.helpers.analyzer_helpers import make_thresholds


def test_frozen_defaults() -> None:
    """V1.0 defaults match the frozen requirements exactly."""
    defaults = default_thresholds().effective()
    assert defaults == {
        "fan_out": 7,
        "fan_in": 10,
        "coupling": 12,
        "module_lines": 500,
        "module_declarations": 30,
        "class_lines": 200,
        "class_methods": 10,
        "function_lines": 50,
        "function_complexity": 10,
        "complexity": 10,
        "nesting": 4,
        "parameters": 5,
        "duplicate_tokens": 50,
        "dependencies": 200,
    }


@pytest.mark.parametrize(
    ("name", "at", "over"),
    [
        ("fan_out", 7, 8),
        ("fan_in", 10, 11),
        ("coupling", 12, 13),
        ("module_lines", 500, 501),
        ("module_declarations", 30, 31),
        ("class_lines", 200, 201),
        ("class_methods", 10, 11),
        ("function_lines", 50, 51),
        ("function_complexity", 10, 11),
        ("complexity", 10, 11),
        ("nesting", 4, 5),
        ("parameters", 5, 6),
        ("duplicate_tokens", 50, 51),
        ("dependencies", 200, 201),
    ],
)
def test_strict_exceedance_boundaries(name: str, at: int, over: int) -> None:
    """At-threshold never exceeds; one over always does (never >=)."""
    thresholds = default_thresholds()
    assert thresholds.exceeds(name, at) is False
    assert thresholds.exceeds(name, at - 1) is False
    assert thresholds.exceeds(name, over) is True


def test_unknown_threshold_rejected() -> None:
    """Unknown names fail fast instead of silently returning False."""
    with pytest.raises(ValueError, match="Unknown threshold"):
        default_thresholds().exceeds("nope", 10**9)


def test_invalid_threshold_values_rejected() -> None:
    """Negative, boolean, and non-integer thresholds are invalid."""
    with pytest.raises(ValueError):
        ThresholdSet(fan_out=-1)
    with pytest.raises(ValueError):
        ThresholdSet(nesting=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ThresholdSet(parameters=2.5)  # type: ignore[arg-type]


def test_deterministic_resolution_and_snapshot() -> None:
    """Overrides validate; effective snapshot is stable and JSON-safe."""
    import json

    custom = make_thresholds(fan_out=9, nesting=6)
    assert custom.exceeds("fan_out", 9) is False
    assert custom.exceeds("fan_out", 10) is True
    assert custom.exceeds("nesting", 7) is True
    snapshot = custom.effective()
    assert snapshot["fan_out"] == 9
    assert snapshot["nesting"] == 6
    assert json.dumps(snapshot, sort_keys=True)
    assert default_thresholds().effective()["fan_out"] == 7


def test_threshold_set_is_frozen() -> None:
    """Thresholds cannot be mutated after construction (deterministic config)."""
    import dataclasses

    thresholds = default_thresholds()
    with pytest.raises(dataclasses.FrozenInstanceError):
        thresholds.fan_out = 99  # type: ignore[misc]
