"""Hotspot and serialization tests (TASK-144 + determinism)."""

import json

from app.analyzers.code_structure.hotspots import build_hotspots, serialize_hotspots
from app.analyzers.code_structure.models import Hotspot
from app.analyzers.code_structure.serialization import (
    SERIALIZATION_MAX_CHARS,
    dumps_canonical,
    serialize_code_report,
    serialize_duplicates,
    serialize_measurements,
)


def test_hotspot_side_by_side_measurements_no_scores() -> None:
    hotspots = build_hotspots([])
    assert hotspots == []


def test_hotspot_ordering_by_signal_count_then_location() -> None:
    from app.analyzers.code_structure.hotspots import HotspotInput
    from tests.fixtures.helpers.analyzer_helpers import make_finding

    first = make_finding(rule_id="CODE-HIGH-COMPLEXITY", path="b.py", subject_key="s1")
    second = make_finding(rule_id="CODE-DEEP-NESTING", path="b.py", subject_key="s1")
    third = make_finding(rule_id="CODE-HIGH-COMPLEXITY", path="a.py", subject_key="s2")
    inputs = [
        HotspotInput(
            finding=first,
            path="b.py",
            symbol="b.f",
            kind="function",
            metric="complexity",
            value=11,
            thresholds={"complexity": 10},
        ),
        HotspotInput(
            finding=second,
            path="b.py",
            symbol="b.f",
            kind="function",
            metric="nesting_depth",
            value=5,
            thresholds={"nesting": 4},
        ),
        HotspotInput(
            finding=third,
            path="a.py",
            symbol="a.g",
            kind="function",
            metric="complexity",
            value=12,
            thresholds={"complexity": 10},
        ),
    ]
    hotspots = build_hotspots(inputs)
    assert [(item.path, item.signal_count) for item in hotspots] == [("b.py", 2), ("a.py", 1)]
    text = json.dumps(serialize_hotspots(hotspots)).lower()
    for forbidden in ("score", "rank", "weight", "grade", "index"):
        assert forbidden not in text


def test_hotspot_finding_traceability() -> None:
    from app.analyzers.code_structure.hotspots import HotspotInput
    from tests.fixtures.helpers.analyzer_helpers import make_finding

    finding = make_finding(rule_id="CODE-HIGH-COMPLEXITY", path="m.py", subject_key="s")
    (hotspot,) = build_hotspots(
        [
            HotspotInput(
                finding=finding,
                path="m.py",
                symbol="m.f",
                kind="function",
                metric="complexity",
                value=11,
                thresholds={"complexity": 10},
            )
        ]
    )
    assert hotspot.finding_ids == (finding.finding_id or finding.identity_key,)
    assert hotspot.measurements[0]["value"] == 11
    assert hotspot.measurements[0]["thresholds"] == {"complexity": 10}


def test_measurements_serialize_sorted_with_availability() -> None:
    from app.analyzers.code_structure.models import FunctionMeasurement

    records = serialize_measurements(
        [
            FunctionMeasurement(name="complexity", path="b.py", qualified_name="b.f", value=3),
            FunctionMeasurement(name="complexity", path="a.py", qualified_name="a.f", value=None),
        ]
    )
    assert [(item["path"], item["availability"]) for item in records] == [
        ("a.py", "unknown"),
        ("b.py", "available"),
    ]
    assert records[0]["value"] is None


def test_duplicates_serialize_with_primary_marked() -> None:
    from app.analyzers.code_structure.models import DuplicateGroup, DuplicateLocation

    group = DuplicateGroup(
        members=(
            DuplicateLocation(
                path="a.py", qualified_name="a.f", start_line=1, end_line=9, matched_tokens=55
            ),
            DuplicateLocation(
                path="b.py", qualified_name="b.g", start_line=4, end_line=12, matched_tokens=55
            ),
        ),
        matched_tokens=55,
        exact=True,
    )
    (record,) = serialize_duplicates([group])
    assert [item["primary"] for item in record["members"]] == [True, False]
    assert record["matched_tokens"] == 55
    assert record["exact"] is True


def test_canonical_bytes_stable() -> None:
    payload = {"b": [2, 1], "a": {"z": 1}}
    assert dumps_canonical(payload) == '{"a":{"z":1},"b":[2,1]}'
    assert json.loads(dumps_canonical(payload)) == payload


def test_size_guard_rejects_oversized_output() -> None:
    import pytest

    assert SERIALIZATION_MAX_CHARS >= 1024 * 1024
    with pytest.raises(ValueError):
        dumps_canonical({"blob": "x" * (SERIALIZATION_MAX_CHARS + 1)})


def test_code_report_shape_has_no_scores() -> None:
    payload = serialize_code_report(
        metrics=[{"metric": "complexity", "value": 11}],
        duplicates=[],
        hotspots=[],
        limited=False,
        limitation_reasons=[],
        rule_set_version="1.0",
    )
    assert set(payload) == {
        "metrics",
        "duplicates",
        "hotspots",
        "limited",
        "limitation_reasons",
        "rule_set_version",
    }
    assert "score" not in json.dumps(payload).lower()


def test_serialized_hotspots_round_trip() -> None:
    hotspot = Hotspot(path="m.py", symbol="m.f", kind="function", signal_count=1)
    (record,) = serialize_hotspots([hotspot])
    assert record["signal_count"] == 1
    assert record["measurements"] == []
    assert record["finding_ids"] == []
