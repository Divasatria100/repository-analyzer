"""Architecture serialization tests (TASK-133).

Stable sorted output, canonical bytes, explicit unknown metrics, limits,
and no secret leakage.
"""

import json

from app.analyzers.architecture.models import MetricValue
from app.analyzers.architecture.serialization import (
    SERIALIZATION_MAX_CHARS,
    dumps_canonical,
    serialize_graph,
    serialize_metrics,
    serialize_report,
)
from tests.fixtures.helpers.architecture_helpers import graph_for


def test_serialization_stable_under_reordered_input() -> None:
    files = {"c.py": "import a\n", "b.py": "import a\nimport c\n", "a.py": "X = 1\n"}
    from app.analyzers.architecture.cycles import find_cycles

    first_report = graph_for(files)
    second_report = graph_for(dict(reversed(list(files.items()))))
    first = serialize_report(
        first_report,
        metrics=[],
        cycles=find_cycles(first_report.graph),
        rule_set_version="1.0",
    )
    second = serialize_report(
        second_report,
        metrics=[],
        cycles=find_cycles(second_report.graph),
        rule_set_version="1.0",
    )
    assert first == second
    assert dumps_canonical(first) == dumps_canonical(second)


def test_canonical_bytes_are_json_stable() -> None:
    payload = {"b": [3, 1], "a": {"z": 1, "y": 2}}
    assert dumps_canonical(payload) == '{"a":{"y":2,"z":1},"b":[3,1]}'
    assert json.loads(dumps_canonical(payload)) == payload


def test_unknown_metrics_serialize_as_unknown_not_zero() -> None:
    records = serialize_metrics(
        [MetricValue(name="fan_out", subject="a.py", value=None, basis="unavailable")]
    )
    assert records[0]["value"] is None
    assert records[0]["availability"] == "unknown"


def test_metrics_sorted_by_name_and_subject() -> None:
    records = serialize_metrics(
        [
            MetricValue(name="fan_in", subject="b.py", value=1),
            MetricValue(name="fan_in", subject="a.py", value=2),
            MetricValue(name="fan_out", subject="a.py", value=0),
        ]
    )
    assert [(item["metric"], item["subject"]) for item in records] == [
        ("fan_in", "a.py"),
        ("fan_in", "b.py"),
        ("fan_out", "a.py"),
    ]


def test_cycle_count_states_its_unit() -> None:
    from app.analyzers.architecture.cycles import find_cycles

    report = graph_for({"a.py": "import b\n", "b.py": "import a\n"})
    payload = serialize_report(report, cycles=find_cycles(report.graph))
    assert payload["cycle_count"] == {"unit": "group", "value": 1}
    assert payload["module_count"] == 2
    assert payload["dependency_count"] == 2


def test_serialization_exposes_no_source_or_secrets() -> None:
    secret = "FAKE-EXAMPLE-TOKEN-NOT-REAL-99999"
    report = graph_for({"a.py": f'TOKEN = "{secret}"\nimport b\n', "b.py": "X = 1\n"})
    text = dumps_canonical(serialize_report(report))
    assert secret not in text
    assert "TOKEN" not in text


def test_serialization_records_incompleteness() -> None:
    report = graph_for({"good.py": "X = 1\n", "broken.py": "def broken(:\n"})
    payload = serialize_report(report)
    assert payload["failed_files"] == ["broken.py"]
    assert payload["limited"] is True
    assert payload["limitation_reasons"]


def test_size_guard_rejects_oversized_output() -> None:
    import pytest

    assert SERIALIZATION_MAX_CHARS >= 1024 * 1024
    with pytest.raises(ValueError):
        dumps_canonical({"blob": "x" * (SERIALIZATION_MAX_CHARS + 1)})


def test_graph_edges_carry_evidence_locations() -> None:
    report = graph_for({"a.py": "import b\n", "b.py": "X = 1\n"})
    (edge,) = serialize_graph(report.graph)["edges"]
    assert edge["source"] == "a.py"
    assert edge["target"] == "b.py"
    assert edge["locations"] == [{"path": "a.py", "line": 1, "column": 0}]


def test_empty_graph_serializes_cleanly() -> None:
    report = graph_for({})
    payload = serialize_report(report)
    assert payload["graph"] == {
        "nodes": [],
        "edges": [],
        "truncated": False,
        "truncation_reason": "",
    }
    assert payload["cycles"] == []
