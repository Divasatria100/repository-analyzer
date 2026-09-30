"""Versioning tests (TASK-085): explicit, deterministic, single-sourced."""

import pytest

from app.analyzers.versioning import RULE_SET_VERSION, Versions, resolve_versions


def test_versions_present_and_serializable() -> None:
    """Every result carries traceable analyzer + rule-set versions."""
    versions = Versions(analyzer_version="0.1.0", rule_set_version="1.0")
    assert versions.to_dict() == {"analyzer_version": "0.1.0", "rule_set_version": "1.0"}


def test_empty_versions_rejected() -> None:
    """Untraceable results are rejected at construction (fail fast)."""
    with pytest.raises(ValueError):
        Versions(analyzer_version="", rule_set_version="1.0")
    with pytest.raises(ValueError):
        Versions(analyzer_version="0.1.0", rule_set_version="  ")


def test_single_source_of_truth() -> None:
    """Rule-set version reuses the frozen ingestion constant (no duplicate)."""
    from app.repository.ingestion import RULE_SET_VERSION as INGESTION_RULE_SET_VERSION

    assert RULE_SET_VERSION == INGESTION_RULE_SET_VERSION == "1.0"
    resolved = resolve_versions("0.1.0")
    assert resolved.rule_set_version == "1.0"
    assert resolved.analyzer_version == "0.1.0"
