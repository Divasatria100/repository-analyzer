"""Rule registry tests (TASK-084): registration, ordering, rejection, lookup."""

import pytest

from app.analyzers.rules import RuleRegistry, category_for_rule
from tests.fixtures.helpers.analyzer_helpers import make_rule


def _executor(execution_context):  # type: ignore[no-untyped-def]
    from app.analyzers.rules import RuleOutcome

    return RuleOutcome()


def test_registration_and_lookup() -> None:
    """Registered rules resolve by ID; unknown IDs are never fabricated."""
    registry = RuleRegistry()
    registry.register(make_rule("SEC-TEST-001"), _executor)
    assert registry.get("SEC-TEST-001") is not None
    assert registry.get("SEC-NOPE-999") is None
    assert registry.require("SEC-TEST-001").metadata.rule_id == "SEC-TEST-001"
    with pytest.raises(KeyError):
        registry.require("SEC-NOPE-999")


def test_deterministic_ordering() -> None:
    """Iteration order is rule-ID sorted, independent of registration order."""
    registry = RuleRegistry()
    registry.register(make_rule("SEC-TEST-003"), _executor)
    registry.register(make_rule("ARCH-TEST-001", analyzer_id="architecture"), _executor)
    registry.register(make_rule("SEC-TEST-001"), _executor)
    assert registry.rule_ids() == ["ARCH-TEST-001", "SEC-TEST-001", "SEC-TEST-003"]
    assert [r.metadata.rule_id for r in registry.ordered()] == registry.rule_ids()
    assert [r.metadata.rule_id for r in registry] == registry.rule_ids()
    assert len(registry) == 3


def test_duplicate_rule_rejected() -> None:
    """Duplicate IDs raise instead of silently overwriting."""
    registry = RuleRegistry()
    registry.register(make_rule("SEC-TEST-001"), _executor)
    with pytest.raises(ValueError, match="Duplicate rule ID"):
        registry.register(make_rule("SEC-TEST-001"), _executor)
    assert len(registry) == 1
    assert registry.require("SEC-TEST-001").metadata.name.startswith("Test rule")


def test_metadata_validation() -> None:
    """Malformed rule declarations fail fast (bad ID, empty fields)."""
    with pytest.raises(ValueError):
        make_rule(rule_id="bogus")
    with pytest.raises(ValueError):
        make_rule(rule_id="SEC TEST 001")


def test_category_mapping() -> None:
    """Rule prefixes map to finding categories (docs/13 §8.1)."""
    assert category_for_rule("SEC-X-1") == "security"
    assert category_for_rule("DEP-X-1") == "dependency"
    assert category_for_rule("ARCH-X-1") == "architecture"
    assert category_for_rule("CODE-X-1") == "code_structure"
    with pytest.raises(ValueError):
        category_for_rule("XXX-1")


def test_registry_serialization_deterministic() -> None:
    """Registry serializes in rule-ID order (stable across runs)."""
    first = RuleRegistry()
    second = RuleRegistry()
    first.register(make_rule("SEC-TEST-002"), _executor)
    first.register(make_rule("SEC-TEST-001"), _executor)
    second.register(make_rule("SEC-TEST-001"), _executor)
    second.register(make_rule("SEC-TEST-002"), _executor)
    assert first.to_dict() == second.to_dict()
