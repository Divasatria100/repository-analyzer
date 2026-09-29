"""Concurrency tests: 2 slots enforced, capacity always released (TASK-055)."""

import pytest

from app.repository.concurrency import ConcurrencyManager
from app.repository.errors import ConcurrencyExhaustedError


def test_two_allowed_third_rejected() -> None:
    manager = ConcurrencyManager(max_analyses=2)
    with manager.acquire("a1"), manager.acquire("a2"):
        with pytest.raises(ConcurrencyExhaustedError) as exc_info:
            with manager.acquire("a3"):
                pass
    assert exc_info.value.contract_code == "RATE_LIMITED"


def test_capacity_released_after_success() -> None:
    manager = ConcurrencyManager(max_analyses=1)
    with manager.acquire("a1"):
        pass
    with manager.acquire("a2"):
        pass


def test_capacity_released_after_failure_and_exception() -> None:
    manager = ConcurrencyManager(max_analyses=1)
    with pytest.raises(RuntimeError):
        with manager.acquire("a1"):
            raise RuntimeError("boom")
    with manager.acquire("a2"):
        pass


def test_rejection_while_slots_held() -> None:
    manager = ConcurrencyManager(max_analyses=2)
    with manager.acquire("holder-1"), manager.acquire("holder-2"):
        rejected = 0
        for name in ("late-1", "late-2"):
            with pytest.raises(ConcurrencyExhaustedError):
                with manager.acquire(name):
                    pass
            rejected += 1
    assert rejected == 2
    with manager.acquire("after-release"):
        pass


def test_invalid_max_rejected() -> None:
    with pytest.raises(ValueError):
        ConcurrencyManager(max_analyses=0)
