"""In-process concurrency slots for analyses (TASK-055, NFR-045).

Local V1.0 architecture: a bounded semaphore enforces
concurrency.max_analyses at the ingestion boundary. Exhaustion raises
ConcurrencyExhaustedError (contract RATE_LIMITED) — visible decline, never
a silent drop. Capacity releases on success, failure, exception, timeout,
and cleanup via the context manager. No queues, brokers, or workers.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from app.core.logging import get_logger, log_event
from app.repository.errors import ConcurrencyExhaustedError

_logger = get_logger("concurrency")


class ConcurrencyManager:
    """Bounded analysis slots (max_analyses from centralized settings)."""

    def __init__(self, max_analyses: int) -> None:
        if max_analyses < 1:
            raise ValueError("max_analyses must be at least 1")
        self._max_analyses = max_analyses
        self._semaphore = threading.BoundedSemaphore(max_analyses)

    @property
    def max_analyses(self) -> int:
        """Configured slot count."""
        return self._max_analyses

    @contextmanager
    def acquire(self, analysis_id: str) -> Iterator[None]:
        """Hold one slot; raise ConcurrencyExhaustedError when full."""
        acquired = self._semaphore.acquire(blocking=False)
        if not acquired:
            log_event(
                _logger,
                logging.WARNING,
                "analysis.concurrency.rejected",
                "Analysis rejected: concurrency limit reached",
                analysis_id=analysis_id,
                max_analyses=self._max_analyses,
            )
            raise ConcurrencyExhaustedError()
        try:
            yield
        finally:
            self._semaphore.release()
