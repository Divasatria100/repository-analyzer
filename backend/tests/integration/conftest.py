"""Integration-test capture policy.

Environment limitation (documented per phase spec §18): this runner's
fd-level capture makes repeated Windows subprocess spawning flaky
(OSError WinError 6 duplicating pipe handles after several git
invocations). Sys-level capture is unaffected. These tests suspend fd
capture only; output is still captured at the sys level.
"""

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _suspend_fd_capture_for_subprocess(
    capfd: pytest.CaptureFixture[str],
) -> Iterator[None]:
    with capfd.disabled():
        yield
