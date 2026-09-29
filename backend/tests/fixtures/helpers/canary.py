"""Non-execution canary helpers: reusable guardrail for analysis tests.

A canary fixture contains executable-looking content whose execution would
produce an unmistakable, harmless side effect (marker file / env var).
Tests handle the fixture with non-executing operations only (read, parse,
scan) and then assert the side effect did NOT occur. The helpers below
must never execute fixture content themselves.
"""

import os
from pathlib import Path
from tempfile import gettempdir

CANARY_ENV_VAR = "REPOLENS_CANARY_PY01"
CANARY_MARKER_NAME = "repolens-canary-py01.marker"
CANARY_PAYLOAD_SENTINEL = "REPOLENS_CANARY_PY01_PAYLOAD"


def canary_marker_path() -> Path:
    """Deterministic marker location the canary payload would create."""
    return Path(gettempdir()) / CANARY_MARKER_NAME


def assert_canary_absent() -> None:
    """Assert neither canary side effect occurred (file nor env var)."""
    assert not canary_marker_path().exists(), (
        f"Canary marker exists: fixture content was executed! ({canary_marker_path()})"
    )
    assert os.environ.get(CANARY_ENV_VAR) is None, (
        "Canary env var is set: fixture content was executed!"
    )


def fixture_contains_canary_payload(source_text: str) -> bool:
    """Confirm the canary payload was present (test would detect execution)."""
    return CANARY_PAYLOAD_SENTINEL in source_text
