"""NON-EXECUTION CANARY fixture data. Never executed.

If this source text were ever executed as a program, it would create the
marker file ``<tempdir>/repolens-canary-py01.marker`` and set the
``REPOLENS_CANARY_PY01`` environment variable. Both side effects are
harmless and deterministic, and their absence proves the test path that
handled this file did not execute it.

Storing, reading, parsing (``ast.parse``), or scanning this file MUST NOT
trigger either side effect.
"""

import os
from pathlib import Path
from tempfile import gettempdir

# REPOLENS_CANARY_PY01_PAYLOAD — presence of this text proves the fixture
# content was available to the test without being executed.
Path(gettempdir(), "repolens-canary-py01.marker").write_text("executed", encoding="utf-8")
os.environ["REPOLENS_CANARY_PY01"] = "executed"
