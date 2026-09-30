"""Parse worker entry point: isolated per-file parsing subprocess.

Invoked as ``python -m app.parsers.worker <adapter>`` with raw source bytes
on stdin. Parses, writes one JSON result line to stdout, exits 0. Any
crash, traceback, or malformed output is treated as infrastructure failure
by the parent runner — the worker never decides analysis outcomes.

Reads NOTHING except stdin + argv. No network, no filesystem, no imports
of repository code (repository bytes are parsed as data by adapters).
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    """Parse stdin with the named adapter; emit one JSON line."""
    if len(sys.argv) != 4:
        sys.stdout.write(
            json.dumps({"error": "usage: worker <adapter> <language> <relative-path>"}) + "\n"
        )
        return 2
    adapter_name = sys.argv[1]
    language = sys.argv[2]
    # Repo-relative path from the parent (argv element only — no shell is
    # ever involved, so repository-controlled names cannot inject commands).
    relative_path = sys.argv[3]
    try:
        from app.parsers.base import ParserInput
        from app.parsers.registry import get_adapter_by_name
    except Exception as exc:
        sys.stdout.write(
            json.dumps({"error": f"worker import failed: {type(exc).__name__}"}) + "\n"
        )
        return 2
    adapter = get_adapter_by_name(adapter_name)
    if adapter is None:
        sys.stdout.write(json.dumps({"error": f"unknown adapter: {adapter_name}"}) + "\n")
        return 2
    source = sys.stdin.buffer.read()
    try:
        result = adapter.parse(
            ParserInput(
                relative_path=relative_path,
                language=language,
                source=source,
                timeout_s=0.0,
                max_bytes=len(source),
            )
        )
    except Exception as exc:
        sys.stdout.write(json.dumps({"error": f"adapter raised: {type(exc).__name__}"}) + "\n")
        return 1
    payload = result.to_dict()
    sys.stdout.write(json.dumps(payload) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
