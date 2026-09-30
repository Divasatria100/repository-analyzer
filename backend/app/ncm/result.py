"""Parse states and results (docs/10 §5.9, docs/12 §4.3).

File ``parse_result`` vocabulary is exactly ``parsed``,
``parsed_with_diagnostics``, ``failed`` (lowercase). ``unsupported`` is a
pipeline-level outcome for files with no adapter — never a ``parse_result``
value and never a failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.ncm.model import Diagnostic, NormalizedModule, ncm_from_dict, ncm_to_dict


class ParseState(StrEnum):
    """Per-file parse outcome (lowercase, matching the frozen vocabulary)."""

    PARSED = "parsed"
    PARSED_WITH_DIAGNOSTICS = "parsed_with_diagnostics"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class ParseResult:
    """Normalized parse product for one file (adapter-independent)."""

    state: ParseState
    ncm: NormalizedModule | None
    diagnostics: list[Diagnostic] = field(default_factory=list)
    parser_name: str = ""
    parser_version: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Serialize for worker transport (NCM included when present)."""
        return {
            "state": self.state.value,
            "ncm": ncm_to_dict(self.ncm) if self.ncm is not None else None,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ParseResult:
        """Rebuild from worker transport (NCM revalidated, never trusted raw)."""
        ncm_data = data.get("ncm")
        diagnostics = data.get("diagnostics", [])
        assert isinstance(diagnostics, list)
        duration = data.get("duration_ms", 0.0)
        assert isinstance(duration, (int, float))
        return cls(
            state=ParseState(str(data["state"])),
            ncm=ncm_from_dict(ncm_data) if isinstance(ncm_data, dict) else None,
            diagnostics=[Diagnostic.from_dict(d) for d in diagnostics if isinstance(d, dict)],
            parser_name=str(data.get("parser_name", "")),
            parser_version=str(data.get("parser_version", "")),
            duration_ms=float(duration),
        )
