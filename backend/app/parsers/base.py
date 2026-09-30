"""Parser adapter interface (TASK-064).

Contract between indexed files and normalized parse results. Adapters
receive bounded bytes plus identity metadata and return parser-independent
NCM — never parser-specific objects, never a clean result on failure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.ncm import ParseResult


@dataclass(frozen=True)
class ParserInput:
    """Bounded adapter input: identity, language, raw bytes, limits."""

    relative_path: str
    language: str
    source: bytes
    timeout_s: float
    max_bytes: int


class ParserAdapter(ABC):
    """Adapter contract: bytes in, normalized NCM out."""

    name: str = ""
    parser_version: str = ""
    supported_languages: frozenset[str] = frozenset()

    def supports(self, language: str) -> bool:
        """True when this adapter claims the language."""
        return language in self.supported_languages

    @abstractmethod
    def parse(self, data: ParserInput) -> ParseResult:
        """Parse bounded source bytes into a normalized result.

        Must return failed (never clean) when nothing usable is produced,
        partial with diagnostics when coverage is incomplete, and parsed
        only when the representation is complete. Must not raise on
        malformed input — encode it as failed with diagnostics instead.
        """
        raise NotImplementedError
