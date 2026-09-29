"""Shared test fixtures: isolated configuration, no external network."""

import os
import socket
from collections.abc import Iterator

import pytest

from app.api.deps import reset_session_factory
from app.core.config import get_settings

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK_HOSTS or host.startswith("127.")


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Clear REPOLENS_ env vars and reset cached settings/factories per test."""
    for key in [key for key in os.environ if key.startswith("REPOLENS_")]:
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    reset_session_factory()
    yield
    get_settings.cache_clear()
    reset_session_factory()


@pytest.fixture(autouse=True)
def block_non_loopback_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Tripwire: any non-localhost socket connection fails loudly.

    Mock transports and ASGI test clients never open sockets, so legitimate
    tests are unaffected; an accidental github.com/osv.dev call raises
    instead of silently leaving the machine.
    """
    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: object) -> None:
        host = address[0] if isinstance(address, tuple) else str(address)
        if _is_loopback(str(host)):
            real_connect(self, address)  # type: ignore[arg-type]
            return
        raise RuntimeError(f"External network blocked in tests: {host}")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield
