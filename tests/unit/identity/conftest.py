"""Shared fixtures for identity/backend unit tests."""
from unittest.mock import AsyncMock, MagicMock

import pytest


class FakeFlowStore:
    """Dict-backed IdentityFlowStore double (single-use semantics)."""

    def __init__(self):
        self.storage = {}
        self.ttls = {}

    async def set(self, key, payload, ttl):
        self.storage[key] = payload
        self.ttls[key] = ttl

    async def get(self, key):
        return self.storage.get(key)

    async def getdel(self, key):
        self.ttls.pop(key, None)
        return self.storage.pop(key, None)

    async def delete(self, key):
        self.storage.pop(key, None)

    async def start_link(self, state, payload, ttl):
        await self.set(f"idlink:{state}", payload, ttl)

    async def consume_link(self, state):
        return await self.getdel(f"idlink:{state}")


@pytest.fixture
def flow_store():
    return FakeFlowStore()


def make_backend(cls, flow_store=None, **attrs):
    """Instantiate a backend class bypassing __init__ (no app wiring)."""
    backend = object.__new__(cls)
    backend.logger = MagicMock()
    backend._flow_store = flow_store if flow_store is not None else FakeFlowStore()
    # instance attributes normally set by BaseAuthBackend.__init__:
    backend.scheme = "Bearer"
    backend.session_key_property = "session_key"
    backend.session_id_property = "session_id"
    backend.user_property = "user"
    for key, value in attrs.items():
        setattr(backend, key, value)
    return backend
