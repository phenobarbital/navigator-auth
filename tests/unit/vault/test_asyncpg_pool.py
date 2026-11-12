"""FEAT-115: vault targets get native asyncpg connections from asyncdb pools (issue:82ec902fa145)."""

from contextlib import asynccontextmanager

import pytest

from navigator_auth.identity.targets import IdentityTarget
from navigator_auth.identity.targets import factory as identity_factory
from navigator_auth.mfa.targets import MfaSecretTarget
from navigator_auth.mfa.targets import factory as mfa_factory
from navigator_auth.vault import AsyncpgPoolAdapter, asyncpg_pool
from navigator_auth.vault.pool import native_connection


class _RawConn:
    """asyncpg-style connection: ``transaction()`` returns an object to ``start()``."""

    def transaction(self):
        """Return a transaction placeholder."""
        return object()


class _Driver:
    """asyncdb-style driver wrapping a raw connection."""

    def __init__(self, raw):
        """Wrap ``raw``."""
        self._raw = raw

    def engine(self):
        """Return the wrapped connection, as asyncdb's ``engine()`` does."""
        return self._raw

    async def fetch_all(self, *args):
        """asyncdb-style fetch."""
        return []


class _AwaitablePool:
    """Pool whose ``acquire()`` is an awaitable and that records releases."""

    def __init__(self, conn):
        """Hand out ``conn``."""
        self.conn = conn
        self.released = []

    async def acquire(self):
        """Return the connection."""
        return self.conn

    async def release(self, conn):
        """Record the release."""
        self.released.append(conn)


class _ContextPool:
    """Pool whose ``acquire()`` is an async context manager that records exits."""

    def __init__(self, conn):
        """Hand out ``conn``."""
        self.conn = conn
        self.exited = 0

    @asynccontextmanager
    async def _acquire(self):
        try:
            yield self.conn
        finally:
            self.exited += 1

    def acquire(self):
        """Return the acquire context."""
        return self._acquire()


def test_native_connection_unwraps_asyncdb_driver():
    """An asyncdb driver is replaced by the connection its ``engine()`` returns."""
    raw = _RawConn()
    assert native_connection(_Driver(raw)) is raw


def test_native_connection_passes_asyncpg_through():
    """A connection without ``engine``/``fetch_all`` is already native."""
    raw = _RawConn()
    assert native_connection(raw) is raw


@pytest.mark.parametrize("raw", [None, object()], ids=["none", "no-transaction"])
def test_native_connection_rejects_driver_without_raw(raw):
    """A driver whose ``engine()`` has no usable connection is refused, never used as a fallback."""
    with pytest.raises(TypeError, match="engine"):
        native_connection(_Driver(raw))


def test_native_connection_rejects_asyncdb_style_without_engine():
    """``fetch_all`` without ``engine()`` is asyncdb-style with nothing native to hand over."""

    class _Conn:
        async def fetch_all(self, *args):
            return []

    with pytest.raises(TypeError, match="asyncdb-style"):
        native_connection(_Conn())


def test_asyncpg_pool_is_idempotent():
    """An adapter is returned unchanged, never double-wrapped."""
    pool = object()
    adapter = asyncpg_pool(pool)
    assert isinstance(adapter, AsyncpgPoolAdapter)
    assert adapter.pool is pool
    assert asyncpg_pool(adapter) is adapter


@pytest.mark.asyncio
async def test_adapter_supports_awaitable_acquire_and_releases():
    """Awaitable acquire: the driver is unwrapped, then released back to the pool."""
    raw = _RawConn()
    driver = _Driver(raw)
    pool = _AwaitablePool(driver)
    async with asyncpg_pool(pool).acquire() as conn:
        assert conn is raw
        assert pool.released == []
    assert pool.released == [driver]


@pytest.mark.asyncio
async def test_adapter_supports_context_acquire_and_releases_on_refusal():
    """Context-manager acquire: native connections pass through; a refused driver is still returned."""
    raw = _RawConn()
    pool = _ContextPool(raw)
    async with asyncpg_pool(pool).acquire() as conn:
        assert conn is raw
    assert pool.exited == 1

    bad = _ContextPool(_Driver(None))
    with pytest.raises(TypeError):
        async with asyncpg_pool(bad).acquire():
            pass
    assert bad.exited == 1


@pytest.mark.parametrize(
    "build",
    [
        MfaSecretTarget,
        IdentityTarget,
        lambda pool: mfa_factory({"db_pool": pool}),
        lambda pool: identity_factory({"db_pool": pool}),
    ],
    ids=["mfa", "identity", "mfa-factory", "identity-factory"],
)
def test_targets_wrap_their_pool(build):
    """navigator-auth targets (and their entry-point factories) wrap the pool they are given."""
    pool = object()
    target = build(pool)
    assert isinstance(target._pool, AsyncpgPoolAdapter)
    assert target._pool.pool is pool
