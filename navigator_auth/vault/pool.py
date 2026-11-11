"""asyncpg view of an application database pool, for vault protected targets.

``PostgresTarget`` (navigator-session) drives its connection with the asyncpg API:
``conn.transaction()`` returns a transaction to ``start()``, and ``execute()`` raises on error
and returns a command tag (``"UPDATE 1"``) that ``write()`` checks for a missing row.

The application's ``authdb`` pool is an asyncdb pool. Its connections are asyncdb ``pg``
drivers: ``transaction()`` is a coroutine that has already started the transaction, and
``execute()`` never raises and returns ``[result, error]``. Driving a target through such a
driver either crashes (``'coroutine' object has no attribute 'start'``) or fails open: a
rejected or row-less UPDATE reports success, and a key rotation counts the row as rotated.

:func:`asyncpg_pool` borrows connections from the application pool and hands the target the
native asyncpg connection under the asyncdb driver. Every target (navigator-auth's own and
navigator-session's ``UserVaultTarget``) then gets asyncpg semantics.
"""

from collections.abc import AsyncGenerator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from navigator_session.vault.targets.postgres import acquire_connection


def native_connection(conn: Any) -> Any:
    """Return the asyncpg connection behind ``conn``.

    An asyncdb driver exposes its asyncpg connection through ``engine()``. Any other connection
    without ``fetch_all`` (asyncpg connections, pool proxies) is already native and is returned
    unchanged.

    Args:
        conn: Connection acquired from an asyncpg or asyncdb pool.

    Returns:
        The native asyncpg connection.

    Raises:
        TypeError: ``conn`` is asyncdb-style but exposes no usable native connection. The
            asyncdb driver is never used as a fallback, because its ``execute()`` swallows errors.
    """
    engine = getattr(conn, "engine", None)
    if callable(engine):
        raw = engine()
        if raw is None or not callable(getattr(raw, "transaction", None)):
            raise TypeError(
                f"{type(conn).__name__}.engine() returned no asyncpg connection; "
                "vault targets need native asyncpg semantics"
            )
        return raw
    if hasattr(conn, "fetch_all"):
        raise TypeError(
            f"{type(conn).__name__} is an asyncdb-style connection without engine(); "
            "vault targets need native asyncpg semantics"
        )
    return conn


class AsyncpgPoolAdapter:
    """Pool whose ``acquire()`` yields native asyncpg connections from the wrapped pool.

    Args:
        pool: asyncpg pool, or asyncdb pool whose ``acquire()`` is an async context
            manager or an awaitable.
    """

    def __init__(self, pool: Any) -> None:
        """Wrap ``pool``."""
        self.pool = pool

    def acquire(self) -> AbstractAsyncContextManager[Any]:
        """Borrow a connection; it goes back to the wrapped pool when the context exits.

        Returns:
            Async context manager yielding the native asyncpg connection.

        Raises:
            TypeError: On entry, when the wrapped pool yields an asyncdb-style connection
                with no native connection (see :func:`native_connection`).
        """
        return self._acquire()

    @asynccontextmanager
    async def _acquire(self) -> AsyncGenerator[Any]:
        async with acquire_connection(self.pool) as conn:
            yield native_connection(conn)


def asyncpg_pool(pool: Any) -> AsyncpgPoolAdapter:
    """Wrap ``pool`` so vault targets get native asyncpg connections.

    Use it for in-process rotation or migration on the application pool, e.g.
    ``UserVaultTarget(asyncpg_pool(app_pool))``. navigator-auth's own targets wrap their pool
    themselves.

    Args:
        pool: asyncpg pool, asyncdb pool or an existing adapter.

    Returns:
        An adapter around ``pool``; an :class:`AsyncpgPoolAdapter` is returned unchanged.
    """
    if isinstance(pool, AsyncpgPoolAdapter):
        return pool
    return AsyncpgPoolAdapter(pool)
