"""Persistence for linked identities (auth.user_identities).

DB is the source of truth; the Session Vault is used as a per-session
cache of the decrypted credential to avoid database round-trips.
"""
import asyncio
import json
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncGenerator, Optional
from datetime import datetime, timezone

from asyncdb.exceptions import NoDataFound
from navconfig.logging import logging

from ..exceptions import AuthException
from ..models import UserIdentity
from .crypto import IdentityCipher
from .types import TokenResponse

logger = logging.getLogger("navigator.identity")

# Session Vault key for the cached credential of a provider:
IDENTITY_VAULT_KEY = "identity:{provider}"

# Cross-process refresh lock (IdentityStore.refresh_lock). The key text is
# hashed by Postgres (hashtextextended, PostgreSQL 11+) into the advisory lock
# id; a collision only makes two unrelated refreshes take turns.
_REFRESH_LOCK_KEY = "navigator_auth.identity_refresh:{provider}:{user_id}:{provider_user_id}"
_REFRESH_TRY_LOCK = "SELECT pg_try_advisory_lock(hashtextextended($1, 0))"
_REFRESH_UNLOCK = "SELECT pg_advisory_unlock(hashtextextended($1, 0))"
_REFRESH_LOCK_POLL = 0.1  # seconds between attempts while another worker refreshes

# (pool, connection) holding this task's refresh lock. IdentityStore calls made
# inside the lock reuse that connection instead of taking a second one.
_REFRESH_CONNECTION: ContextVar[Optional[tuple[Any, Any]]] = ContextVar(
    "navigator_auth_identity_refresh_connection", default=None
)


def _is_live(conn: Any) -> bool:
    """Whether a pooled asyncdb connection is still open (False when unsure)."""
    try:
        return bool(conn.is_connected())
    except Exception:  # pylint: disable=W0703
        return False


class IdentityRefreshBusy(AuthException):
    """Another worker kept refreshing this credential past the lock timeout."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status=503)

# Read projection for auth.user_identities.
#
# asyncdb's ``Model.filter()`` issues ``SELECT *`` and hands every column it
# gets back to the dataclass ``__init__``, so a single column the model does
# not declare makes hydration raise
# ``TypeError: UserIdentity.__init__() got an unexpected keyword argument``.
# A legacy table has exactly such a column: ``uid``, half of its legacy
# primary key, which ``005_identity_legacy_uid_default.sql`` deliberately
# leaves in place. ``Model.get()`` never had the problem because it projects
# the model's own columns — every read here does the same, which also keeps
# any future legacy column from breaking hydration again.
_IDENTITY_FIELDS: tuple[str, ...] = tuple(UserIdentity.get_fields(UserIdentity))
_IDENTITY_TABLE = f"{UserIdentity.Meta.schema}.{UserIdentity.Meta.name}"
_IDENTITY_SELECT = f"SELECT {', '.join(_IDENTITY_FIELDS)} FROM {_IDENTITY_TABLE}"

try:
    from navigator_session.vault import VaultCryptoError
except ImportError:  # pragma: no cover - IdentityCipher raises ConfigError first

    class VaultCryptoError(Exception):  # type: ignore[no-redef]
        """Placeholder when navigator-session vault crypto is unavailable."""


class IdentityCredentialError(Exception):
    """A stored identity token cannot be opened.

    The ciphertext was tampered with, copied from another user/account/column,
    sealed with a key version no longer configured, or is in a legacy format.
    The identity must be re-linked.

    Attributes:
        provider: ``auth_provider`` of the identity.
        field: Token column that failed.
        reason: Error class name (never secret material).
    """

    def __init__(self, provider: str, field: str, reason: str) -> None:
        super().__init__(f"{provider}: stored {field} cannot be decrypted ({reason})")
        self.provider = provider
        self.field = field
        self.reason = reason


def _newest_first(rows: list[Any]) -> None:
    """Order credential rows newest-first, in place and deterministically.

    Rows rank on ``refreshed_at``, falling back to ``created_at``. Ties — two
    rows written in the same transaction, or both timestamps missing — break on
    ``identity_id``, so the same row always wins instead of whatever order the
    database happened to return.

    Args:
        rows: Identity rows to sort in place.
    """
    rows.sort(
        key=lambda r: (
            getattr(r, "refreshed_at", None)
            or getattr(r, "created_at", None)
            or datetime.min.replace(tzinfo=timezone.utc),
            str(getattr(r, "identity_id", "") or ""),
        ),
        reverse=True,
    )


def _user_id_param(value: Any) -> Any:
    """Normalize a ``user_id`` for a parameterized query.

    ``auth.users.user_id`` is an integer, but a session can carry it as the
    string ``"35"``. asyncdb's ``filter()`` inlined the value into the SQL
    text and let Postgres cast it; a bound parameter is typed, so the string
    form would be rejected outright.

    Args:
        value: ``user_id`` as it arrives from the session or a caller.

    Returns:
        The integer form of a digits-only string, otherwise ``value``.
    """
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


_JSONB_COLUMNS = frozenset({"scopes", "auth_data", "attributes"})


async def _update_identity_row(
    conn: Any,
    identity_id: Any,
    provider_user_id: Any,
    changes: dict[str, Any],
) -> bool:
    """Write ``changes`` onto one identity row with a plain, keyed ``UPDATE``.

    Used instead of asyncdb's ``Model.update()``, which rewrites every column,
    builds its ``WHERE`` from old values kept in a dict shared by all
    ``UserIdentity`` instances, and caps the statement at a hard-coded
    2-second client timeout. That timeout reported committed writes as
    failures ("Error on Insert over table user_identities").

    Args:
        conn: An acquired database connection.
        identity_id: Primary key of the row.
        provider_user_id: The external account the row is bound to, as the
            caller read it. Tokens are sealed for that account, so a row
            re-bound to another account meanwhile is not written.
        changes: ``column=value`` to set. jsonb columns take the Python value.

    Returns:
        True when the row was written; False when no row matched.

    Raises:
        ValueError: ``identity_id`` is missing (an unkeyed ``UPDATE`` would
            rewrite every row), or a column is not declared on the model.
    """
    if identity_id is None:
        raise ValueError("identity row has no identity_id to key the write on")
    params: list[Any] = []
    assignments: list[str] = []
    for column, value in changes.items():
        if column not in _IDENTITY_FIELDS:
            raise ValueError(f"{_IDENTITY_TABLE} has no column {column!r}")
        if column in _JSONB_COLUMNS:
            # Bound as text and cast in SQL, so the value does not depend on
            # whether the connection has a jsonb codec registered.
            params.append(json.dumps(value, default=str))
            assignments.append(f"{column} = ${len(params)}::text::jsonb")
        else:
            params.append(value)
            assignments.append(f"{column} = ${len(params)}")
    params += [identity_id, None if provider_user_id is None else str(provider_user_id)]
    sql = (
        f"UPDATE {_IDENTITY_TABLE} SET {', '.join(assignments)} "
        f"WHERE identity_id = ${len(params) - 1} "
        f"AND provider_user_id IS NOT DISTINCT FROM ${len(params)}::varchar "
        "RETURNING identity_id"
    )
    return await conn.fetch_one(sql, *params) is not None


async def _filter_identities(conn: Any, **criteria: Any) -> list[UserIdentity]:
    """Identity rows matching an equality filter, hydrated as models.

    Replaces ``UserIdentity.filter()``: same equality semantics, but it
    projects ``_IDENTITY_SELECT`` instead of ``SELECT *`` so a legacy column
    on the table cannot break hydration (see the ``_IDENTITY_SELECT`` note).

    Args:
        conn: An acquired database connection.
        **criteria: ``column=value`` filters AND-ed together. Every column
            must be declared on ``UserIdentity``.

    Returns:
        The matching rows in database order; empty when nothing matches.

    Raises:
        ValueError: A filter names a column the model does not declare.
    """
    conditions: list[str] = []
    params: list[Any] = []
    for column, value in criteria.items():
        if column not in _IDENTITY_FIELDS:
            raise ValueError(f"{_IDENTITY_TABLE} has no column {column!r}")
        params.append(value)
        conditions.append(f"{column} = ${len(params)}")
    sql = _IDENTITY_SELECT
    if conditions:
        sql = f"{sql} WHERE {' AND '.join(conditions)}"
    rows = await conn.fetch_all(sql, *params)
    # Mirrors Model.filter(): the old-value map is class-level, so it is
    # reset before a batch of rows is hydrated. Unknown keys are dropped the
    # way Model.get() drops them — the projection should never return one,
    # and hydration must not depend on that.
    UserIdentity.reset_values(UserIdentity)
    return [
        UserIdentity(
            **{
                column: value
                for column, value in dict(row).items()
                if column in _IDENTITY_FIELDS
            }
        )
        for row in rows or []
    ]


class IdentityStore:
    """CRUD for ciphered identity credentials on auth.user_identities."""

    def __init__(self, db_pool: Any, cipher: Optional[IdentityCipher] = None):
        self._pool = db_pool
        self._cipher = cipher if cipher is not None else IdentityCipher()

    @asynccontextmanager
    async def _connection(self) -> AsyncGenerator[Any, None]:
        """A pooled connection, or the one holding this task's refresh lock.

        Inside ``refresh_lock`` every call on a store over the same pool reuses
        the lock's connection, so a refresh needs one connection, not two, and
        a burst of refreshes cannot exhaust the pool waiting on each other.
        Calls inside the lock must therefore run one at a time (no
        ``asyncio.gather`` of store calls there).
        """
        held = _REFRESH_CONNECTION.get()
        if held is not None and held[0] is self._pool and _is_live(held[1]):
            yield held[1]
            return
        # No lock held, or its connection died during the refresh (the lock
        # went with it): write through a fresh connection rather than lose a
        # credential the provider has already rotated.
        async with await self._pool.acquire() as conn:
            yield conn

    @asynccontextmanager
    async def refresh_lock(
        self,
        provider: str,
        user_id: Any,
        provider_user_id: Any,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncGenerator[None, None]:
        """Hold the cross-process lock for refreshing one stored credential.

        A Postgres advisory lock keyed by ``(provider, user, external account)``:
        every worker shares this database, so workers refreshing the same
        credential take turns. It is a session lock held on one connection, not
        a transaction, so the refreshed tokens are committed as soon as they
        are written; and it goes away with the connection if the worker dies.

        The lock is polled (``pg_try_advisory_lock``) rather than waited on, so
        the wait is bounded by ``timeout`` and not by the pool's
        ``statement_timeout``.

        Args:
            provider: Backend service name (``auth_provider`` of the row).
            user_id: Local Navigator user id.
            provider_user_id: External account id the row is bound to.
            timeout: Seconds to wait for another worker's refresh to finish.
                Defaults to ``IDENTITY_REFRESH_LOCK_TIMEOUT``.

        Raises:
            IdentityRefreshBusy: The lock stayed taken for ``timeout`` seconds.
        """
        if timeout is None:
            from ..conf import IDENTITY_REFRESH_LOCK_TIMEOUT

            timeout = IDENTITY_REFRESH_LOCK_TIMEOUT
        key = _REFRESH_LOCK_KEY.format(
            provider=provider, user_id=user_id, provider_user_id=provider_user_id
        )
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        # Acquired and released by hand: releasing a connection that died
        # while checked out raises in asyncdb, and that must not turn a
        # refresh that already stored its tokens into a failure.
        acquired = await self._pool.acquire()
        conn = await acquired.__aenter__()
        try:
            while not await conn.fetchval(_REFRESH_TRY_LOCK, key):
                if loop.time() >= deadline:
                    raise IdentityRefreshBusy(
                        f"{provider}: another worker is still refreshing this "
                        f"credential after {timeout:g}s; try again."
                    )
                await asyncio.sleep(_REFRESH_LOCK_POLL)
            held = _REFRESH_CONNECTION.set((self._pool, conn))
            try:
                yield
            finally:
                _REFRESH_CONNECTION.reset(held)
                # A dead connection already lost its locks; querying it
                # anyway can wedge it in the pool, so leave it alone.
                if _is_live(conn):
                    try:
                        await conn.fetchval(_REFRESH_UNLOCK, key)
                    except Exception as err:  # pylint: disable=W0703
                        # Returning the connection to the pool runs
                        # pg_advisory_unlock_all(): never let a failed unlock
                        # mask the refresh result.
                        logger.warning("identity refresh lock: unlock failed (%s)", err)
        finally:
            try:
                await acquired.__aexit__(None, None, None)
            except Exception as err:  # pylint: disable=W0703
                logger.warning("identity refresh lock: releasing its connection failed (%s)", err)

    # ------------------------------------------------------------------
    # Context-bound sealing helpers
    # ------------------------------------------------------------------

    def _seal(
        self,
        value: Any,
        user_id: Any,
        provider: str,
        provider_user_id: Optional[str],
        field: str,
    ) -> bytes:
        return self._cipher.encrypt(
            value,
            user_id=user_id,
            auth_provider=provider,
            provider_user_id=provider_user_id,
            field=field,
        )

    def _open(self, identity: Any, field: str) -> Any:
        try:
            return self._cipher.decrypt(
                getattr(identity, field),
                user_id=identity.user_id,
                auth_provider=identity.auth_provider,
                provider_user_id=identity.provider_user_id,
                field=field,
            )
        except VaultCryptoError as err:
            logger.error(
                "Identity credential integrity failure: user=%s provider=%s field=%s error=%s",
                getattr(identity, "user_id", None),
                identity.auth_provider,
                field,
                type(err).__name__,
            )
            raise IdentityCredentialError(identity.auth_provider, field, type(err).__name__) from None

    def _reseal_kept(
        self,
        existing: Any,
        user_id: Any,
        provider: str,
        new_provider_user_id: Optional[str],
        fields: tuple[str, ...],
    ) -> dict[str, bytes]:
        """Re-seal kept token columns of ``existing`` for a new provider_user_id."""
        resealed: dict[str, bytes] = {}
        for field in fields:
            if getattr(existing, field, None) is None:
                continue
            value = self._open(existing, field)
            resealed[field] = self._seal(value, user_id, provider, new_provider_user_id, field)
        return resealed

    async def save_linked_identity(
        self,
        user_id: Any,
        provider: str,
        token: TokenResponse,
        userinfo: Optional[dict] = None,
    ) -> UserIdentity:
        """Upsert the linked identity for (user, provider, external account).

        Tokens are sealed bound to ``(user_id, provider, provider_user_id,
        column)``. When an existing row is updated with a different
        ``provider_user_id`` (e.g. a legacy row without one), token columns
        that are kept from the old row are re-sealed for the new context.
        """
        userinfo = userinfo or {}
        now = datetime.now(timezone.utc)
        puid = token.provider_user_id
        values = {
            "provider_user_id": puid,
            "scopes": list(token.scopes or []),
            "access_token": self._seal(token.access_token, user_id, provider, puid, "access_token"),
            "refresh_token": (
                self._seal(token.refresh_token, user_id, provider, puid, "refresh_token")
                if token.refresh_token
                else None
            ),
            "id_token": (self._seal(token.id_token, user_id, provider, puid, "id_token") if token.id_token else None),
            "token_type": token.token_type,
            "expires_at": token.expires_at,
            "refreshed_at": now,
            "enabled": True,
            "key_version": self._cipher.key_id,
            "auth_data": self._identity_profile(userinfo),
        }
        async with self._connection() as conn:
            UserIdentity.Meta.connection = conn
            existing = None
            try:
                existing = await UserIdentity.get(
                    user_id=user_id,
                    auth_provider=provider,
                    provider_user_id=token.provider_user_id,
                )
            except NoDataFound:
                existing = None
            if existing:
                # D10: a re-save without a new refresh/id token keeps the
                # previously vaulted one instead of clobbering it with None.
                kept: list[str] = []
                if token.refresh_token is None:
                    values.pop("refresh_token", None)
                    kept.append("refresh_token")
                if token.id_token is None:
                    values.pop("id_token", None)
                    kept.append("id_token")
                bound_puid = getattr(existing, "provider_user_id", None)
                if kept and bound_puid != puid:
                    values.update(self._reseal_kept(existing, user_id, provider, puid, tuple(kept)))
                # A None value keeps the stored column, as the asyncdb model
                # write did (it skipped None columns).
                changes = {key: value for key, value in values.items() if value is not None}
                if not await _update_identity_row(conn, getattr(existing, "identity_id", None), bound_puid, changes):
                    raise NoDataFound(
                        f"{provider}: identity {existing.identity_id} changed while it was "
                        "being re-linked; the credential was not stored."
                    )
                for key, value in changes.items():
                    setattr(existing, key, value)
                return existing
            identity = UserIdentity(
                user_id=user_id,
                auth_provider=provider,
                **values,
            )
            return await identity.insert()

    def _identity_profile(self, userinfo: dict) -> dict:
        """Displayable (non-secret) provider profile attributes."""
        profile = {}
        for key in (
            "name",
            "email",
            "login",
            "sub",
            "id",
            "picture",
            "avatar_url",
            "preferred_username",
            "userPrincipalName",
            "displayName",
        ):
            value = userinfo.get(key)
            if value is not None:
                profile[key] = value
        return profile

    async def list_for_user(self, user_id: Any) -> list[dict]:
        """All linked identities for a user, with secrets masked out."""
        async with self._connection() as conn:
            rows = await _filter_identities(
                conn, user_id=_user_id_param(user_id)
            )
        return [self.masked(row) for row in rows]

    async def get_one(
        self, user_id: Any, identity_id: Any
    ) -> Optional[UserIdentity]:
        """One identity by PK, restricted to its owner."""
        async with self._connection() as conn:
            UserIdentity.Meta.connection = conn
            try:
                return await UserIdentity.get(
                    identity_id=identity_id, user_id=user_id
                )
            except NoDataFound:
                return None

    async def get_by_provider(
        self, user_id: Any, provider: str
    ) -> Optional[UserIdentity]:
        """The newest enabled credential-bearing identity for a provider."""
        async with self._connection() as conn:
            rows = await _filter_identities(
                conn,
                user_id=_user_id_param(user_id),
                auth_provider=provider,
            )
        rows = [
            row
            for row in rows
            if getattr(row, "access_token", None) and getattr(row, "enabled", True)
        ]
        if not rows:
            return None
        _newest_first(rows)
        return rows[0]

    async def get_for_provider_account(
        self,
        user_id: Any,
        provider: str,
        provider_user_id: Optional[str],
    ) -> Optional[UserIdentity]:
        """The enabled credential-bearing identity for one EXACT account.

        Unlike :meth:`get_by_provider`, this never falls back to "the newest
        linked account": a session bound to external account A must never be
        refreshed with account B's credential, however recently B was linked
        (FEAT-103 Module 4).

        Args:
            user_id: Local Navigator user id.
            provider: Backend service name (``self._service_name``).
            provider_user_id: Verified external account id. ``None`` or an
                empty string returns ``None`` — a legacy row without a
                binding requires a re-login, it is not a match.

        Returns:
            The matching ``UserIdentity``, or ``None``.
        """
        if not provider_user_id:
            return None
        async with self._connection() as conn:
            rows = await _filter_identities(
                conn,
                user_id=_user_id_param(user_id),
                auth_provider=provider,
                provider_user_id=str(provider_user_id),
            )
        rows = [
            row
            for row in rows
            if getattr(row, "access_token", None) and getattr(row, "enabled", True)
        ]
        if len(rows) > 1:
            # The partial unique index on (user_id, auth_provider,
            # provider_user_id) normally prevents this, but a legacy table may
            # predate it — and on a table that already holds duplicates the
            # index cannot be created at all. Surface the integrity problem,
            # then pick the newest row deterministically rather than whichever
            # one the database listed first (issue:c9c05c53ec05).
            logger.warning(
                "get_for_provider_account: %d enabled credential rows for "
                "user_id=%s provider=%s; using the newest.",
                len(rows), user_id, provider,
            )
        if not rows:
            return None
        _newest_first(rows)
        return rows[0]

    async def delete(self, user_id: Any, identity_id: Any) -> bool:
        async with self._connection() as conn:
            UserIdentity.Meta.connection = conn
            try:
                row = await UserIdentity.get(
                    identity_id=identity_id, user_id=user_id
                )
            except NoDataFound:
                return False
            await row.delete()
            return True

    async def update_tokens(
        self, identity: UserIdentity, token: TokenResponse
    ) -> UserIdentity:
        """Persist refreshed tokens on an existing identity row (same context).

        ``access_token`` is always replaced; ``refresh_token`` and ``id_token``
        only when the refresh actually returned one, so a provider that omits
        either on the refresh grant does not erase what is stored.

        Only the refreshed columns are written, keyed by the row's own
        ``identity_id`` (see ``_update_identity_row`` for why this is not
        ``Model.update()``).

        Args:
            identity: The row to update, as read from this store.
            token: The rotated credential.

        Returns:
            The updated row.

        Raises:
            ValueError: The row has no ``identity_id`` to key the write on.
            NoDataFound: The row no longer exists, or was re-bound to another
                external account, so the sealed tokens would not match it.
        """
        if getattr(identity, "identity_id", None) is None:
            # checked before sealing, so a refused write leaves the row object untouched
            raise ValueError("update_tokens: identity has no identity_id")
        user_id, provider = identity.user_id, identity.auth_provider
        puid = identity.provider_user_id
        identity.access_token = self._seal(token.access_token, user_id, provider, puid, "access_token")
        changes: dict[str, Any] = {"access_token": identity.access_token}
        if token.refresh_token:
            identity.refresh_token = self._seal(token.refresh_token, user_id, provider, puid, "refresh_token")
            changes["refresh_token"] = identity.refresh_token
        if token.id_token:
            # Only when the refresh returned one: an OIDC provider may omit
            # id_token on the refresh grant, and the stored one is still the
            # truth about the account (issue:d73106586c38).
            identity.id_token = self._seal(token.id_token, user_id, provider, puid, "id_token")
            changes["id_token"] = identity.id_token
        # A refresh that omits token_type / expires_at keeps the stored value,
        # as the asyncdb model write did (it skipped None columns).
        if token.token_type is not None:
            identity.token_type = token.token_type
            changes["token_type"] = identity.token_type
        if token.expires_at is not None:
            identity.expires_at = token.expires_at
            changes["expires_at"] = identity.expires_at
        identity.refreshed_at = datetime.now(timezone.utc)
        identity.key_version = self._cipher.key_id
        changes.update(refreshed_at=identity.refreshed_at, key_version=identity.key_version)
        if token.scopes:
            identity.scopes = list(token.scopes)
            changes["scopes"] = identity.scopes
        async with self._connection() as conn:
            written = await _update_identity_row(conn, identity.identity_id, puid, changes)
        if not written:
            raise NoDataFound(
                f"{provider}: identity {identity.identity_id} no longer exists "
                "for this account; the refreshed credential was not stored."
            )
        return identity

    def decrypt_credential(self, identity: UserIdentity) -> TokenResponse:
        """Decrypt a stored identity row into a TokenResponse.

        Raises:
            IdentityCredentialError: If any stored token fails to open
                (tampered, moved between rows/columns, unknown key version,
                legacy format); the identity must be re-linked.
        """
        access_token = self._open(identity, "access_token")
        refresh_token = self._open(identity, "refresh_token") if identity.refresh_token else None
        id_token = self._open(identity, "id_token") if getattr(identity, "id_token", None) else None
        return TokenResponse(
            access_token=access_token,
            token_type=identity.token_type or "Bearer",
            refresh_token=refresh_token,
            id_token=id_token,
            expires_at=identity.expires_at,
            scopes=list(identity.scopes or []),
            provider_user_id=identity.provider_user_id,
        )

    def masked(self, identity: UserIdentity) -> dict:
        """API-safe representation: never includes token material."""
        expires_at = identity.expires_at
        expired = False
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            expired = expires_at <= datetime.now(timezone.utc)
        return {
            "expired": expired,
            "identity_id": str(identity.identity_id),
            "auth_provider": identity.auth_provider,
            "provider_user_id": identity.provider_user_id,
            "scopes": list(identity.scopes or []),
            "token_type": identity.token_type,
            "expires_at": (
                identity.expires_at.isoformat() if identity.expires_at else None
            ),
            "refreshed_at": (
                identity.refreshed_at.isoformat()
                if identity.refreshed_at
                else None
            ),
            "created_at": (
                identity.created_at.isoformat() if identity.created_at else None
            ),
            "enabled": identity.enabled,
            "has_refresh_token": identity.refresh_token is not None,
            "has_id_token": getattr(identity, "id_token", None) is not None,
            "profile": identity.auth_data or {},
        }

    async def find_user_by_provider_account(
        self, provider: str, provider_user_id: str
    ) -> Optional[Any]:
        """``user_id`` of the enabled identity for (provider, provider_user_id).

        Uses the existing unique partial index
        ``(user_id, auth_provider, provider_user_id)``: a plain filter on
        ``auth_provider``/``provider_user_id`` is enough, then ``enabled``
        rows are filtered in Python. Returns ``None`` on miss or when only
        disabled rows match.
        """
        async with self._connection() as conn:
            rows = await _filter_identities(
                conn,
                auth_provider=provider,
                provider_user_id=str(provider_user_id),
            )
        rows = [row for row in rows if getattr(row, "enabled", True)]
        if not rows:
            return None
        return rows[0].user_id


# --- Session Vault caching helpers (best-effort; DB is source of truth) ---

async def cache_credential(session: Any, provider: str, credential: dict) -> None:
    """Cache a decrypted credential in the user's Session Vault."""
    try:
        from ..vault.integration import VAULT_SESSION_KEY

        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            await vault.set(
                IDENTITY_VAULT_KEY.format(provider=provider), credential
            )
    except Exception as err:  # pylint: disable=W0703
        logger.warning(f"Identity: cannot cache credential in vault: {err}")


async def cached_credential(session: Any, provider: str) -> Optional[dict]:
    """Fetch a cached credential from the Session Vault, if present."""
    try:
        from ..vault.integration import VAULT_SESSION_KEY

        vault = session.get(VAULT_SESSION_KEY)
        if vault is None:
            return None
        key = IDENTITY_VAULT_KEY.format(provider=provider)
        if not await vault.exists(key):
            return None
        return await vault.get(key)
    except Exception as err:  # pylint: disable=W0703
        logger.warning(f"Identity: cannot read credential from vault: {err}")
        return None


async def invalidate_cached(session: Any, provider: str) -> None:
    """Remove a cached credential from the Session Vault."""
    try:
        from ..vault.integration import VAULT_SESSION_KEY

        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            key = IDENTITY_VAULT_KEY.format(provider=provider)
            if await vault.exists(key):
                await vault.delete(key)
    except Exception as err:  # pylint: disable=W0703
        logger.warning(f"Identity: cannot invalidate vault credential: {err}")
