"""Persistence for linked identities (auth.user_identities).

DB is the source of truth; the Session Vault is used as a per-session
cache of the decrypted credential to avoid database round-trips.
"""
from typing import Any, Optional
from datetime import datetime, timezone

from asyncdb.exceptions import NoDataFound
from navconfig.logging import logging

from ..models import UserIdentity
from .crypto import IdentityCipher
from .types import TokenResponse

logger = logging.getLogger("navigator.identity")

# Session Vault key for the cached credential of a provider:
IDENTITY_VAULT_KEY = "identity:{provider}"

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
        async with await self._pool.acquire() as conn:
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
                if kept and getattr(existing, "provider_user_id", None) != puid:
                    values.update(self._reseal_kept(existing, user_id, provider, puid, tuple(kept)))
                for key, value in values.items():
                    setattr(existing, key, value)
                return await existing.update()
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
        async with await self._pool.acquire() as conn:
            rows = await _filter_identities(
                conn, user_id=_user_id_param(user_id)
            )
        return [self.masked(row) for row in rows]

    async def get_one(
        self, user_id: Any, identity_id: Any
    ) -> Optional[UserIdentity]:
        """One identity by PK, restricted to its owner."""
        async with await self._pool.acquire() as conn:
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
        async with await self._pool.acquire() as conn:
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
        async with await self._pool.acquire() as conn:
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
        async with await self._pool.acquire() as conn:
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

        Args:
            identity: The row to update, as read from this store.
            token: The rotated credential.

        Returns:
            The updated row.
        """
        user_id, provider = identity.user_id, identity.auth_provider
        puid = identity.provider_user_id
        identity.access_token = self._seal(token.access_token, user_id, provider, puid, "access_token")
        if token.refresh_token:
            identity.refresh_token = self._seal(token.refresh_token, user_id, provider, puid, "refresh_token")
        if token.id_token:
            # Only when the refresh returned one: an OIDC provider may omit
            # id_token on the refresh grant, and the stored one is still the
            # truth about the account (issue:d73106586c38).
            identity.id_token = self._seal(token.id_token, user_id, provider, puid, "id_token")
        identity.token_type = token.token_type
        identity.expires_at = token.expires_at
        identity.refreshed_at = datetime.now(timezone.utc)
        identity.key_version = self._cipher.key_id
        if token.scopes:
            identity.scopes = list(token.scopes)
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            return await identity.update()

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
        async with await self._pool.acquire() as conn:
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
