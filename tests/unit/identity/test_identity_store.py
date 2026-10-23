"""Unit tests for IdentityStore and the vault-cache helpers."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navigator_auth.identity.crypto import IdentityCipher
from navigator_auth.identity.store import (
    _IDENTITY_SELECT,
    IDENTITY_VAULT_KEY,
    IdentityStore,
    _filter_identities,
    cache_credential,
    cached_credential,
    invalidate_cached,
)
from navigator_auth.models import UserIdentity

MASTER_KEYS = {1: b"\x00" * 32}


def _make_pool():
    conn = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=False)

    async def _acquire():
        return ctx

    pool = MagicMock()
    pool.acquire = MagicMock(side_effect=lambda: _acquire())
    return pool, conn


def _store():
    pool, _ = _make_pool()
    return IdentityStore(pool, cipher=IdentityCipher(master_keys=MASTER_KEYS))


def _enc(store, value, field, user_id=1, provider="github", puid="99"):
    return store._cipher.encrypt(value, user_id=user_id, auth_provider=provider, provider_user_id=puid, field=field)


class TestCipherRoundtripThroughStore:
    def test_decrypt_credential(self):
        store = _store()
        identity = MagicMock()
        identity.user_id = 1
        identity.auth_provider = "github"
        identity.access_token = _enc(store, "the-at", "access_token")
        identity.refresh_token = _enc(store, "the-rt", "refresh_token")
        identity.id_token = _enc(store, "the-id", "id_token")
        identity.token_type = "Bearer"
        identity.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        identity.scopes = ["read:user"]
        identity.provider_user_id = "99"
        token = store.decrypt_credential(identity)
        assert token.access_token == "the-at"
        assert token.refresh_token == "the-rt"
        assert token.id_token == "the-id"
        assert token.scopes == ["read:user"]

    def test_decrypt_without_refresh_token(self):
        store = _store()
        identity = MagicMock()
        identity.user_id = 1
        identity.auth_provider = "github"
        identity.access_token = _enc(store, "at", "access_token", puid=None)
        identity.refresh_token = None
        identity.id_token = None
        identity.token_type = None
        identity.expires_at = None
        identity.scopes = None
        identity.provider_user_id = None
        token = store.decrypt_credential(identity)
        assert token.access_token == "at"
        assert token.refresh_token is None
        assert token.id_token is None
        assert token.token_type == "Bearer"


class TestMasked:
    def test_masked_has_no_token_material(self):
        store = _store()
        identity = MagicMock()
        identity.identity_id = "11111111-1111-1111-1111-111111111111"
        identity.auth_provider = "github"
        identity.provider_user_id = "99"
        identity.scopes = ["read:user"]
        identity.token_type = "Bearer"
        identity.expires_at = None
        identity.refreshed_at = None
        identity.created_at = None
        identity.enabled = True
        identity.refresh_token = b"ciphered"
        identity.auth_data = {"login": "octo"}
        masked = store.masked(identity)
        assert "access_token" not in masked
        assert masked["has_refresh_token"] is True
        assert masked["auth_provider"] == "github"
        assert masked["profile"] == {"login": "octo"}


class TestVaultCacheHelpers:
    def _session_with_vault(self, vault):
        session = MagicMock()
        session.get = MagicMock(return_value=vault)
        return session

    @pytest.mark.asyncio
    async def test_cache_credential_sets_key(self):
        vault = AsyncMock()
        session = self._session_with_vault(vault)
        await cache_credential(session, "github", {"access_token": "at"})
        vault.set.assert_awaited_once_with(
            IDENTITY_VAULT_KEY.format(provider="github"),
            {"access_token": "at"},
        )

    @pytest.mark.asyncio
    async def test_cached_credential_roundtrip(self):
        vault = AsyncMock()
        vault.exists = AsyncMock(return_value=True)
        vault.get = AsyncMock(return_value={"access_token": "at"})
        session = self._session_with_vault(vault)
        assert await cached_credential(session, "github") == {"access_token": "at"}

    @pytest.mark.asyncio
    async def test_cached_credential_none_without_vault(self):
        session = self._session_with_vault(None)
        assert await cached_credential(session, "github") is None

    @pytest.mark.asyncio
    async def test_invalidate_deletes_key(self):
        vault = AsyncMock()
        vault.exists = AsyncMock(return_value=True)
        session = self._session_with_vault(vault)
        await invalidate_cached(session, "github")
        vault.delete.assert_awaited_once_with(IDENTITY_VAULT_KEY.format(provider="github"))

    @pytest.mark.asyncio
    async def test_helpers_swallow_vault_errors(self):
        vault = AsyncMock()
        vault.set = AsyncMock(side_effect=RuntimeError("redis down"))
        session = self._session_with_vault(vault)
        # must not raise
        await cache_credential(session, "github", {"a": 1})


class _Row:
    """Minimal stand-in for an ``auth.user_identities`` row."""

    def __init__(self, identity_id, refreshed_at=None, created_at=None):
        self.identity_id = identity_id
        self.refreshed_at = refreshed_at
        self.created_at = created_at
        self.access_token = b"ciphered"
        self.enabled = True


def _patch_filter(rows):
    return patch(
        "navigator_auth.identity.store._filter_identities",
        AsyncMock(return_value=list(rows)),
    )


class TestDuplicateRowOrdering:
    """A duplicated (user, provider, account) must resolve deterministically."""

    @pytest.mark.asyncio
    async def test_newest_duplicate_wins_whatever_the_db_order(self):
        now = datetime.now(timezone.utc)
        older = _Row("a", refreshed_at=now - timedelta(hours=1))
        newer = _Row("b", refreshed_at=now)
        for rows in ([older, newer], [newer, older]):
            with _patch_filter(rows):
                picked = await _store().get_for_provider_account(1, "github", "99")
            assert picked is newer

    @pytest.mark.asyncio
    async def test_equal_timestamps_break_on_identity_id(self):
        now = datetime.now(timezone.utc)
        first = _Row("aaa", refreshed_at=now)
        second = _Row("bbb", refreshed_at=now)
        for rows in ([first, second], [second, first]):
            with _patch_filter(rows):
                picked = await _store().get_for_provider_account(1, "github", "99")
            assert picked is second

    @pytest.mark.asyncio
    async def test_falls_back_to_created_at_without_refreshed_at(self):
        now = datetime.now(timezone.utc)
        older = _Row("a", created_at=now - timedelta(days=1))
        newer = _Row("b", created_at=now)
        with _patch_filter([older, newer]):
            picked = await _store().get_for_provider_account(1, "github", "99")
        assert picked is newer

    @pytest.mark.asyncio
    async def test_get_by_provider_still_picks_the_newest(self):
        now = datetime.now(timezone.utc)
        older = _Row("a", refreshed_at=now - timedelta(hours=2))
        newer = _Row("b", refreshed_at=now)
        with _patch_filter([older, newer]):
            picked = await _store().get_by_provider(1, "github")
        assert picked is newer


class TestSaveLinkedIdentityNullTokens:
    @pytest.mark.asyncio
    async def test_insert_without_refresh_or_id_token(self):
        """The GitHub insert branch: no existing row, no refresh/id token."""
        from asyncdb.exceptions import NoDataFound
        from navigator_auth.identity.types import TokenResponse
        from navigator_auth.models import UserIdentity

        captured = []

        async def _insert(self_):
            captured.append(self_)
            return self_

        token = TokenResponse(access_token="at", refresh_token=None, id_token=None, provider_user_id="99")
        with (
            patch.object(UserIdentity, "get", new=AsyncMock(side_effect=NoDataFound("none"))),
            patch.object(UserIdentity, "insert", new=_insert),
        ):
            await _store().save_linked_identity(1, "github", token)
        assert len(captured) == 1
        assert captured[0].access_token is not None
        assert captured[0].refresh_token is None
        assert captured[0].id_token is None

    @pytest.mark.asyncio
    async def test_update_keeps_previously_vaulted_tokens(self):
        """Regression guard on store.py:179-193 — a re-save must not clobber."""
        from navigator_auth.identity.types import TokenResponse
        from navigator_auth.models import UserIdentity

        store = _store()
        existing = MagicMock()
        existing.provider_user_id = "99"
        existing.refresh_token = _enc(store, "old-rt", "refresh_token")
        existing.id_token = _enc(store, "old-id", "id_token")
        sealed_rt, sealed_id = existing.refresh_token, existing.id_token
        existing.update = AsyncMock(return_value=existing)

        token = TokenResponse(access_token="new-at", provider_user_id="99")
        with patch.object(UserIdentity, "get", new=AsyncMock(return_value=existing)):
            await store.save_linked_identity(1, "github", token)
        assert existing.refresh_token == sealed_rt
        assert existing.id_token == sealed_id
        existing.update.assert_awaited_once()


class TestFilterIdentitiesProjection:
    """Reads must survive a legacy column on ``auth.user_identities``.

    A pre-Identity-Vault table keeps ``uid`` (half of its legacy primary
    key). ``SELECT *`` fed it into ``UserIdentity.__init__`` and every
    filter-based read died with
    ``TypeError: ... unexpected keyword argument 'uid'``.
    """

    def _row(self, **extra):
        row = {
            "identity_id": "11111111-1111-1111-1111-111111111111",
            "user_id": 35,
            "auth_provider": "azure",
            "access_token": b"ciphered",
            "refresh_token": None,
            "id_token": None,
            "enabled": True,
        }
        row.update(extra)
        return row

    def test_projection_names_the_model_columns(self):
        assert "*" not in _IDENTITY_SELECT
        for column in ("identity_id", "user_id", "auth_provider", "access_token"):
            assert column in _IDENTITY_SELECT
        assert "uid," not in _IDENTITY_SELECT

    @pytest.mark.asyncio
    async def test_hydrates_rows_carrying_a_legacy_column(self):
        conn = AsyncMock()
        conn.fetch_all = AsyncMock(return_value=[self._row(uid="legacy-surrogate")])
        rows = await _filter_identities(conn, user_id=35)
        assert len(rows) == 1
        assert isinstance(rows[0], UserIdentity)
        assert rows[0].auth_provider == "azure"
        assert rows[0].refresh_token is None
        assert not hasattr(rows[0], "uid")

    @pytest.mark.asyncio
    async def test_criteria_become_bound_parameters(self):
        conn = AsyncMock()
        conn.fetch_all = AsyncMock(return_value=None)
        rows = await _filter_identities(
            conn, user_id=35, auth_provider="azure"
        )
        assert rows == []
        sql, *params = conn.fetch_all.await_args.args
        assert sql.endswith("WHERE user_id = $1 AND auth_provider = $2")
        assert params == [35, "azure"]

    @pytest.mark.asyncio
    async def test_unknown_column_is_rejected(self):
        conn = AsyncMock()
        with pytest.raises(ValueError):
            await _filter_identities(conn, uid="legacy-surrogate")
        conn.fetch_all.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_string_user_id_is_bound_as_an_integer(self):
        conn = AsyncMock()
        conn.fetch_all = AsyncMock(return_value=[self._row()])
        pool = MagicMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=conn)
        ctx.__aexit__ = AsyncMock(return_value=False)

        async def _acquire():
            return ctx

        pool.acquire = MagicMock(side_effect=lambda: _acquire())
        store = IdentityStore(pool, cipher=IdentityCipher(master_keys=MASTER_KEYS))
        identities = await store.list_for_user("35")
        assert len(identities) == 1
        assert conn.fetch_all.await_args.args[1] == 35
