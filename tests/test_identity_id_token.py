"""Unit tests for FEAT-096 TASK-047:

- TokenResponse.id_token round-trip (credential()/from_credential()).
- IdentityStore save/decrypt/mask id_token.
- IdentityStore.find_user_by_provider_account.
- D10: re-save without a refresh token keeps the previously vaulted one.
- Migration ordering (001 then 002).

Uses a fake pool/conn and a FakeUserIdentity standing in for the real
``UserIdentity`` model, mirroring the mocking style already used in
tests/unit/identity/test_identity_store.py (no live DB).
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asyncdb.exceptions import NoDataFound

from navigator_auth.identity.crypto import IdentityCipher
from navigator_auth.identity.store import IdentityStore
from navigator_auth.identity.types import TokenResponse

MASTER_KEYS = {1: b"\x00" * 32}


# ---------------------------------------------------------------------------
# TokenResponse.id_token round-trip
# ---------------------------------------------------------------------------
def test_token_response_id_token_roundtrip():
    token = TokenResponse(
        access_token="at",
        refresh_token="rt",
        id_token="id-jwt",
        provider_user_id="u1",
    )
    cred = token.credential()
    assert cred["id_token"] == "id-jwt"
    assert "raw" not in cred
    rebuilt = TokenResponse.from_credential(cred)
    assert rebuilt.id_token == "id-jwt"
    assert rebuilt.access_token == "at"
    assert rebuilt.refresh_token == "rt"


def test_token_response_from_oauth_response_picks_id_token():
    token = TokenResponse.from_oauth_response(
        {"access_token": "at", "id_token": "id-jwt", "token_type": "Bearer"}
    )
    assert token.id_token == "id-jwt"
    assert token.raw.get("id_token") == "id-jwt"


def test_token_response_credential_omits_raw():
    token = TokenResponse(access_token="at", raw={"secret": "leak"})
    assert "raw" not in token.credential()


# ---------------------------------------------------------------------------
# Fake pool / fake UserIdentity model
# ---------------------------------------------------------------------------
def _make_pool():
    conn = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=False)

    async def _acquire():
        return ctx

    pool = MagicMock()
    pool.acquire = MagicMock(side_effect=lambda: _acquire())
    return pool


def _store():
    return IdentityStore(_make_pool(), cipher=IdentityCipher(master_keys=MASTER_KEYS))


class FakeMeta:
    connection = None


class FakeUserIdentity:
    """Stand-in for navigator_auth.models.UserIdentity in unit tests."""

    Meta = FakeMeta
    # Configured per-test: None (miss) or a FakeUserIdentity instance (hit).
    _existing = None
    _filter_result = None

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.user_id = kwargs.get("user_id")
        self.auth_provider = kwargs.get("auth_provider")

    @classmethod
    async def get(cls, **kwargs):
        if cls._existing is not None:
            return cls._existing
        raise NoDataFound("no row")

    @classmethod
    async def filter(cls, **kwargs):
        if cls._filter_result is None:
            raise NoDataFound("no rows")
        return cls._filter_result

    async def insert(self):
        return self

    async def update(self):
        return self


@pytest.fixture(autouse=True)
def _reset_fake_model():
    FakeUserIdentity._existing = None
    FakeUserIdentity._filter_result = None
    yield
    FakeUserIdentity._existing = None
    FakeUserIdentity._filter_result = None


# ---------------------------------------------------------------------------
# save_linked_identity / decrypt_credential / masked
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_store_saves_and_decrypts_id_token():
    store = _store()
    token = TokenResponse(
        access_token="at",
        refresh_token="rt",
        id_token="id-jwt",
        provider_user_id="u1",
    )
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        row = await store.save_linked_identity(user_id=1, provider="azure", token=token)
    assert row.id_token is not None
    decrypted = store._cipher.decrypt(row.id_token)
    assert decrypted == "id-jwt"
    full = store.decrypt_credential(row)
    assert full.id_token == "id-jwt"
    assert full.access_token == "at"
    assert full.refresh_token == "rt"


@pytest.mark.asyncio
async def test_masked_hides_id_token():
    store = _store()
    identity = MagicMock()
    identity.identity_id = "11111111-1111-1111-1111-111111111111"
    identity.auth_provider = "azure"
    identity.provider_user_id = "u1"
    identity.scopes = []
    identity.token_type = "Bearer"
    identity.expires_at = None
    identity.refreshed_at = None
    identity.created_at = None
    identity.enabled = True
    identity.refresh_token = b"ciphered"
    identity.id_token = b"ciphered-id"
    identity.auth_data = {}
    masked = store.masked(identity)
    assert "id_token" not in masked
    assert "access_token" not in masked
    assert masked["has_id_token"] is True


@pytest.mark.asyncio
async def test_resave_without_refresh_keeps_existing_refresh():
    store = _store()
    existing = FakeUserIdentity(
        user_id=1,
        auth_provider="azure",
        provider_user_id="u1",
        refresh_token=store._cipher.encrypt("old-rt"),
        id_token=store._cipher.encrypt("old-id"),
    )
    FakeUserIdentity._existing = existing
    token = TokenResponse(
        access_token="new-at",
        refresh_token=None,
        id_token=None,
        provider_user_id="u1",
    )
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        row = await store.save_linked_identity(user_id=1, provider="azure", token=token)
    assert store._cipher.decrypt(row.refresh_token) == "old-rt"
    assert store._cipher.decrypt(row.id_token) == "old-id"
    # access token is always refreshed
    assert store._cipher.decrypt(row.access_token) == "new-at"


@pytest.mark.asyncio
async def test_resave_with_new_refresh_overwrites_existing():
    store = _store()
    existing = FakeUserIdentity(
        user_id=1,
        auth_provider="azure",
        provider_user_id="u1",
        refresh_token=store._cipher.encrypt("old-rt"),
        id_token=store._cipher.encrypt("old-id"),
    )
    FakeUserIdentity._existing = existing
    token = TokenResponse(
        access_token="new-at",
        refresh_token="new-rt",
        id_token="new-id",
        provider_user_id="u1",
    )
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        row = await store.save_linked_identity(user_id=1, provider="azure", token=token)
    assert store._cipher.decrypt(row.refresh_token) == "new-rt"
    assert store._cipher.decrypt(row.id_token) == "new-id"


# ---------------------------------------------------------------------------
# find_user_by_provider_account
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_find_user_by_provider_account_hit_miss_disabled():
    store = _store()

    # Hit
    row = FakeUserIdentity(user_id=42, auth_provider="azure", provider_user_id="u1", enabled=True)
    FakeUserIdentity._filter_result = [row]
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        user_id = await store.find_user_by_provider_account("azure", "u1")
    assert user_id == 42

    # Miss (NoDataFound)
    FakeUserIdentity._filter_result = None
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        user_id = await store.find_user_by_provider_account("azure", "unknown")
    assert user_id is None

    # Disabled row is ignored
    disabled_row = FakeUserIdentity(user_id=99, auth_provider="azure", provider_user_id="u2", enabled=False)
    FakeUserIdentity._filter_result = [disabled_row]
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        user_id = await store.find_user_by_provider_account("azure", "u2")
    assert user_id is None


# ---------------------------------------------------------------------------
# Migration ordering
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_migration_runs_002_after_001():
    from navigator_auth.identity import migrations

    executed_sql = []

    class FakeConn:
        async def execute(self, sql):
            executed_sql.append(sql)

    class FakeCtx:
        async def __aenter__(self):
            return FakeConn()

        async def __aexit__(self, *args):
            return False

    class FakePool:
        def acquire(self):
            return FakeCtx()

    await migrations.ensure_identity_columns(FakePool())
    assert len(executed_sql) == 2
    assert "provider_user_id" in executed_sql[0]
    assert "id_token" in executed_sql[1]


@pytest.mark.asyncio
async def test_credential_endpoint_serializes_id_token_without_handler_changes():
    """The credential endpoint (handlers/user_identities.py) is read-only in
    this task; it already calls store.decrypt_credential(...).credential(),
    which now carries id_token automatically."""
    store = _store()
    identity = MagicMock()
    identity.access_token = store._cipher.encrypt("at")
    identity.refresh_token = store._cipher.encrypt("rt")
    identity.id_token = store._cipher.encrypt("id-jwt")
    identity.token_type = "Bearer"
    identity.expires_at = None
    identity.scopes = []
    identity.provider_user_id = "u1"
    token = store.decrypt_credential(identity)
    cred = token.credential()
    assert cred["id_token"] == "id-jwt"


@pytest.mark.asyncio
async def test_migration_idempotent_when_run_twice():
    from navigator_auth.identity import migrations

    class FakeConn:
        async def execute(self, sql):
            pass

    class FakeCtx:
        async def __aenter__(self):
            return FakeConn()

        async def __aexit__(self, *args):
            return False

    class FakePool:
        def acquire(self):
            return FakeCtx()

    pool = FakePool()
    await migrations.ensure_identity_columns(pool)
    await migrations.ensure_identity_columns(pool)  # no error on 2nd run
