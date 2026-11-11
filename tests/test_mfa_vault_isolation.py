"""FEAT-106 reserved MFA vault namespace tests."""

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_session import SESSION_OBJECT
from navigator_session.vault import KeyRing, VaultContext, VaultSecretMetadata, seal_value
from navigator_session.vault.session_vault import _SELECT_ALL_ACTIVE

import navigator_auth.vault.reserved as reserved_mod
from navigator_auth.handlers.vault import VaultView
from navigator_auth.vault import integration
from navigator_auth.vault.reserved import ReservedPrefixSessionVault, is_reserved_key

SESSION_UUID = "550e8400-e29b-41d4-a716-446655440000"
UPDATED = datetime(2026, 11, 11, tzinfo=timezone.utc)


@pytest.fixture
def keyring():
    return KeyRing({1: b"\x00" * 32}, 1)


@pytest.fixture
def rows(keyring):
    probe = ReservedPrefixSessionVault(session_uuid=SESSION_UUID, user_id=7, db_pool=None, keyring=keyring)
    ordinary = seal_value("tok-123", probe._db_context("jira:token"), keyring)
    seed_ctx = VaultContext(
        purpose="mfa", layer="db", fields=(("user_id", 7), ("provider", "totp"), ("key", "mfa:totp"))
    )
    seed = seal_value(b"\x01" * 20, seed_ctx, keyring)
    return [
        {"key": "jira:token", "ciphertext_db": ordinary, "key_version": 1, "updated_at": UPDATED},
        {"key": "mfa:totp", "ciphertext_db": seed, "key_version": 1, "updated_at": UPDATED},
    ]


@pytest.fixture
def fake_db(monkeypatch, rows):
    calls = []

    @asynccontextmanager
    async def acquire(_pool):
        yield object()

    async def fetch(_conn, sql, *args):
        calls.append((sql, args))
        return rows

    monkeypatch.setattr(reserved_mod, "acquire_connection", acquire)
    monkeypatch.setattr(reserved_mod, "fetch_rows", fetch)
    return calls


class TestLoader:
    @pytest.mark.asyncio
    async def test_loader_filters_reserved_rows_in_sql(self, fake_db, keyring):
        await ReservedPrefixSessionVault.load_for_session(SESSION_UUID, 7, db_pool=object(), keyring=keyring)
        sql, args = fake_db[0]
        assert "starts_with(key, $2)" in sql
        assert args == (7, "mfa:")

    @pytest.mark.asyncio
    async def test_loader_never_decrypts_reserved_rows(self, fake_db, keyring, caplog):
        vault = await ReservedPrefixSessionVault.load_for_session(SESSION_UUID, 7, db_pool=object(), keyring=keyring)
        assert await vault.keys() == ["jira:token"]
        assert "failed integrity check" not in caplog.text
        assert await vault.get("jira:token") == "tok-123"

    def test_upstream_select_unchanged(self):
        assert " ".join(_SELECT_ALL_ACTIVE.split()) == (
            "SELECT key, ciphertext_db, key_version, updated_at FROM auth.user_vault_secrets "
            "WHERE user_id = $1 AND deleted_at IS NULL"
        )

    def test_integration_uses_filtered_loader(self):
        assert integration.SessionVault is ReservedPrefixSessionVault


class TestValidateKey:
    @pytest.mark.parametrize("key", ["mfa:totp", "mfa:", "mfa:anything"])
    def test_reserved_keys_rejected(self, keyring, key):
        vault = ReservedPrefixSessionVault("session", 7, None, keyring=keyring)
        with pytest.raises(ValueError):
            vault._validate_key(key)

    @pytest.mark.parametrize("key", ["jira:access_token", "mfa", "xmfa:totp", "MFA:totp"])
    def test_ordinary_keys_accepted(self, keyring, key):
        vault = ReservedPrefixSessionVault("session", 7, None, keyring=keyring)
        vault._validate_key(key)
        assert not is_reserved_key(key)


class FakeSession(dict):
    def decode(self, key):
        return {"id": 42, "user_id": 42}


def meta(key, version=1):
    return VaultSecretMetadata(key=key, updated_at=UPDATED, key_version=version)


@pytest.fixture
def mock_vault():
    vault = AsyncMock()
    vault.list_metadata.return_value = [meta("jira:access_token", 2), meta("mfa:totp")]
    vault.exists.return_value = True
    vault.set.return_value = meta("jira:access_token")
    return vault


@pytest.fixture
def create_view(mock_vault):
    def create(method, path, match_info=None, body=None):
        payload = json.dumps(body).encode() if body else None
        request = make_mocked_request(method, path, match_info=match_info or {}, payload=payload)
        request[SESSION_OBJECT] = FakeSession()
        if body is not None:
            request.json = AsyncMock(return_value=body)
        view = VaultView(request)
        view._get_session_and_vault = AsyncMock(return_value=mock_vault)
        return view

    return create


class TestVaultHttp:
    @pytest.mark.asyncio
    async def test_vault_rejects_mfa_namespace(self, create_view, mock_vault):
        for method, path, match_info, body in (
            ("GET", "/vault/mfa:totp", {"key": "mfa:totp"}, None),
            ("POST", "/vault", {}, {"key": "mfa:totp", "value": "x"}),
            ("DELETE", "/vault/mfa:totp", {"key": "mfa:totp"}, None),
        ):
            with pytest.raises(web.HTTPBadRequest) as error:
                await getattr(create_view(method, path, match_info, body), method.lower())()
            assert json.loads(error.value.text) == {"error": "reserved_key"}
        mock_vault.get.assert_not_awaited()
        mock_vault.set.assert_not_awaited()
        mock_vault.delete.assert_not_awaited()
        mock_vault.exists.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_listing_omits_reserved_keys(self, create_view):
        response = await create_view("GET", "/vault").get()
        assert [item["key"] for item in json.loads(response.text)["secrets"]] == ["jira:access_token"]

    @pytest.mark.asyncio
    async def test_ordinary_secrets_still_work(self, create_view, mock_vault):
        assert (
            await create_view("POST", "/vault", body={"key": "jira:access_token", "value": "x"}).post()
        ).status == 201
        assert (await create_view("GET", "/vault/jira:access_token", {"key": "jira:access_token"}).get()).status == 200
        assert (
            await create_view("DELETE", "/vault/jira:access_token", {"key": "jira:access_token"}).delete()
        ).status == 200
