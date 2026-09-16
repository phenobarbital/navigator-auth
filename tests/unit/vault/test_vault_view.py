"""Tests for the Session Vault HTTP API v2 (FEAT-099, TASK-078): metadata only."""
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_session import SESSION_OBJECT
from navigator_session.vault import (
    UnsupportedFormatError,
    VaultIntegrityError,
    VaultSecretMetadata,
)

from navigator_auth.handlers.vault import VaultView

UPDATED = datetime(2026, 9, 16, 10, 30, tzinfo=timezone.utc)


class _FakeSession(dict):
    """Minimal stand-in for SessionData: dict-like, plus decode()."""

    def decode(self, key):
        return {"id": 42, "user_id": 42}


def meta(key, version=1):
    return VaultSecretMetadata(key=key, updated_at=UPDATED, key_version=version)


@pytest.fixture
def mock_vault():
    vault = AsyncMock()
    vault.keys.return_value = ["test_key_1", "jira:access_token"]
    vault.list_metadata.return_value = [meta("jira:access_token", 2), meta("test_key_1")]
    vault.get.return_value = "super_secret_value"
    vault.exists.return_value = True
    vault.set.return_value = meta("new_secret")
    return vault


@pytest.fixture
def create_view(mock_vault):
    def _create_view(method, path, match_info=None, body=None, vault=None):
        payload = json.dumps(body).encode("utf-8") if body else None
        request = make_mocked_request(method, path, match_info=match_info or {}, payload=payload)
        # @user_session() calls get_session(request) first; seed a session object.
        request[SESSION_OBJECT] = _FakeSession()
        if body is not None:
            request.json = AsyncMock(return_value=body)
        view = VaultView(request)

        async def mock_get_session_and_vault():
            return vault or mock_vault

        view._get_session_and_vault = mock_get_session_and_vault
        return view

    return _create_view


def body_of(resp):
    return json.loads(resp.body)


def error_of(exc):
    return json.loads(exc.value.text)


@pytest.mark.asyncio
async def test_list_returns_metadata_only(create_view, mock_vault):
    resp = await create_view("GET", "/api/v1/user/vault").get()
    assert resp.status == 200
    data = body_of(resp)
    assert data == {"secrets": [
        {"key": "jira:access_token", "updated_at": "2026-09-16T10:30:00Z", "key_version": 2},
        {"key": "test_key_1", "updated_at": "2026-09-16T10:30:00Z", "key_version": 1},
    ]}
    assert b"super_secret_value" not in resp.body
    mock_vault.get.assert_not_called()


@pytest.mark.asyncio
async def test_get_key_returns_metadata_only(create_view, mock_vault):
    view = create_view("GET", "/api/v1/user/vault/test_key_1", match_info={"key": "test_key_1"})
    resp = await view.get()
    assert resp.status == 200
    data = body_of(resp)
    assert set(data) == {"key", "updated_at", "key_version"}
    assert data["key"] == "test_key_1" and data["key_version"] == 1
    assert b"super_secret_value" not in resp.body
    mock_vault.exists.assert_called_with("test_key_1")


@pytest.mark.asyncio
async def test_get_key_without_metadata(create_view, mock_vault):
    mock_vault.list_metadata.return_value = []
    view = create_view("GET", "/api/v1/user/vault/cached", match_info={"key": "cached"})
    data = body_of(await view.get())
    assert data == {"key": "cached", "updated_at": None, "key_version": None}


@pytest.mark.asyncio
async def test_get_specific_key_not_found(create_view, mock_vault):
    mock_vault.exists.return_value = False
    view = create_view("GET", "/api/v1/user/vault/missing_key", match_info={"key": "missing_key"})
    with pytest.raises(web.HTTPNotFound) as exc:
        await view.get()
    assert "Secret 'missing_key' not found." in exc.value.reason


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [VaultIntegrityError("x"), UnsupportedFormatError("x")])
async def test_get_key_integrity_error_409(create_view, mock_vault, error):
    mock_vault.get.side_effect = error
    view = create_view("GET", "/api/v1/user/vault/test_key_1", match_info={"key": "test_key_1"})
    with pytest.raises(web.HTTPConflict) as exc:
        await view.get()
    assert error_of(exc) == {"error": "vault_integrity_error"}


@pytest.mark.asyncio
async def test_post_returns_metadata_and_message(create_view, mock_vault):
    payload = {"key": "new_secret", "value": "my_new_value"}
    resp = await create_view("POST", "/api/v1/user/vault", body=payload).post()
    assert resp.status == 201
    data = body_of(resp)
    assert data == {
        "key": "new_secret", "updated_at": "2026-09-16T10:30:00Z", "key_version": 1,
        "message": "Secret 'new_secret' saved successfully.",
    }
    assert "value" not in data and b"my_new_value" not in resp.body
    mock_vault.set.assert_called_with("new_secret", "my_new_value")


@pytest.mark.asyncio
async def test_post_colon_key(create_view, mock_vault):
    mock_vault.set.return_value = meta("jira:access_token")
    resp = await create_view("POST", "/api/v1/user/vault",
                             body={"key": "jira:access_token", "value": "tok"}).post()
    assert body_of(resp)["key"] == "jira:access_token"


@pytest.mark.asyncio
async def test_post_validation_errors(create_view, mock_vault):
    with pytest.raises(web.HTTPBadRequest):
        await create_view("POST", "/api/v1/user/vault", body={"key": "new_secret"}).post()
    with pytest.raises(web.HTTPBadRequest):
        await create_view("POST", "/api/v1/user/vault", body={"value": "secret"}).post()
    mock_vault.set.side_effect = ValueError("Vault key cannot contain control characters")
    with pytest.raises(web.HTTPBadRequest):
        await create_view("POST", "/api/v1/user/vault", body={"key": "bad", "value": "v"}).post()


@pytest.mark.asyncio
async def test_post_unexpected_error_500_without_value(create_view, mock_vault):
    mock_vault.set.side_effect = RuntimeError("db down")
    with pytest.raises(web.HTTPInternalServerError) as exc:
        await create_view("POST", "/api/v1/user/vault", body={"key": "k", "value": "leak-me"}).post()
    assert "leak-me" not in exc.value.text


@pytest.mark.asyncio
async def test_delete_secret(create_view, mock_vault):
    view = create_view("DELETE", "/api/v1/user/vault/test_key_1", match_info={"key": "test_key_1"})
    resp = await view.delete()
    assert resp.status == 200
    assert body_of(resp)["message"] == "Secret 'test_key_1' deleted successfully."
    mock_vault.delete.assert_called_with("test_key_1")


@pytest.mark.asyncio
async def test_delete_secret_not_found(create_view, mock_vault):
    mock_vault.exists.return_value = False
    view = create_view("DELETE", "/api/v1/user/vault/missing_key", match_info={"key": "missing_key"})
    with pytest.raises(web.HTTPNotFound):
        await view.delete()


@pytest.mark.asyncio
async def test_vault_unavailable_503():
    request = make_mocked_request("GET", "/api/v1/user/vault", app={"authdb": None})
    request[SESSION_OBJECT] = _FakeSession()
    view = VaultView(request)
    view.user = {"user_id": 42}
    with pytest.raises(web.HTTPServiceUnavailable) as exc:
        await view._get_vault(_FakeSession())
    assert error_of(exc) == {"error": "vault_unavailable"}


@pytest.mark.asyncio
async def test_vault_load_failure_503(monkeypatch):
    import navigator_auth.handlers.vault as handler_mod

    monkeypatch.setattr(handler_mod, "get_session_vault", AsyncMock(return_value=None))
    request = make_mocked_request("GET", "/api/v1/user/vault", app={"authdb": object()})
    request[SESSION_OBJECT] = _FakeSession()
    view = VaultView(request)
    view.user = {"user_id": 42}
    with pytest.raises(web.HTTPServiceUnavailable) as exc:
        await view._get_vault(_FakeSession())
    assert error_of(exc) == {"error": "vault_unavailable"}
