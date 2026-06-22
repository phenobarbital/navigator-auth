import pytest
import json
from unittest.mock import AsyncMock, patch
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_auth.handlers.vault import VaultView

@pytest.fixture
def mock_vault():
    vault = AsyncMock()
    vault.keys.return_value = ["test_key_1", "test_key_2"]
    vault.get.return_value = "super_secret_value"
    vault.exists.return_value = True
    return vault

@pytest.fixture
def create_view(mock_vault):
    def _create_view(method, path, match_info=None, body=None):
        payload = json.dumps(body).encode('utf-8') if body else None
        
        request = make_mocked_request(
            method, path, match_info=match_info or {},
            payload=payload
        )
        
        # We need an abstract json method on the request since get_json() isn't trivial on mock
        if body is not None:
            request.json = AsyncMock(return_value=body)
            
        view = VaultView(request)
        
        async def mock_get_session_and_vault():
            return mock_vault
        view._get_session_and_vault = mock_get_session_and_vault
        return view
    return _create_view

@pytest.mark.asyncio
async def test_get_all_keys(create_view, mock_vault):
    view = create_view("GET", "/api/v1/user/vault")
    resp = await view.get()
    assert resp.status == 200
    data = json.loads(resp.body)
    assert "keys" in data
    assert data["keys"] == ["test_key_1", "test_key_2"]

@pytest.mark.asyncio
async def test_get_specific_key(create_view, mock_vault):
    view = create_view("GET", "/api/v1/user/vault/test_key_1", match_info={"key": "test_key_1"})
    resp = await view.get()
    assert resp.status == 200
    data = json.loads(resp.body)
    assert data["key"] == "test_key_1"
    assert data["value"] == "super_secret_value"
    mock_vault.exists.assert_called_with("test_key_1")
    mock_vault.get.assert_called_with("test_key_1")

@pytest.mark.asyncio
async def test_get_specific_key_not_found(create_view, mock_vault):
    mock_vault.exists.return_value = False
    view = create_view("GET", "/api/v1/user/vault/missing_key", match_info={"key": "missing_key"})
    
    with pytest.raises(web.HTTPNotFound) as exc:
        await view.get()
    assert "Secret 'missing_key' not found." in exc.value.reason

@pytest.mark.asyncio
async def test_post_secret(create_view, mock_vault):
    payload = {"key": "new_secret", "value": "my_new_value"}
    view = create_view("POST", "/api/v1/user/vault", body=payload)
    
    resp = await view.post()
    assert resp.status == 201
    data = json.loads(resp.body)
    assert data["message"] == "Secret 'new_secret' saved successfully."
    mock_vault.set.assert_called_with("new_secret", "my_new_value")

@pytest.mark.asyncio
async def test_post_secret_missing_fields(create_view):
    # Missing value
    view = create_view("POST", "/api/v1/user/vault", body={"key": "new_secret"})
    with pytest.raises(web.HTTPBadRequest):
        await view.post()

    # Missing key
    view = create_view("POST", "/api/v1/user/vault", body={"value": "secret"})
    with pytest.raises(web.HTTPBadRequest):
        await view.post()

@pytest.mark.asyncio
async def test_delete_secret(create_view, mock_vault):
    view = create_view("DELETE", "/api/v1/user/vault/test_key_1", match_info={"key": "test_key_1"})
    resp = await view.delete()
    assert resp.status == 200
    data = json.loads(resp.body)
    assert data["message"] == "Secret 'test_key_1' deleted successfully."
    mock_vault.delete.assert_called_with("test_key_1")

@pytest.mark.asyncio
async def test_delete_secret_not_found(create_view, mock_vault):
    mock_vault.exists.return_value = False
    view = create_view("DELETE", "/api/v1/user/vault/missing_key", match_info={"key": "missing_key"})
    
    with pytest.raises(web.HTTPNotFound):
        await view.delete()
