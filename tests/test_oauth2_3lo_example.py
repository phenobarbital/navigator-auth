"""FEAT-108 — examples/oauth2_3lo_server.py wiring (M1) and, from TASK-206, the app-level flow (M8)."""

import importlib.util
import logging
import secrets
from pathlib import Path
from types import ModuleType
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from navigator_session import SESSION_KEY

import navigator_auth.conf as nav_conf
import navigator_auth.backends.idp as idp_module
from navigator_auth.backends.oauth2.pkce import generate_challenge

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "oauth2_3lo_server.py"
SETTINGS = Path(__file__).resolve().parent.parent / "settings" / "settings.py"
_TEST_SECRET = "feat108-" + "k" * 40


def _load_example() -> ModuleType:
    """Import examples/oauth2_3lo_server.py by path (it is not a package).

    Its ``os.environ.setdefault`` side effects are expected.
    """
    spec = importlib.util.spec_from_file_location("oauth2_3lo_server_example", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_pins_oauth2_backend_only():
    """AC1: only Oauth2Provider, no authorization backends, even with a richer settings.py."""
    if not SETTINGS.exists():
        pytest.skip("settings/settings.py absent: nothing to override")
    example = _load_example()
    app = example.make_app()
    auth = app["auth"]
    assert set(auth.backends) == {"Oauth2Provider"}
    assert auth._authz_backends == []


@pytest.mark.parametrize("key", ["short", b"tiny", None])
def test_example_warns_on_short_secret(monkeypatch, caplog, key):
    """AC2: one warning naming AUTH_SECRET_KEY, never the key."""
    example = _load_example()
    monkeypatch.setattr(nav_conf, "SECRET_KEY", key)
    with caplog.at_level(logging.WARNING):
        example._warn_on_short_secret()
    records = [record for record in caplog.records if "AUTH_SECRET_KEY" in record.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert str(key) not in records[0].getMessage()


def test_example_quiet_on_long_secret(monkeypatch, caplog):
    """AC2: nothing logged for a >= 32-byte key."""
    example = _load_example()
    monkeypatch.setattr(nav_conf, "SECRET_KEY", "k" * 48)
    with caplog.at_level(logging.WARNING):
        example._warn_on_short_secret()
    assert not [record for record in caplog.records if "AUTH_SECRET_KEY" in record.getMessage()]


@pytest_asyncio.fixture
async def example_client(monkeypatch):
    """Start the 3LO example and provide a cookie-carrying test client."""
    monkeypatch.setattr(idp_module, "SECRET_KEY", _TEST_SECRET)
    example = _load_example()
    app = example.make_app()
    auth = app["auth"]
    storage = auth.session.storage

    async def create_foreign_session(request):
        """Create a session whose owner does not exist in the demo IdP."""
        identity = "35"
        request[SESSION_KEY] = identity
        session = await storage.new_session(request, {SESSION_KEY: identity})
        await session.save_encoded_data(request, "user", {"user_id": 35, "username": "foreign"})
        return web.json_response({"created": True})

    app.router.add_post("/_test/foreign-session", create_foreign_session)
    auth.add_exclude_list("/_test/foreign-session")
    client = TestClient(TestServer(app))
    try:
        await client.start_server()
    except Exception as exc:
        await client.close()
        pytest.skip(f"Redis session storage unavailable: {exc}")

    yield client, example

    await client.close()


def _query(location: str) -> dict[str, str]:
    """Return a redirect location's single-valued query parameters."""
    return {key: values[0] for key, values in parse_qs(urlparse(location).query).items()}


async def _login_and_get_tokens(client: TestClient, example: ModuleType) -> dict:
    """Drive login, authorization, consent, and a PKCE token exchange."""
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(12)
    authorize = {
        "response_type": "code",
        "client_id": example.CLIENT_ID,
        "redirect_uri": example.REDIRECT_URI,
        "scope": example.SCOPES,
        "state": state,
        "code_challenge": generate_challenge(verifier),
        "code_challenge_method": "S256",
    }
    login = await client.post(
        "/oauth2/login", data={"username": "demo", "password": "demo123", **authorize}, allow_redirects=False
    )
    assert login.status == 302
    authorize_response = await client.get(login.headers["Location"], allow_redirects=False)
    assert authorize_response.status == 302
    consent = _query(authorize_response.headers["Location"])
    assert urlparse(authorize_response.headers["Location"]).path == "/oauth2/consent"

    approved = await client.post("/oauth2/consent", data={"action": "approve", **consent}, allow_redirects=False)
    assert approved.status == 302
    redirect = _query(approved.headers["Location"])
    assert urlparse(approved.headers["Location"]).geturl().startswith(example.REDIRECT_URI)
    assert redirect["state"] == state

    token = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": redirect["code"],
            "client_id": example.CLIENT_ID,
            "redirect_uri": example.REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert token.status == 200, await token.text()
    return await token.json()


@pytest.mark.asyncio
async def test_3lo_me_with_bearer_200(example_client):
    """AC18: the protected resource accepts the code-exchange bearer."""
    client, example = example_client
    tokens = await _login_and_get_tokens(client, example)

    response = await client.get("/api/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert response.status == 200
    payload = await response.json()
    assert payload["user"]["username"] == "demo"
    assert payload["token_claims"]["client_id"] == example.CLIENT_ID
    assert payload["token_claims"]["scope"]
    assert payload["token_claims"]["jti"]


@pytest.mark.asyncio
async def test_3lo_me_without_credentials_401(example_client):
    """AC18: the resource rejects a request with no bearer or session."""
    client, _ = example_client
    response = await client.get("/api/v1/me")
    assert response.status == 401


@pytest.mark.asyncio
async def test_3lo_list_grants_200(example_client):
    """AC18: the bearer exposes the caller's consent grant."""
    client, example = example_client
    tokens = await _login_and_get_tokens(client, example)

    response = await client.get(
        "/api/v1/oauth2/grants", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status == 200
    grants = await response.json()
    assert any(grant["client_id"] == example.CLIENT_ID for grant in grants)


@pytest.mark.asyncio
async def test_3lo_userinfo_profile(example_client):
    """AC18: userinfo returns the demo user's profile claims."""
    client, example = example_client
    tokens = await _login_and_get_tokens(client, example)

    response = await client.get("/oauth2/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert response.status == 200
    payload = await response.json()
    assert payload["sub"] == "1"
    assert payload["username"] == "demo"
    assert payload["email"] == "demo@example.com"


@pytest.mark.asyncio
async def test_3lo_refresh_binds_session(example_client, caplog):
    """AC18: refreshed tokens remain bound to a session without warnings."""
    client, example = example_client
    tokens = await _login_and_get_tokens(client, example)

    refreshed = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": example.CLIENT_ID,
        },
    )
    assert refreshed.status == 200, await refreshed.text()
    refreshed_tokens = await refreshed.json()
    response = await client.get(
        "/api/v1/me", headers={"Authorization": f"Bearer {refreshed_tokens['access_token']}"}
    )
    assert response.status == 200
    assert not [record for record in caplog.records if "cannot bind a session" in record.getMessage().lower()]


@pytest.mark.asyncio
async def test_3lo_foreign_session_forces_login(example_client):
    """AC11: a session whose owner is unknown is redirected to login."""
    client, example = example_client
    created = await client.post("/_test/foreign-session")
    assert created.status == 200
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(12)
    authorize = {
        "response_type": "code",
        "client_id": example.CLIENT_ID,
        "redirect_uri": example.REDIRECT_URI,
        "scope": example.SCOPES,
        "state": state,
        "code_challenge": generate_challenge(verifier),
        "code_challenge_method": "S256",
    }

    response = await client.get("/oauth2/authorize", params=authorize, allow_redirects=False)
    assert response.status == 302
    location = response.headers["Location"]
    assert urlparse(location).path == "/oauth2/login"
    login = _query(location)
    assert login["client_id"] == example.CLIENT_ID
    assert login["state"] == state
    assert login["code_challenge"] == authorize["code_challenge"]
