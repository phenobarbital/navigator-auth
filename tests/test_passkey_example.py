"""examples/passkey_server.py — the passkey life cycle against the example app (no browser)."""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

import navigator_auth.backends.idp as idp_module
import navigator_auth.backends.passkey as passkey_backend
import navigator_auth.conf as nav_conf
from tests.fixtures.passkey import SoftAuthenticator

pytest.importorskip("webauthn")

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "passkey_server.py"
_TEST_SECRET = "passkey-example-" + "k" * 40


def _load_example() -> ModuleType:
    """Import examples/passkey_server.py by path (it is not a package)."""
    spec = importlib.util.spec_from_file_location("passkey_server_example", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest_asyncio.fixture
async def example_client(monkeypatch):
    """Start the example; undo the module-level replacements ``make_app()`` installs."""
    monkeypatch.setattr(idp_module, "SECRET_KEY", _TEST_SECRET)
    monkeypatch.setattr(
        passkey_backend, "security_transition", passkey_backend.security_transition
    )
    monkeypatch.setattr(
        nav_conf, "PASSKEY_RELYING_PARTIES", nav_conf.PASSKEY_RELYING_PARTIES
    )
    monkeypatch.setattr(nav_conf, "PASSKEY_USER_VERIFICATION", "required")
    example = _load_example()
    client = TestClient(TestServer(example.make_app()))
    try:
        await client.start_server()
    except Exception as exc:  # pylint: disable=W0703
        await client.close()
        pytest.skip(f"Redis unavailable: {exc}")

    yield client, example

    await client.close()


def _b64_to_bytes(value: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(value)


async def _password_login(client: TestClient, example: ModuleType) -> dict:
    """Sign in as ``demo`` with BasicAuth; return the bearer + Origin headers."""
    response = await client.post(
        "/api/v1/login",
        json={"username": "demo", "password": "demo123"},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert response.status == 200
    token = (await response.json())["token"]
    return {"Authorization": f"Bearer {token}", "Origin": example.BASE_URL}


async def _enroll(
    client: TestClient, example: ModuleType, headers: dict
) -> tuple[SoftAuthenticator, bytes, str]:
    """Enroll a software authenticator; return it with the user handle and credential id."""
    response = await client.post(
        "/api/v1/auth/passkey/register/options", json={}, headers=headers
    )
    assert response.status == 200
    options = await response.json()
    assert options["rp"]["id"] == example.HOST
    handle = _b64_to_bytes(options["user"]["id"])
    soft = SoftAuthenticator()
    credential = soft.make_attestation(
        example.HOST, example.BASE_URL, _b64_to_bytes(options["challenge"]), handle
    )
    response = await client.post(
        "/api/v1/auth/passkey/register/verify",
        json={"credential": credential, "label": "soft key"},
        headers=headers,
    )
    assert response.status == 201
    return soft, handle, (await response.json())["id"]


async def _passkey_login(client, example, soft, handle, *, username=None, sign_count=1):
    """Run a sign-in ceremony and return the ``POST /api/v1/login`` response."""
    origin = {"Origin": example.BASE_URL}
    response = await client.post(
        "/api/v1/auth/passkey/login/options",
        json={"username": username} if username else {},
        headers=origin,
    )
    assert response.status == 200
    started = await response.json()
    assertion = soft.make_assertion(
        example.HOST,
        example.BASE_URL,
        _b64_to_bytes(started["publicKey"]["challenge"]),
        sign_count=sign_count,
        user_handle=handle,
    )
    return started, await client.post(
        "/api/v1/login",
        json={"challenge_id": started["challenge_id"], "credential": assertion},
        headers={"X-Auth-Method": "PasskeyAuth", **origin},
    )


def test_example_pins_backends_and_relying_party(monkeypatch):
    """Only BasicAuth + PasskeyAuth, no authorization backends, one RP for the example origin."""
    monkeypatch.setattr(
        passkey_backend, "security_transition", passkey_backend.security_transition
    )
    monkeypatch.setattr(
        nav_conf, "PASSKEY_RELYING_PARTIES", nav_conf.PASSKEY_RELYING_PARTIES
    )
    example = _load_example()
    app = example.make_app()
    auth = app["auth"]
    assert list(auth.backends) == ["BasicAuth", "PasskeyAuth"]
    assert auth._authz_backends == []
    assert [rp["origin"] for rp in example.RELYING_PARTIES] == [example.BASE_URL]


@pytest.mark.asyncio
async def test_example_serves_page_and_protects_me(example_client):
    """The page is public; /api/v1/me needs a session."""
    client, _ = example_client
    response = await client.get("/")
    assert response.status == 200
    assert "Passkey example" in await response.text()
    assert (await client.get("/api/v1/me")).status == 401


@pytest.mark.asyncio
async def test_example_enroll_then_sign_in_with_passkey(example_client):
    """Password login → enroll → username-first and usernameless passkey logins → /api/v1/me."""
    client, example = example_client
    headers = await _password_login(client, example)
    me = await (await client.get("/api/v1/me", headers=headers)).json()
    assert me["username"] == "demo"
    assert me["auth_method"] != "passkey"

    soft, handle, credential_id = await _enroll(client, example, headers)
    listed = await (
        await client.get("/api/v1/auth/passkey/credentials", headers=headers)
    ).json()
    assert [(c["id"], c["label"], c["rp_id"]) for c in listed] == [
        (credential_id, "soft key", example.HOST)
    ]

    started, response = await _passkey_login(
        client, example, soft, handle, username="demo", sign_count=1
    )
    assert [c["id"] for c in started["publicKey"]["allowCredentials"]] == [
        credential_id
    ]
    assert response.status == 200
    body = await response.json()
    assert (body["auth_method"], body["mfa"], body["amr"]) == (
        "passkey",
        True,
        ["hwk", "user"],
    )

    started, response = await _passkey_login(
        client, example, soft, handle, sign_count=2
    )
    assert not started["publicKey"].get("allowCredentials")
    assert response.status == 200
    token = (await response.json())["token"]
    me = await (
        await client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    ).json()
    assert (me["username"], me["auth_method"], me["mfa"], me["amr"]) == (
        "demo",
        "passkey",
        True,
        ["hwk", "user"],
    )


@pytest.mark.asyncio
async def test_example_rejects_unknown_user_wrong_origin_and_replay(example_client):
    """Decoy ceremony, foreign origin and a reused challenge never open a session."""
    client, example = example_client
    headers = await _password_login(client, example)
    soft, handle, _ = await _enroll(client, example, headers)

    started, response = await _passkey_login(
        client, example, soft, handle, username="nobody"
    )
    assert started["publicKey"][
        "allowCredentials"
    ]  # decoy ids: same shape as a real account
    assert response.status == 401

    response = await client.post(
        "/api/v1/auth/passkey/login/options",
        json={},
        headers={"Origin": "http://evil.example"},
    )
    assert response.status == 401

    started, response = await _passkey_login(
        client, example, soft, handle, username="demo"
    )
    assert response.status == 200
    assertion = soft.make_assertion(
        example.HOST,
        example.BASE_URL,
        _b64_to_bytes(started["publicKey"]["challenge"]),
        sign_count=5,
        user_handle=handle,
    )
    replay = await client.post(
        "/api/v1/login",
        json={"challenge_id": started["challenge_id"], "credential": assertion},
        headers={"X-Auth-Method": "PasskeyAuth", "Origin": example.BASE_URL},
    )
    assert replay.status == 401


@pytest.mark.asyncio
async def test_example_rename_and_delete(example_client):
    """Rename and delete the enrolled passkey; a deleted passkey no longer signs in."""
    client, example = example_client
    headers = await _password_login(client, example)
    soft, handle, credential_id = await _enroll(client, example, headers)
    path = f"/api/v1/auth/passkey/credentials/{credential_id}"

    assert (
        await client.patch(path, json={"label": "renamed"}, headers=headers)
    ).status == 200
    listed = await (
        await client.get("/api/v1/auth/passkey/credentials", headers=headers)
    ).json()
    assert listed[0]["label"] == "renamed"

    assert (await client.delete(path, headers=headers)).status == 204
    assert (
        await (
            await client.get("/api/v1/auth/passkey/credentials", headers=headers)
        ).json()
        == []
    )
    _, response = await _passkey_login(client, example, soft, handle, username="demo")
    assert response.status == 401
