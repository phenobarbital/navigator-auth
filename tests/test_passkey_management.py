# ruff: noqa: F811
"""FEAT-101 TASK-96 — passkey credential management, live (Postgres + Redis)."""

import pytest

from tests.fixtures.passkey import (
    PASSKEY_TEST_PASSWORD,
    _make_password,
    SoftAuthenticator,
    passkey_app,  # noqa: F401
    passkey_rp_config,  # noqa: F401
    soft_authenticator,  # noqa: F401
)

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]

ORIGIN = "https://a.test"
BASE = "/api/v1/auth/passkey"


def _b2b(value):
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(value)


async def _enroll(app, auth, headers, label=None):
    h = {**headers, "Origin": ORIGIN}
    opts = await (await app.client.post(f"{BASE}/register/options", json={}, headers=h)).json()
    cred = auth.make_attestation("a.test", ORIGIN, _b2b(opts["challenge"]), _b2b(opts["user"]["id"]))
    body = {"credential": cred}
    if label:
        body["label"] = label
    resp = await app.client.post(f"{BASE}/register/verify", json=body, headers=h)
    assert resp.status == 201, await resp.text()
    return (await resp.json())["id"]


async def _cleanup(app, user_id):
    async with await app.db_pool.acquire() as conn:
        await conn.execute(f"DELETE FROM auth.user_credentials WHERE user_id = {user_id}")


async def test_manage_list_rename_delete(passkey_app, soft_authenticator):
    """List (no key material), rename (400/404/200), delete (404, 204)."""
    app, h = passkey_app, passkey_app.headers
    try:
        id1 = await _enroll(app, soft_authenticator, h, label="Laptop")
        other = SoftAuthenticator()
        id2 = await _enroll(app, other, h)

        resp = await app.client.get(f"{BASE}/credentials", headers=h)
        assert resp.status == 200
        rows = await resp.json()
        assert {r["id"] for r in rows} == {id1, id2}
        for r in rows:
            assert set(r) == {"id", "label", "created_at", "last_used_at", "device_type", "backed_up", "rp_id"}
            assert r["rp_id"] == "a.test"
        assert next(r for r in rows if r["id"] == id1)["label"] == "Laptop"

        # rename
        url = f"{BASE}/credentials/{id1}"
        for bad in ({}, {"label": ""}, {"label": "   "}, {"label": "x" * 129}, {"label": 5}):
            assert (await app.client.patch(url, json=bad, headers=h)).status == 400
        resp = await app.client.patch(url, json={"label": "  Phone  "}, headers=h)
        assert resp.status == 200 and await resp.json() == {"status": "renamed"}
        rows = await (await app.client.get(f"{BASE}/credentials", headers=h)).json()
        assert next(r for r in rows if r["id"] == id1)["label"] == "Phone"
        unknown = "AAAA"
        assert (await app.client.patch(f"{BASE}/credentials/{unknown}", json={"label": "x"}, headers=h)).status == 404
        assert (await app.client.patch(f"{BASE}/credentials/!!!", json={"label": "x"}, headers=h)).status == 404

        # delete
        assert (await app.client.delete(f"{BASE}/credentials/{unknown}", headers=h)).status == 404
        assert (await app.client.delete(url, headers=h)).status == 204
        # the user has a password → deleting the last one is allowed
        assert (await app.client.delete(f"{BASE}/credentials/{id2}", headers=h)).status == 204
        assert await (await app.client.get(f"{BASE}/credentials", headers=h)).json() == []
    finally:
        await _cleanup(app, app.user_id)


async def test_manage_requires_session(passkey_app):
    import aiohttp

    base = str(passkey_app.client.make_url("/")).rstrip("/")
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        for method, path in (
            ("GET", f"{BASE}/credentials"),
            ("PATCH", f"{BASE}/credentials/AAAA"),
            ("DELETE", f"{BASE}/credentials/AAAA"),
        ):
            resp = await s.request(method, base + path, json={"label": "x"}, headers={"Origin": ORIGIN})
            assert resp.status in (401, 403), (method, resp.status)


async def test_cannot_delete_last_login_method(passkey_app):
    """E13: no password and no linked identity → 409; a foreign credential → 404."""
    app = passkey_app
    name = "test_passkey_nopass"
    async with await app.db_pool.acquire() as conn:
        await conn.execute(f"DELETE FROM auth.users WHERE username = '{name}'")
        await conn.execute(
            "INSERT INTO auth.users (username, password, email, first_name, last_name, "
            "is_active, is_superuser, is_new, is_staff) VALUES "
            f"('{name}', '{_make_password(PASSKEY_TEST_PASSWORD)}', 'nopass@example.com', "
            "'No', 'Pass', true, false, false, false)"
        )
    resp = await app.client.post(
        "/api/v1/login",
        json={"username": name, "password": PASSKEY_TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    data = await resp.json()
    uid = data["user_id"]
    h = {"Authorization": f"Bearer {data['token']}"}
    # the account then loses its password (passkey-only)
    async with await app.db_pool.acquire() as conn:
        await conn.execute(f"UPDATE auth.users SET password = '' WHERE user_id = {uid}")
    try:
        auth = SoftAuthenticator()
        cid = await _enroll(app, auth, h)
        # another user's credential is invisible → 404
        foreign = await _enroll(app, SoftAuthenticator(), app.headers)
        assert (await app.client.delete(f"{BASE}/credentials/{foreign}", headers=h)).status == 404
        resp = await app.client.delete(f"{BASE}/credentials/{cid}", headers=h)
        assert resp.status == 409, await resp.text()
        assert len(await app.backend._store.list_credentials(uid)) == 1
    finally:
        await _cleanup(app, uid)
        await _cleanup(app, app.user_id)
        async with await app.db_pool.acquire() as conn:
            await conn.execute(f"DELETE FROM auth.users WHERE username = '{name}'")
