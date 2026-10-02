# ruff: noqa: F811
"""FEAT-101 TASK-94 — passkey enrollment, live (Postgres + Redis)."""

import pytest

from tests.fixtures.passkey import passkey_app, passkey_rp_config, soft_authenticator  # noqa: F401

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]

ORIGIN = {"Origin": "https://a.test"}
OPTS = "/api/v1/auth/passkey/register/options"
VERIFY = "/api/v1/auth/passkey/register/verify"


class _Anon:
    """Cookie-isolated client against the same server (does not own the server)."""

    def __init__(self, app):
        import aiohttp

        self._base = str(app.client.make_url("/")).rstrip("/")
        self._session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def start_server(self):
        return None

    def post(self, path, **kw):
        return self._session.post(self._base + path, **kw)

    async def close(self):
        await self._session.close()


async def _fresh_client(passkey_app):
    """A cookie-less client against the same server (no session)."""
    return _Anon(passkey_app)


async def test_register_requires_session(passkey_app):
    """E12: both register endpoints → 401/403 without a session."""
    anon = await _fresh_client(passkey_app)
    await anon.start_server()
    try:
        for path in (OPTS, VERIFY):
            resp = await anon.post(path, json={}, headers=ORIGIN)
            assert resp.status in (401, 403), (path, resp.status)
    finally:
        await anon.close()


async def test_register_cookie_session_requires_csrf():
    """Cookie-only session without X-CSRF-Token → 403 on the register routes (CSRF middleware).

    Cookie sessions are only honoured with ``secure_cookies=True`` (Secure cookie, not
    replayable over the plain-HTTP test server), so the middleware is exercised directly.
    """
    from unittest.mock import AsyncMock

    from aiohttp import web
    from aiohttp.test_utils import make_mocked_request

    import navigator_auth.middlewares.csrf as csrf

    if not csrf.ENABLE_CSRF_PROTECTION:
        pytest.skip("CSRF disabled")
    for path in (OPTS, VERIFY):
        request = make_mocked_request("POST", path, headers=ORIGIN)
        request["authenticated"] = True
        handler = AsyncMock()
        with pytest.raises(web.HTTPForbidden):
            await csrf.csrf_middleware(request, handler)
        handler.assert_not_awaited()
    # Bearer-authenticated requests skip CSRF
    request = make_mocked_request("POST", OPTS, headers={**ORIGIN, "Authorization": "Bearer x"})
    request["authenticated"] = True
    handler = AsyncMock(return_value=web.Response())
    await csrf.csrf_middleware(request, handler)
    handler.assert_awaited_once()


async def test_register_roundtrip(passkey_app, soft_authenticator):
    """Options use the random handle (≠ user_id) and excludeCredentials; verify → 201 and the
    stored row carries rp_id (C3, E10, E15)."""
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    c, h = passkey_app.client, {**passkey_app.headers, **ORIGIN}
    resp = await c.post(OPTS, json={}, headers=h)
    assert resp.status == 200, await resp.text()
    opts = await resp.json()
    handle = base64url_to_bytes(opts["user"]["id"])
    assert len(handle) == 32 and handle != str(passkey_app.user_id).encode()
    assert opts["rp"]["id"] == "a.test"
    assert opts["authenticatorSelection"]["residentKey"] == "required"
    assert opts["excludeCredentials"] == []
    assert opts["attestation"] == "none"

    challenge = base64url_to_bytes(opts["challenge"])
    cred = soft_authenticator.make_attestation("a.test", "https://a.test", challenge, handle)
    resp = await c.post(VERIFY, json={"credential": cred, "label": "Laptop"}, headers=h)
    assert resp.status == 201, await resp.text()
    body = await resp.json()
    assert body == {"status": "registered", "id": bytes_to_base64url(soft_authenticator.credential_id)}

    stored = await passkey_app.backend._store.get_credential(soft_authenticator.credential_id)
    assert stored.rp_id == "a.test" and stored.user_id == passkey_app.user_id
    assert stored.label == "Laptop" and stored.transports == ["internal"]

    # challenge is single use (E1)
    resp = await c.post(VERIFY, json={"credential": cred}, headers=h)
    assert resp.status == 401

    # the next options call excludes the enrolled credential (E10) and reuses the handle
    resp = await c.post(OPTS, json={}, headers=h)
    opts2 = await resp.json()
    assert [e["id"] for e in opts2["excludeCredentials"]] == [bytes_to_base64url(soft_authenticator.credential_id)]
    assert opts2["user"]["id"] == opts["user"]["id"]

    # re-enrolling the same authenticator → 409
    cred2 = soft_authenticator.make_attestation(
        "a.test", "https://a.test", base64url_to_bytes(opts2["challenge"]), handle
    )
    resp = await c.post(VERIFY, json={"credential": cred2}, headers=h)
    assert resp.status == 409, await resp.text()
    await passkey_app.backend._store.delete_credential(passkey_app.user_id, soft_authenticator.credential_id)


async def test_register_verify_rejects_bad_attestation_and_wrong_origin(passkey_app, soft_authenticator):
    from webauthn.helpers import base64url_to_bytes

    c, h = passkey_app.client, {**passkey_app.headers, **ORIGIN}
    opts = await (await c.post(OPTS, json={}, headers=h)).json()
    challenge = base64url_to_bytes(opts["challenge"])
    handle = base64url_to_bytes(opts["user"]["id"])
    # attestation made for another origin → 400
    cred = soft_authenticator.make_attestation("a.test", "https://evil.test", challenge, handle)
    resp = await c.post(VERIFY, json={"credential": cred}, headers=h)
    assert resp.status == 400
    # the failed attempt burned the challenge
    good = soft_authenticator.make_attestation("a.test", "https://a.test", challenge, handle)
    resp = await c.post(VERIFY, json={"credential": good}, headers=h)
    assert resp.status == 401
    # origin not on the allow-list → 401
    resp = await c.post(OPTS, json={}, headers={**passkey_app.headers, "Origin": "https://evil.test"})
    assert resp.status == 401
    # label too long → 400
    opts = await (await c.post(OPTS, json={}, headers=h)).json()
    cred = soft_authenticator.make_attestation(
        "a.test", "https://a.test", base64url_to_bytes(opts["challenge"]), handle
    )
    resp = await c.post(VERIFY, json={"credential": cred, "label": "x" * 129}, headers=h)
    assert resp.status == 400
