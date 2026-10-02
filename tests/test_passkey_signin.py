# ruff: noqa: F811
"""FEAT-101 TASK-95 — passkey sign-in, live (Postgres + Redis)."""

import logging
from types import SimpleNamespace

import jwt
import pytest
import pytest_asyncio

from navigator_auth.exceptions import InvalidAuth
from tests.fixtures.passkey import (
    PASSKEY_TEST_PASSWORD,
    _make_password,
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

A = {"Origin": "https://a.test"}
B = {"Origin": "https://b.test"}
REG_OPTS = "/api/v1/auth/passkey/register/options"
REG_VERIFY = "/api/v1/auth/passkey/register/verify"
LOGIN_OPTS = "/api/v1/auth/passkey/login/options"
LOGIN = "/api/v1/login"
PK = {"X-Auth-Method": "PasskeyAuth"}


def _b2b(value):
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(value)


async def _enroll(app, auth, origin="https://a.test", rp_id="a.test", headers=None, uv=True):
    """Enroll ``auth`` through the real register endpoints; returns the user handle."""
    h = {**(headers or app.headers), "Origin": origin}
    opts = await (await app.client.post(REG_OPTS, json={}, headers=h)).json()
    handle = _b2b(opts["user"]["id"])
    cred = auth.make_attestation(rp_id, origin, _b2b(opts["challenge"]), handle, uv=uv)
    resp = await app.client.post(REG_VERIFY, json={"credential": cred}, headers=h)
    assert resp.status == 201, await resp.text()
    return handle


async def _options(app, origin="https://a.test", username=None):
    body = {"username": username} if username is not None else {}
    resp = await app.client.post(LOGIN_OPTS, json=body, headers={"Origin": origin})
    assert resp.status == 200, await resp.text()
    return await resp.json()


async def _login(
    app,
    auth,
    opts,
    *,
    origin="https://a.test",
    rp_id="a.test",
    sign_count=1,
    uv=True,
    user_handle=None,
    cdj_origin=None,
    client=None,
):
    cred = auth.make_assertion(
        rp_id,
        cdj_origin or origin,
        _b2b(opts["publicKey"]["challenge"]),
        sign_count=sign_count,
        uv=uv,
        user_handle=user_handle,
    )
    return await (client or app.client).post(
        LOGIN,
        json={"challenge_id": opts["challenge_id"], "credential": cred},
        headers={**PK, "Origin": origin},
    )


@pytest_asyncio.fixture(autouse=True, loop_scope="module")
async def _clean(passkey_app):
    yield
    async with await passkey_app.db_pool.acquire() as conn:
        await conn.execute(f"DELETE FROM auth.user_credentials WHERE user_id = {passkey_app.user_id}")


async def _second_user(app):
    name = "test_passkey_user2"
    async with await app.db_pool.acquire() as conn:
        await conn.execute(f"DELETE FROM auth.users WHERE username = '{name}'")
        await conn.execute(
            "INSERT INTO auth.users (username, password, email, first_name, last_name, "
            "is_active, is_superuser, is_new, is_staff) VALUES "
            f"('{name}', '{_make_password(PASSKEY_TEST_PASSWORD)}', 'pk2@example.com', "
            "'Two', 'Key', true, false, false, false)"
        )
    resp = await app.client.post(
        LOGIN,
        json={"username": name, "password": PASSKEY_TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    data = await resp.json()
    return data["user_id"], {"Authorization": f"Bearer {data['token']}"}, name


async def _drop_user(app, name):
    async with await app.db_pool.acquire() as conn:
        await conn.execute(f"DELETE FROM auth.users WHERE username = '{name}'")


async def test_login_usernameless_success(passkey_app, soft_authenticator):
    """C4, AC6: body + JWT mfa/amr/jti/auth_method + session cookie."""
    from navigator_auth.conf import AUTH_JWT_ALGORITHM, SECRET_KEY

    handle = await _enroll(passkey_app, soft_authenticator)
    opts = await _options(passkey_app)
    assert opts["publicKey"]["allowCredentials"] == []
    resp = await _login(passkey_app, soft_authenticator, opts, user_handle=handle)
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    for key in ("token", "refresh_token", "username", "user_id", "expires_in", "token_type"):
        assert key in data, key
    assert data["auth_method"] == "passkey" and data["mfa"] is True
    assert data["amr"] == ["hwk", "user"]
    claims = jwt.decode(data["token"], SECRET_KEY, algorithms=[AUTH_JWT_ALGORITHM])
    assert claims["auth_method"] == "passkey" and claims["mfa"] is True
    assert claims["amr"] == ["hwk", "user"] and claims.get("jti")
    # Cookie parity with BasicAuth (the session is created by the shared open_session)
    basic = await passkey_app.client.post(
        LOGIN,
        json={"username": passkey_app.username, "password": PASSKEY_TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert set(resp.cookies) == set(basic.cookies)
    stored = await passkey_app.backend._store.get_credential(soft_authenticator.credential_id)
    assert stored.sign_count == 1 and stored.last_used_at is not None


async def test_login_username_first_known(passkey_app, soft_authenticator):
    """Known user: allowCredentials lists their credentials; another user's credential → 401."""
    from tests.fixtures.passkey import SoftAuthenticator

    await _enroll(passkey_app, soft_authenticator)
    opts = await _options(passkey_app, username=passkey_app.username)
    allow = opts["publicKey"]["allowCredentials"]
    assert [_b2b(a["id"]) for a in allow] == [soft_authenticator.credential_id]
    resp = await _login(passkey_app, soft_authenticator, opts)
    assert resp.status == 200, await resp.text()

    uid2, h2, name2 = await _second_user(passkey_app)
    try:
        other = SoftAuthenticator()
        await _enroll(passkey_app, other, headers=h2)
        opts = await _options(passkey_app, username=passkey_app.username)
        resp = await _login(passkey_app, other, opts)
        assert resp.status == 401, await resp.text()
    finally:
        await _drop_user(passkey_app, name2)


async def test_login_username_first_unknown_shape(passkey_app, soft_authenticator):
    """E5, AC7: unknown user gets the same shape (decoy ids); deterministic; login fails."""
    import navigator_auth.conf as conf

    await _enroll(passkey_app, soft_authenticator)
    known = await _options(passkey_app, username=passkey_app.username)
    unknown = await _options(passkey_app, username="nobody_such_user")
    again = await _options(passkey_app, username="NOBODY_such_user")
    assert set(known) == set(unknown)
    assert set(known["publicKey"]) == set(unknown["publicKey"])
    assert 1 <= len(unknown["publicKey"]["allowCredentials"]) <= conf.PASSKEY_DECOY_CREDENTIALS
    assert unknown["publicKey"]["allowCredentials"] == again["publicKey"]["allowCredentials"]
    resp = await _login(passkey_app, soft_authenticator, unknown)
    assert resp.status == 401


async def test_challenge_replay(passkey_app, soft_authenticator):
    """E1: a challenge is single use."""
    await _enroll(passkey_app, soft_authenticator)
    opts = await _options(passkey_app)
    assert (await _login(passkey_app, soft_authenticator, opts, sign_count=1)).status == 200
    resp = await _login(passkey_app, soft_authenticator, opts, sign_count=2)
    assert resp.status == 401


async def test_challenge_expired(passkey_app, soft_authenticator):
    """E2: an expired (deleted) challenge → 401."""
    import redis.asyncio as aioredis

    await _enroll(passkey_app, soft_authenticator)
    opts = await _options(passkey_app)
    async with aioredis.Redis(connection_pool=passkey_app.backend._pool) as r:
        assert await r.delete(f"passkey_login_{opts['challenge_id']}") == 1
    assert (await _login(passkey_app, soft_authenticator, opts)).status == 401
    # and a missing challenge_id → 401 fast
    resp = await passkey_app.client.post(
        LOGIN, json={"challenge_id": "nope", "credential": {"id": "x"}}, headers={**PK, **A}
    )
    assert resp.status == 401


async def test_origin_mismatch(passkey_app, soft_authenticator):
    """E3: clientDataJSON origin / other RP's credential must fail."""
    await _enroll(passkey_app, soft_authenticator)
    opts = await _options(passkey_app)
    resp = await _login(passkey_app, soft_authenticator, opts, cdj_origin="https://evil.test")
    assert resp.status == 401
    # credential enrolled for a.test cannot be used in a ceremony started on b.test (AC4)
    opts_b = await _options(passkey_app, origin="https://b.test")
    resp = await _login(passkey_app, soft_authenticator, opts_b, origin="https://b.test", rp_id="b.test")
    assert resp.status == 401
    # origin not on the allow-list
    resp = await passkey_app.client.post(LOGIN_OPTS, json={}, headers={"Origin": "https://evil.test"})
    assert resp.status == 401


async def test_unknown_credential_uniform_401(passkey_app, soft_authenticator):
    """E4: unknown credential and bad signature are indistinguishable."""
    from tests.fixtures.passkey import SoftAuthenticator

    await _enroll(passkey_app, soft_authenticator)
    opts = await _options(passkey_app)
    unknown = await _login(passkey_app, SoftAuthenticator(), opts)
    opts = await _options(passkey_app)
    forged = SoftAuthenticator()
    forged.credential_id = soft_authenticator.credential_id  # right id, wrong key
    bad_sig = await _login(passkey_app, forged, opts)
    assert unknown.status == bad_sig.status == 401
    assert await unknown.text() == await bad_sig.text()


async def test_sign_count_zero_accepted(passkey_app, soft_authenticator):
    """E6: authenticators that always report 0 are accepted."""
    await _enroll(passkey_app, soft_authenticator)
    for _ in range(2):
        opts = await _options(passkey_app)
        resp = await _login(passkey_app, soft_authenticator, opts, sign_count=0)
        assert resp.status == 200, await resp.text()


async def test_sign_count_regression_rejected_logged(passkey_app, soft_authenticator, caplog):
    """E7, Q4: regression → 401 + warning with the credential id; credential still usable."""
    from webauthn.helpers import bytes_to_base64url

    await _enroll(passkey_app, soft_authenticator)
    assert (await _login(passkey_app, soft_authenticator, await _options(passkey_app), sign_count=5)).status == 200
    with caplog.at_level(logging.WARNING):
        resp = await _login(passkey_app, soft_authenticator, await _options(passkey_app), sign_count=3)
    assert resp.status == 401
    cid = bytes_to_base64url(soft_authenticator.credential_id)
    assert any(cid in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)
    # Q4: not disabled
    assert (await _login(passkey_app, soft_authenticator, await _options(passkey_app), sign_count=6)).status == 200


async def test_uv_required(passkey_app, soft_authenticator):
    """E8: with UV required, an assertion without UV is rejected."""
    await _enroll(passkey_app, soft_authenticator)
    resp = await _login(passkey_app, soft_authenticator, await _options(passkey_app), uv=False)
    assert resp.status == 401


async def test_inactive_user_rejected(passkey_app, soft_authenticator):
    """E9: disabled account → 403 and no session."""
    await _enroll(passkey_app, soft_authenticator)
    async with await passkey_app.db_pool.acquire() as conn:
        await conn.execute(f"UPDATE auth.users SET is_active = false WHERE user_id = {passkey_app.user_id}")
    try:
        resp = await _login(passkey_app, soft_authenticator, await _options(passkey_app))
        assert resp.status == 403, await resp.text()
        assert "token" not in (await resp.text())
        # a rejected (disabled) account must not touch the credential
        stored = await passkey_app.backend._store.get_credential(soft_authenticator.credential_id)
        assert stored.sign_count == 0 and stored.last_used_at is None
    finally:
        async with await passkey_app.db_pool.acquire() as conn:
            await conn.execute(f"UPDATE auth.users SET is_active = true WHERE user_id = {passkey_app.user_id}")


async def test_user_handle_mismatch(passkey_app, soft_authenticator):
    """A userHandle that is not the stored one → 401."""
    handle = await _enroll(passkey_app, soft_authenticator)
    resp = await _login(passkey_app, soft_authenticator, await _options(passkey_app), user_handle=b"x" * 32)
    assert resp.status == 401
    resp = await _login(passkey_app, soft_authenticator, await _options(passkey_app), user_handle=handle, sign_count=2)
    assert resp.status == 200


async def test_tenant_attribute_check(passkey_app, soft_authenticator, monkeypatch):
    """AC10: PASSKEY_TENANT_ATTRIBUTE mismatch → 401; absent attribute → skipped."""
    import navigator_auth.conf as conf

    backend = passkey_app.backend
    rp = backend._resolver.by_rp_id("a.test")
    monkeypatch.setattr(conf, "PASSKEY_TENANT_ATTRIBUTE", "org_id", raising=False)
    backend._check_tenant(SimpleNamespace(org_id=5), rp)  # match
    backend._check_tenant(SimpleNamespace(org_id="5"), rp)  # str/int tolerant
    backend._check_tenant(SimpleNamespace(), rp)  # attribute absent → skip
    with pytest.raises(InvalidAuth):
        backend._check_tenant(SimpleNamespace(org_id=7), rp)
    monkeypatch.setattr(conf, "PASSKEY_TENANT_ATTRIBUTE", None, raising=False)
    backend._check_tenant(SimpleNamespace(org_id=7), rp)  # disabled
    # end-to-end: user.first_name ("Pass") != rp.org_id → 401
    await _enroll(passkey_app, soft_authenticator)
    monkeypatch.setattr(conf, "PASSKEY_TENANT_ATTRIBUTE", "first_name", raising=False)
    resp = await _login(passkey_app, soft_authenticator, await _options(passkey_app))
    assert resp.status == 401


async def test_session_carries_tenant(passkey_app, soft_authenticator):
    """AC10: the session/body carry the RP's org_id/client_id (and EvalContext resolves them)."""
    await _enroll(passkey_app, soft_authenticator, origin="https://b.test", rp_id="b.test")
    opts = await _options(passkey_app, origin="https://b.test")
    resp = await _login(passkey_app, soft_authenticator, opts, origin="https://b.test", rp_id="b.test")
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    assert data["org_id"] == 7 and data["client_id"] == 2 and data["passkey_rp_id"] == "b.test"

    from unittest.mock import MagicMock

    from navigator_auth.abac.context import EvalContext

    ctx = EvalContext(MagicMock(), None, data, {})
    assert ctx.store["auth_method"] == "passkey" and ctx.store["mfa"] is True


async def test_fallback_loop_unaffected(passkey_app):
    """E11: header-less api_login still works with PasskeyAuth enabled; failures are 4xx."""
    from aiohttp import ClientSession, CookieJar

    base = str(passkey_app.client.make_url("/")).rstrip("/")
    async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
        resp = await s.post(
            base + LOGIN,
            json={"username": passkey_app.username, "password": PASSKEY_TEST_PASSWORD},
        )
        assert resp.status == 200, await resp.text()
        resp = await s.post(base + LOGIN, json={"username": passkey_app.username, "password": "wrong-password"})
        assert 400 <= resp.status < 500, resp.status
