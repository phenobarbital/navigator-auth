# ruff: noqa: F811
"""FEAT-101 TASK-93 — PasskeyAuth core (no Redis/DB)."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import ConfigError, InvalidAuth
from tests.fixtures.passkey import passkey_rp_config  # noqa: F401


@pytest.fixture
def backend(passkey_rp_config):
    from navigator_auth.backends.passkey import PasskeyAuth

    return PasskeyAuth(user_model=MagicMock(), identity=MagicMock())


class _Explode:
    def __getattr__(self, name):
        raise AssertionError(f"I/O attempted: {name}")


def _json_request(body: bytes, content_type="application/json"):
    req = make_mocked_request("POST", "/", headers={"Content-Type": content_type})
    req._read_bytes = body
    return req


def test_backends_import_without_webauthn():
    """AC2/R9: importing navigator_auth.backends works when webauthn is unimportable."""
    code = "import sys; sys.modules['webauthn'] = None; " "import navigator_auth.backends as b; assert b.PasskeyAuth"
    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": root}
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=root, env=env)
    assert res.returncode == 0, res.stderr[-500:]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body, ctype",
    [
        (b"", "application/json"),
        (b"not json", "application/json"),
        (b"[]", "application/json"),
        (b"{}", "application/json"),
        (b'{"challenge_id": "x"}', "application/json"),
        (b'{"credential": {"id": "x"}}', "application/json"),
        (b'{"challenge_id": 1, "credential": {"id": "x"}}', "application/json"),
        (b'{"challenge_id": "x", "credential": "str"}', "application/json"),
        (b'{"challenge_id": "x", "credential": {"id": "x"}}', "text/plain"),
    ],
)
async def test_get_payload_fast_fail(backend, body, ctype):
    """E11: missing assertion → InvalidAuth before any Redis/DB access."""
    backend._pool = _Explode()
    backend._store = _Explode()
    with pytest.raises(InvalidAuth) as exc:
        await backend.get_payload(_json_request(body, ctype))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_get_payload_ok(backend):
    cid, cred = await backend.get_payload(_json_request(b'{"challenge_id": "abc", "credential": {"id": "x"}}'))
    assert cid == "abc" and cred == {"id": "x"}


def test_decoy_ids_deterministic(backend, passkey_rp_config, monkeypatch):
    """Same RP + username → same ids (casefold); other RP → different ids; count = setting."""
    import navigator_auth.conf as conf
    from navigator_auth.passkey import RelyingParty

    a, b = (RelyingParty(**p) for p in passkey_rp_config)
    ids = backend._decoy_ids(a, "Bob")
    assert 1 <= len(ids) <= conf.PASSKEY_DECOY_CREDENTIALS
    assert ids == backend._decoy_ids(a, "bOB")
    assert ids != backend._decoy_ids(b, "Bob")
    assert ids != backend._decoy_ids(a, "alice")
    monkeypatch.setattr(conf, "PASSKEY_DECOY_CREDENTIALS", 4, raising=False)
    counts = {len(backend._decoy_ids(a, f"user{i}")) for i in range(40)}
    lengths = {len(x) for i in range(40) for x in backend._decoy_ids(a, f"user{i}")}
    assert counts <= {1, 2, 3, 4} and len(counts) > 1  # count varies per username
    assert lengths <= {16, 32, 64} and len(lengths) > 1  # id length varies like real ones
    assert backend._decoy_ids(a, "user7") == backend._decoy_ids(a, "USER7")  # still deterministic


def test_configure_registers_routes_and_exclude(backend):
    app = web.Application()
    app["auth_exclude_list"] = []
    from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY

    app[AUTH_EXCLUDE_LIST_KEY] = []
    backend.configure(app)
    paths = {r.resource.canonical for r in app.router.routes() if r.resource}
    assert "/api/v1/auth/passkey/register/options" in paths
    assert "/api/v1/auth/passkey/register/verify" in paths
    assert "/api/v1/auth/passkey/login/options" in paths
    excl = app[AUTH_EXCLUDE_LIST_KEY]
    assert "/api/v1/auth/passkey/login/options" in excl
    assert "/api/v1/auth/passkey/register/options" not in excl
    assert "/api/v1/auth/passkey/register/verify" not in excl


def test_configure_empty_rp_map_raises(monkeypatch):
    """AC1: an empty PASSKEY_RELYING_PARTIES → ConfigError at configure()."""
    import navigator_auth.conf as conf
    from navigator_auth.backends.passkey import PasskeyAuth

    monkeypatch.setattr(conf, "PASSKEY_RELYING_PARTIES", [], raising=False)
    be = PasskeyAuth(user_model=MagicMock(), identity=MagicMock())
    with pytest.raises(ConfigError):
        be.configure(web.Application())


@pytest.mark.asyncio
async def test_on_startup_without_webauthn_raises(backend, monkeypatch):
    """AC1: webauthn missing → ConfigError at on_startup."""
    monkeypatch.setitem(sys.modules, "webauthn", None)
    with pytest.raises(ConfigError):
        await backend.on_startup(web.Application())


# pre-existing: auth_error passes the deprecated `body=` to aiohttp HTTP errors
@pytest.mark.filterwarnings("ignore:body argument is deprecated:DeprecationWarning")
def test_session_user_requires_auth(backend):
    req = make_mocked_request("POST", "/")
    exc = backend._session_user  # raises an aiohttp HTTP error (Unauthorized RETURNS it)
    with pytest.raises(web.HTTPError):
        exc(req)


def test_configure_invalid_user_verification_raises(monkeypatch, passkey_rp_config):
    import navigator_auth.conf as conf
    from navigator_auth.backends.passkey import PasskeyAuth

    monkeypatch.setattr(conf, "PASSKEY_USER_VERIFICATION", "requierd", raising=False)
    be = PasskeyAuth(user_model=MagicMock(), identity=MagicMock())
    with pytest.raises(ConfigError):
        be.configure(web.Application())


def test_sign_count_regression_message_pinned():
    """authenticate() classifies regressions by py_webauthn's message; pin it to the library."""
    import os

    import webauthn
    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    from tests.fixtures.passkey import SoftAuthenticator

    auth = SoftAuthenticator()
    challenge = os.urandom(32)
    reg = webauthn.verify_registration_response(
        credential=auth.make_attestation("a.test", "https://a.test", challenge, b"h" * 32),
        expected_challenge=challenge, expected_rp_id="a.test", expected_origin="https://a.test",
    )
    challenge = os.urandom(32)
    with pytest.raises(InvalidAuthenticationResponse) as exc:
        webauthn.verify_authentication_response(
            credential=auth.make_assertion("a.test", "https://a.test", challenge, sign_count=3),
            expected_challenge=challenge, expected_rp_id="a.test", expected_origin="https://a.test",
            credential_public_key=reg.credential_public_key, credential_current_sign_count=5,
        )
    assert "sign count" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_rate_limit_disabled_and_enforced(backend, monkeypatch):
    import navigator_auth.conf as conf

    req = make_mocked_request("POST", "/")
    await backend._rate_limit(req)  # default 0 → no Redis access (pool unset)

    class _Redis:
        n = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def incr(self, key):
            _Redis.n += 1
            return _Redis.n

        async def expire(self, key, ttl):
            return True

    monkeypatch.setattr(conf, "PASSKEY_LOGIN_OPTIONS_RATE", 2, raising=False)
    monkeypatch.setattr("navigator_auth.backends.passkey.aioredis.Redis", lambda **kw: _Redis())
    backend._pool = object()
    await backend._rate_limit(req)
    await backend._rate_limit(req)
    from navigator_auth.exceptions import AuthException

    with pytest.raises(AuthException) as exc:
        await backend._rate_limit(req)
    assert exc.value.status == 429
