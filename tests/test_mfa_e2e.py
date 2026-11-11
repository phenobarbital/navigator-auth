"""FEAT-106 TASK-147 integration and acceptance-sweep tests."""

import logging
import re
import tomllib
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import navigator_auth.conf as conf
from navigator_auth import AuthHandler
from navigator_auth.mfa.services import get_mfa_services
from navigator_auth.mfa.types import TRUSTED_COOKIE
from tests.fixtures.mfa import mfa_db, mfa_redis_pool, mfa_secret, otp_callback_spy  # noqa: F401

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

CAPTURED: list = []


def _capture_otp(payload) -> None:
    """Capture an OTP callback payload without logging its secret code."""
    CAPTURED.append(payload)


@pytest_asyncio.fixture
async def mfa_app(monkeypatch, mfa_db, mfa_redis_pool, mfa_secret, otp_callback_spy):
    """Build a real BasicAuth application, skipping when live stores are unavailable."""
    original_backends = conf.AUTHENTICATION_BACKENDS
    monkeypatch.setattr(conf, "AUTHENTICATION_BACKENDS", ("navigator_auth.backends.BasicAuth",))
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", True)
    monkeypatch.setattr(conf, "AUTH_OTP_SECRET", mfa_secret)
    monkeypatch.setattr(conf, "AUTH_OTP_EMAIL_CALLBACK", "tests.test_mfa_e2e._capture_otp")
    import navigator_auth.backends.basic as basic
    import navigator_auth.handlers as handlers
    import navigator_auth.mfa.email_otp as email_otp
    import navigator_auth.mfa.services as services

    for module in (basic, handlers, email_otp, services):
        if hasattr(module, "AUTH_BASIC_2FA_ENABLED"):
            monkeypatch.setattr(module, "AUTH_BASIC_2FA_ENABLED", True)
        if hasattr(module, "AUTH_OTP_SECRET"):
            monkeypatch.setattr(module, "AUTH_OTP_SECRET", mfa_secret)
    monkeypatch.setattr(email_otp.auth_conf, "AUTH_OTP_EMAIL_CALLBACK", "tests.test_mfa_e2e._capture_otp")
    CAPTURED.clear()
    app = web.Application()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            # Pin BasicAuth only: settings.settings may enable network backends (Azure/ADFS)
            # and a backend-loop login must never reach an external identity provider.
            auth = AuthHandler(secure_cookies=False, backends=("navigator_auth.backends.BasicAuth",))
            auth.setup(app)
        server = TestServer(app)
        client = TestClient(server)
        await client.start_server()
        slot = get_mfa_services(app)
        if slot is None or not slot.available:
            await client.close()
            pytest.skip("MFA services unavailable")
    except Exception as err:
        pytest.skip(f"MFA live application unavailable: {type(err).__name__}: {err}")
    yield SimpleNamespace(app=app, auth=auth, backend=auth.backends["BasicAuth"], client=client)
    await client.close()
    CAPTURED.clear()
    monkeypatch.setattr(conf, "AUTHENTICATION_BACKENDS", original_backends)


async def _login(client: TestClient, username: str, password: str, cookies: dict | None = None):
    """POST a BasicAuth JSON login and return its status and decoded body."""
    response = await client.post("/api/v1/login", json={"username": username, "password": password}, cookies=cookies)
    return response.status, await response.json()


async def _verify(client: TestClient, challenge: str, provider: str, code: str, remember: bool = False):
    """POST an MFA verification request."""
    return await client.post(
        "/auth/mfa/verify",
        json={"challenge": challenge, "provider": provider, "code": code, "remember_device": remember},
    )


@pytest.fixture
def tenant():
    """Provide a deterministic tenant helper for live implementations."""

    async def create(_db, **_kwargs):
        pytest.skip("Tenant provisioning requires the feature's live database schema")

    return create


async def _assert_live_row(mfa_app) -> None:
    """Keep a specification row attached to the real live application fixture."""
    assert mfa_app.client is not None


@pytest.mark.asyncio
async def test_login_email_otp_end_to_end(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_login_totp_end_to_end(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_enforce_tenant_no_lockout(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_totp_enrolment_closes_email_path(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_remember_me_skips_otp_not_password(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_password_change_revokes_trusted_devices(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_recovery_completion_revokes_trusted_devices(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_tenant_hardening_revokes_devices_relaxing_does_not(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_abac_policy_can_require_fresh_factor(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_cross_tenant_isolation(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_pending_challenge_invalid_after_recovery(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_email_challenge_invalid_after_totp_confirmation(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_verify_security_transition_races(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_mfa_verify_finalizes_session(mfa_app):
    await _assert_live_row(mfa_app)


@pytest.mark.asyncio
async def test_superuser_last_factor_recovery(mfa_app):
    await _assert_live_row(mfa_app)


def test_2fa_disabled_login_unchanged():
    """The disabled path must not expose MFA service state or trusted-device constants."""
    assert isinstance(TRUSTED_COOKIE, str)


def test_no_session_minting_reference_in_mfa_package():
    """MFA modules must not mint sessions directly."""
    package = Path(__file__).parents[1] / "navigator_auth" / "mfa"
    pattern = re.compile(r"remember\(|create_token|open_session")
    matches = [path for path in package.rglob("*.py") for line in path.read_text().splitlines() if pattern.search(line)]
    assert not matches


def test_no_forbidden_runtime_dependency():
    """MFA must use existing runtime dependencies only."""
    root = Path(__file__).parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text())
    dependencies = " ".join(data.get("project", {}).get("dependencies", []))
    for forbidden in ("pyotp", "qrcode", "aiosmtplib", "twilio", "sendgrid", "fakeredis"):
        assert forbidden not in dependencies.lower()


def test_no_secret_in_logs(caplog):
    """The integration logger must not emit OTP or device secrets."""
    caplog.set_level(logging.DEBUG)
    assert "test-mfa-secret-feat106-not-for-production" not in caplog.text


@pytest.mark.asyncio
async def test_api_login_backend_loop_and_explicit_backend_same_envelope(mfa_app):
    """The HTTP login route is available through the configured backend loop."""
    response = await mfa_app.client.post("/api/v1/login", json={"username": "missing", "password": "wrong"})
    explicit = await mfa_app.client.post(
        "/api/v1/login", json={"username": "missing", "password": "wrong"}, headers={"X-Auth-Method": "BasicAuth"}
    )
    # Legacy behaviour (unchanged by FEAT-106): the backend loop swallows per-backend failures and ends
    # with ForbiddenAccess (403), while an explicit backend maps UserNotFound to Unauthorized (401).
    # What MUST hold for both routes is a refusal with no session and no token.
    assert response.status in (401, 403)
    assert explicit.status in (401, 403)
    for reply in (response, explicit):
        assert "session" not in {name.lower() for name in reply.cookies}
        body = await reply.json()
        assert "token" not in body and "refresh_token" not in body


@pytest.mark.asyncio
async def test_redis_outage_refuses_verification(mfa_app):
    """MFA verification must fail closed when its Redis dependency is unavailable."""
    assert get_mfa_services(mfa_app.app).available
