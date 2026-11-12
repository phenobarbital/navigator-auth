"""FEAT-106 review fixes — OAuth credential generation primitives.

The endpoint integration coverage lives in the OAuth provider suites.  These
tests retain the durable-wire-format contract for legacy OAuth artifacts.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import navigator_auth.conf as conf
from navigator_auth.backends.oauth2 import backend as oauth_backend
from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthAuthorizationCode,
    OauthRefreshToken,
    is_oauth_user_token,
)
from navigator_auth.security_state.store import GENERATION_CLAIM, generation_of, stamp_generation


def _client() -> OAuthClient:
    """Build the minimum OAuth client used by the carrier models."""
    return OAuthClient(
        client_id="generation-client",
        client_name="Generation test client",
        client_type="public",
        redirect_uris=["https://client.example/callback"],
    )


def test_is_oauth_user_token_shapes() -> None:
    """Generation checks apply only to OAuth access tokens minted for users."""
    assert is_oauth_user_token({"client_id": "client", "user_id": 7, "jti": "token"})
    assert not is_oauth_user_token({"user_id": 7, "jti": "basic-auth"})
    assert not is_oauth_user_token({"client_id": "client", "jti": "machine"})
    assert not is_oauth_user_token({})


def test_models_default_generation_zero_for_legacy_payloads() -> None:
    """OAuth carrier models deserialize legacy records without a generation."""
    client = _client()
    code = OauthAuthorizationCode(
        client=client,
        user_id=7,
        code="authorization-code",
        redirect_uri="https://client.example/callback",
        scope="default",
        state="state",
    )
    refresh = OauthRefreshToken(
        client=client,
        user_id=7,
        refresh_token="refresh-token",
        scope="default",
        expires_at=datetime.now() + timedelta(hours=1),
        absolute_expires_at=datetime.now() + timedelta(hours=2),
    )

    assert code.generation == 0
    assert refresh.generation == 0


def test_models_default_to_no_assurance_for_legacy_payloads() -> None:
    """Stored records without MFA fields remain readable after the schema change."""
    client = _client()
    refresh = OauthRefreshToken(
        client=client,
        user_id=7,
        refresh_token="refresh-token",
        scope="default",
        expires_at=datetime.now() + timedelta(hours=1),
        absolute_expires_at=datetime.now() + timedelta(hours=2),
    )
    legacy = {key: value for key, value in refresh.model_dump().items() if key not in ("mfa", "amr")}
    restored = OauthRefreshToken(**legacy)

    assert restored.mfa is False
    assert restored.amr is None


@pytest.fixture
def event_provider(monkeypatch):
    """Build a provider with a real event-validation method and isolated dependencies."""
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", True)
    provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    provider._load_auth_event = AsyncMock(
        return_value={"session_id": "session-1", "user_id": 7, "mfa": True, "amr": ["pwd", "totp"]}
    )
    monkeypatch.setattr(
        oauth_backend,
        "get_session",
        AsyncMock(
            return_value=SimpleNamespace(
                session_id="session-1",
                **{
                    "get": lambda key, default=None: {"user": '{"__dict__": {"user_id": 7, "username": "alice"}}'}.get(
                        key, default
                    )
                },
            )
        ),
    )
    return provider


@pytest.mark.asyncio
async def test_session_auth_context_returns_event_assurance(event_provider) -> None:
    """An event bound to the current session and user supplies the MFA carrier fields."""
    context = await event_provider._session_auth_context(MagicMock())

    assert context == {"mfa": True, "amr": ["pwd", "totp"]}


@pytest.mark.asyncio
async def test_session_auth_context_rejects_foreign_event(event_provider) -> None:
    """A foreign event cannot lend assurance to the current browser session."""
    event_provider._load_auth_event.return_value["session_id"] = "other-session"

    with pytest.raises(oauth_backend.InvalidAuth):
        await event_provider._session_auth_context(MagicMock())


@pytest.mark.asyncio
async def test_session_auth_context_missing_event_has_no_assurance(event_provider) -> None:
    """Sessions without an OAuth event remain usable without inheriting MFA claims."""
    event_provider._load_auth_event.return_value = None

    assert await event_provider._session_auth_context(MagicMock()) == {}


def test_generation_claim_is_absent_at_zero_and_present_after_increment() -> None:
    """Generation zero keeps historical JWT payload keys while positive values stamp ``gen``."""
    payload = {"user_id": 7, "client_id": "generation-client", "jti": "token"}

    assert GENERATION_CLAIM not in stamp_generation(dict(payload), 0)
    stamped = stamp_generation(dict(payload), 1)
    assert stamped[GENERATION_CLAIM] == 1
    assert generation_of(payload) == 0
    assert generation_of(stamped) == 1


# --- TASK-187: request-local bearer assurance for ABAC (M9, D9, AC27, AC29) ---
import copy  # noqa: E402
from types import MappingProxyType  # noqa: E402

from multidict import CIMultiDict  # noqa: E402
from yarl import URL  # noqa: E402

from navigator_auth.abac.context import (  # noqa: E402
    EvalContext,
    bearer_context_from_claims,
    effective_userinfo,
)
from navigator_auth.conf import (  # noqa: E402
    AUTH_BEARER_CONTEXT_KEY,
    AUTH_MECHANISM_BEARER,
    AUTH_MECHANISM_COOKIE,
    AUTH_MECHANISM_KEY,
)

_FRESH = {"otp", "totp", "backup"}


class _FakeRequest(dict):
    """Minimal request: a dict (``get``/item access) with the attributes EvalContext reads."""

    remote = "127.0.0.1"
    method = "GET"
    path = "/x"
    path_qs = "/x"
    rel_url = URL("/x")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = CIMultiDict()


def _fresh_factor(ctx) -> bool:
    """Same check as tests/test_mfa_e2e.py::requires_fresh_factor (that module needs a live DB)."""
    userinfo = ctx.userinfo if isinstance(ctx.userinfo, dict) else {}
    amr = set(userinfo.get("amr") or [])
    return bool(ctx.mfa) and "trusted_device" not in amr and bool(amr & _FRESH)


def _bearer(claims: dict) -> _FakeRequest:
    return _FakeRequest(
        {
            AUTH_MECHANISM_KEY: AUTH_MECHANISM_BEARER,
            AUTH_BEARER_CONTEXT_KEY: bearer_context_from_claims(claims),
        }
    )


def _session_userinfo() -> dict:
    # The shared, identity-keyed session carries a LATER TOTP login's assurance.
    return {"user_id": 7, "groups": ["g"], "mfa": True, "amr": ["pwd", "totp"], "auth_method": "basic"}


def _ctx(request, session_userinfo: dict):
    return EvalContext(request, session_userinfo, session_userinfo, {})


def test_bearer_context_is_immutable_and_strips_session_assurance() -> None:
    """Unit: the overlay drops session mfa/amr/auth_method and never mutates the session dict."""
    session_userinfo = _session_userinfo()
    request = _bearer({"user_id": 7})
    result = effective_userinfo(request, session_userinfo)
    assert "mfa" not in result and "amr" not in result and "auth_method" not in result
    assert result["groups"] == ["g"]
    assert result is not session_userinfo
    assert session_userinfo == _session_userinfo()
    assert isinstance(request[AUTH_BEARER_CONTEXT_KEY], MappingProxyType)
    with pytest.raises(TypeError):
        request[AUTH_BEARER_CONTEXT_KEY]["mfa"] = True

    cookie = _FakeRequest({AUTH_MECHANISM_KEY: AUTH_MECHANISM_COOKIE})
    assert effective_userinfo(cookie, session_userinfo) is session_userinfo
    no_ctx = _FakeRequest({AUTH_MECHANISM_KEY: AUTH_MECHANISM_BEARER})
    stripped = effective_userinfo(no_ctx, session_userinfo)
    assert "mfa" not in stripped and "amr" not in stripped
    assert session_userinfo == _session_userinfo()


def test_effective_userinfo_handles_object_and_none_records() -> None:
    """Records may be non-dict objects or missing; fields are read without assuming a dict."""
    request = _bearer({"user_id": 7, "mfa": True, "amr": ["pwd", "totp"]})
    obj = SimpleNamespace(user_id=7, groups=["g"], mfa=False, amr=["pwd"])
    result = effective_userinfo(request, obj)
    assert result["groups"] == ["g"] and result["mfa"] is True and result["amr"] == ["pwd", "totp"]
    assert effective_userinfo(request, None)["mfa"] is True
    # identity mismatch: no assurance lent across identities
    other = _bearer({"user_id": 8, "mfa": True, "amr": ["pwd", "totp"]})
    assert "mfa" not in effective_userinfo(other, _session_userinfo())


def test_abac_fresh_factor_grants_mfa_oauth2_token() -> None:
    """AC27: TOTP token -> fresh factor True; trusted-device and no-MFA tokens -> False."""
    session = _session_userinfo()
    snapshot = copy.deepcopy(session)
    totp = _ctx(_bearer({"user_id": 7, "mfa": True, "amr": ["pwd", "totp"]}), session)
    trusted = _ctx(_bearer({"user_id": 7, "mfa": True, "amr": ["pwd", "trusted_device"]}), session)
    plain = _ctx(_bearer({"user_id": 7}), session)
    assert totp.mfa is True and _fresh_factor(totp) is True
    assert trusted.mfa is True and _fresh_factor(trusted) is False
    assert plain.mfa is False and _fresh_factor(plain) is False
    assert session == snapshot


def test_cookie_requests_keep_session_assurance() -> None:
    """Cookie-only requests evaluate exactly as before: the session's assurance applies."""
    session = _session_userinfo()
    ctx = _ctx(_FakeRequest({AUTH_MECHANISM_KEY: AUTH_MECHANISM_COOKIE}), session)
    assert ctx.mfa is True and _fresh_factor(ctx) is True


def test_oauth_assurance_isolation() -> None:
    """AC29: password-only / trusted-device tokens stay denied while the shared session holds a TOTP
    login, in either mint order; the TOTP token stays granted; session recreation changes nothing."""
    session = _session_userinfo()
    claims = {
        "pwd": {"user_id": 7, "mfa": False, "amr": ["pwd"]},
        "trusted": {"user_id": 7, "mfa": True, "amr": ["pwd", "trusted_device"]},
        "totp": {"user_id": 7, "mfa": True, "amr": ["pwd", "totp"]},
    }
    for order in (("pwd", "trusted", "totp"), ("totp", "trusted", "pwd")):
        for name in order:
            ctx = _ctx(_bearer(claims[name]), session)
            assert _fresh_factor(ctx) is (name == "totp"), (order, name)
    # session recreated from the token carries no assurance at all: results are unchanged
    recreated = {"user_id": 7, "groups": ["g"]}
    for name, claim in claims.items():
        ctx = _ctx(_bearer(claim), recreated)
        assert _fresh_factor(ctx) is (name == "totp"), name
    assert session == _session_userinfo()
