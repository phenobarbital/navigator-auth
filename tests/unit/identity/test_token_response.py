"""Unit tests for navigator_auth.identity.types.TokenResponse."""
import base64
import json
from datetime import datetime, timedelta, timezone

from navigator_auth.identity.types import (
    TokenResponse,
    jwt_issued_at,
    mask_value,
)


def _jwt(**claims) -> str:
    """A compact JWT whose payload carries *claims* (signature not used)."""
    def _part(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_part({'alg': 'RS256'})}.{_part(claims)}.sig"


class TestTokenResponse:
    def test_expires_at_computed_from_expires_in(self):
        token = TokenResponse(access_token="abc", expires_in=3600)
        assert token.expires_at is not None
        assert token.expires_at.tzinfo is not None
        remaining = token.expires_at - datetime.now(timezone.utc)
        assert timedelta(seconds=3590) < remaining <= timedelta(seconds=3600)

    def test_no_expiry_when_not_reported(self):
        token = TokenResponse(access_token="abc")
        assert token.expires_at is None
        assert token.is_expiring() is False

    def test_is_expiring_with_leeway(self):
        token = TokenResponse(access_token="abc", expires_in=60)
        assert token.is_expiring(leeway=0) is False
        assert token.is_expiring(leeway=120) is True

    def test_expired_token(self):
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        token = TokenResponse(access_token="abc", expires_at=past)
        assert token.is_expiring() is True

    def test_credential_shape_and_no_raw(self):
        token = TokenResponse(
            access_token="at",
            refresh_token="rt",
            expires_in=100,
            scopes=["email"],
            provider_user_id="u-1",
            raw={"access_token": "at", "extra": "never-cached"},
        )
        cred = token.credential()
        assert set(cred) == {
            "access_token",
            "token_type",
            "refresh_token",
            "id_token",
            "expires_at",
            "scopes",
            "provider_user_id",
        }
        assert "raw" not in cred
        assert cred["refresh_token"] == "rt"

    def test_credential_roundtrip(self):
        token = TokenResponse(
            access_token="at", refresh_token="rt", expires_in=100,
            scopes=["a", "b"], provider_user_id="uid",
        )
        rebuilt = TokenResponse.from_credential(token.credential())
        assert rebuilt.access_token == "at"
        assert rebuilt.refresh_token == "rt"
        assert rebuilt.scopes == ["a", "b"]
        assert rebuilt.provider_user_id == "uid"
        assert rebuilt.expires_at == token.expires_at

    def test_from_oauth_response(self):
        payload = {
            "access_token": "at",
            "token_type": "bearer",
            "refresh_token": "rt",
            "expires_in": "3600",
            "scope": "read:user user:email",
        }
        token = TokenResponse.from_oauth_response(payload)
        assert token.access_token == "at"
        assert token.token_type == "bearer"
        assert token.refresh_token == "rt"
        assert token.scopes == ["read:user", "user:email"]
        assert token.expires_at is not None
        assert token.raw == payload

    def test_from_oauth_response_minimal(self):
        token = TokenResponse.from_oauth_response({"access_token": "at"})
        assert token.token_type == "Bearer"
        assert token.refresh_token is None
        assert token.scopes == []
        assert token.expires_at is None


class TestIssuedAt:
    """issue:3fd80396c685 — a reused provider token must be observable."""

    def test_issued_at_read_from_the_access_token_iat(self):
        iat = int(datetime.now(timezone.utc).timestamp()) - 300
        token = TokenResponse(access_token=_jwt(iat=iat), expires_in=5155)
        assert token.issued_at == datetime.fromtimestamp(iat, tz=timezone.utc)
        # the grant reached us 5 minutes after Entra issued it
        assert 299 <= token.age_seconds() <= 310

    def test_issued_at_is_none_for_an_opaque_token(self):
        token = TokenResponse(access_token="ya29.opaque-google-token")
        assert token.issued_at is None
        assert token.age_seconds() is None

    def test_issued_at_is_none_when_the_jwt_carries_no_iat(self):
        assert TokenResponse(access_token=_jwt(sub="x")).issued_at is None

    def test_explicit_issued_at_is_not_overwritten(self):
        when = datetime(2026, 10, 23, tzinfo=timezone.utc)
        token = TokenResponse(access_token=_jwt(iat=1), issued_at=when)
        assert token.issued_at == when

    def test_jwt_issued_at_never_raises_on_garbage(self):
        for value in (None, "", "a.b", "x.y.z", "...", 42, _jwt(iat="soon")):
            assert jwt_issued_at(value) is None


class TestMaskValue:
    def test_masks_secret(self):
        assert mask_value("secret") == "***6"

    def test_none(self):
        assert mask_value(None) is None
        assert mask_value("") is None
