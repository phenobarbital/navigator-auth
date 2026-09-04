"""Unit tests for navigator_auth.identity.types.TokenResponse."""
from datetime import datetime, timedelta, timezone

from navigator_auth.identity.types import TokenResponse, mask_value


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


class TestMaskValue:
    def test_masks_secret(self):
        assert mask_value("secret") == "***6"

    def test_none(self):
        assert mask_value(None) is None
        assert mask_value("") is None
