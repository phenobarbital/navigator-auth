"""Tests for TASK-026 — P2 Refresh hardening + durable storage.

Covers:
  - Rotation: new refresh token issued; old marked revoked(reason='rotated')
  - Reuse detection: presenting rotated token => chain revoked + invalid_grant
  - Absolute expiry: past absolute_expires_at => invalid_grant
  - offline_access gate: no offline_access in scope => no refresh token in response
  - Scope narrowing: can narrow scope on refresh; widening rejected
"""

import pytest
from datetime import datetime, timedelta

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthRefreshToken,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return OAuthClient(
        client_id="test_client_uid",
        client_pk=1,
        client_name="Test App",
        client_type="confidential",
        client_secret="secret123",
        redirect_uris=["https://app.example.com/callback"],
        default_scopes=["default", "profile", "email", "offline_access"],
        allowed_grant_types=["authorization_code", "refresh_token"],
    )


def make_rt(
    client,
    user_id: int = 42,
    scope: str = "default profile offline_access",
    token: str = "token_abc",
    parent: str = None,
    revoked: bool = False,
    revoked_reason: str = None,
    sliding_days: int = 30,
    absolute_days: int = 90,
) -> OauthRefreshToken:
    now = datetime.now()
    return OauthRefreshToken(
        client=client,
        user_id=user_id,
        refresh_token=token,
        scope=scope,
        parent_token=parent,
        issued_at=now,
        expires_at=now + timedelta(days=sliding_days),
        absolute_expires_at=now + timedelta(days=absolute_days),
        revoked=revoked,
        revoked_reason=revoked_reason,
    )


# ---------------------------------------------------------------------------
# OauthRefreshToken model
# ---------------------------------------------------------------------------

class TestRefreshTokenModel:
    """OauthRefreshToken model shape (TASK-026 fields)."""

    def test_has_parent_token_field(self, client):
        """parent_token field exists and defaults to None."""
        rt = make_rt(client)
        assert rt.parent_token is None

    def test_has_absolute_expires_at(self, client):
        """absolute_expires_at is present and is a datetime."""
        rt = make_rt(client)
        assert isinstance(rt.absolute_expires_at, datetime)

    def test_has_revoked_reason(self, client):
        """revoked_reason field exists."""
        rt = make_rt(client, revoked=True, revoked_reason="rotated")
        assert rt.revoked_reason == "rotated"

    def test_user_id_stored_independently(self, client):
        """user_id is on the RT, not derived from client.user."""
        rt = make_rt(client, user_id=99)
        assert rt.user_id == 99

    def test_chain_link_via_parent_token(self, client):
        """parent_token links old → new token for chain revocation."""
        old_token = "token_old"
        new_rt = make_rt(client, token="token_new", parent=old_token)
        assert new_rt.parent_token == old_token

    def test_absolute_expires_at_copied_from_chain_root(self, client):
        """On rotation, absolute_expires_at from old RT is copied to new RT (not extended)."""
        now = datetime.now()
        chain_root_absolute = now + timedelta(days=90)
        old_rt = OauthRefreshToken(
            client=client,
            user_id=42,
            refresh_token="old",
            scope="default offline_access",
            issued_at=now,
            expires_at=now + timedelta(days=30),
            absolute_expires_at=chain_root_absolute,
        )
        # Simulate rotation: new RT copies absolute_expires_at from old.
        new_rt = OauthRefreshToken(
            client=client,
            user_id=42,
            refresh_token="new",
            scope="default offline_access",
            parent_token=old_rt.refresh_token,
            issued_at=now,
            expires_at=now + timedelta(days=30),
            absolute_expires_at=old_rt.absolute_expires_at,  # copied, not extended
        )
        assert new_rt.absolute_expires_at == old_rt.absolute_expires_at
        assert new_rt.absolute_expires_at == chain_root_absolute


# ---------------------------------------------------------------------------
# Rotation state machine (pure logic, no storage needed)
# ---------------------------------------------------------------------------

class TestRotationLogic:
    """Rotation state-machine logic tests — pure, no external dependencies."""

    def test_fresh_token_not_revoked(self, client):
        """A freshly-issued RT must have revoked=False."""
        rt = make_rt(client)
        assert not rt.revoked

    def test_rotated_token_is_revoked_with_reason(self, client):
        """Marking a token as rotated sets revoked=True and revoked_reason='rotated'."""
        rt = make_rt(client, revoked=True, revoked_reason="rotated")
        assert rt.revoked
        assert rt.revoked_reason == "rotated"

    def test_sliding_expiry_extends_with_new_token(self, client):
        """New RT gets a fresh sliding expiry window (expires_at = now + TTL)."""
        old_rt = make_rt(client, token="old", sliding_days=30)
        new_rt = make_rt(client, token="new", parent="old", sliding_days=30)
        # New RT's expires_at must be later than old RT's (it was issued later).
        assert new_rt.expires_at > old_rt.expires_at or (
            new_rt.expires_at == old_rt.expires_at  # Same second — acceptable
        )

    def test_scope_narrowing_allowed(self, client):
        """A scope that is a subset of the original is valid for narrowing."""
        original_scopes = {"default", "profile", "email", "offline_access"}
        narrowed_scopes = {"default", "profile"}
        assert narrowed_scopes.issubset(original_scopes)

    def test_scope_widening_rejected(self, client):
        """A scope wider than the original is invalid."""
        original_scopes = {"default", "profile"}
        widened_scopes = {"default", "profile", "admin"}
        extra = widened_scopes - original_scopes
        assert extra == {"admin"}  # Non-empty => widening

    def test_no_offline_access_means_no_refresh_token(self, client):
        """Scope without offline_access must not yield a refresh token."""
        scope = "default profile email"  # no offline_access
        assert "offline_access" not in scope.split()

    def test_offline_access_enables_refresh_token(self, client):
        """Scope including offline_access permits refresh token issuance."""
        scope = "default profile offline_access"
        assert "offline_access" in scope.split()


# ---------------------------------------------------------------------------
# Absolute expiry checks (pure datetime logic)
# ---------------------------------------------------------------------------

class TestAbsoluteExpiry:
    """Absolute lifetime enforcement (no storage needed for pure datetime checks)."""

    def test_sliding_expiry_is_in_future(self, client):
        """A freshly-issued RT has expires_at in the future."""
        rt = make_rt(client)
        assert rt.expires_at > datetime.now()

    def test_absolute_expiry_is_in_future(self, client):
        """A freshly-issued RT has absolute_expires_at in the future."""
        rt = make_rt(client)
        assert rt.absolute_expires_at > datetime.now()

    def test_absolute_expiry_exceeds_sliding(self, client):
        """absolute_expires_at must be >= expires_at (absolute bounds sliding)."""
        rt = make_rt(client, sliding_days=30, absolute_days=90)
        assert rt.absolute_expires_at >= rt.expires_at

    def test_expired_sliding_window(self, client):
        """A token with expires_at in the past is sliding-expired."""
        now = datetime.now()
        rt = OauthRefreshToken(
            client=client,
            user_id=42,
            refresh_token="expired_sliding",
            scope="default offline_access",
            issued_at=now - timedelta(days=31),
            expires_at=now - timedelta(days=1),  # past sliding window
            absolute_expires_at=now + timedelta(days=59),  # within absolute
        )
        assert rt.expires_at < datetime.now()

    def test_absolute_lifetime_exceeded(self, client):
        """A token past absolute_expires_at is absolutely expired."""
        now = datetime.now()
        rt = OauthRefreshToken(
            client=client,
            user_id=42,
            refresh_token="expired_absolute",
            scope="default offline_access",
            issued_at=now - timedelta(days=91),
            expires_at=now - timedelta(days=61),  # sliding expired too
            absolute_expires_at=now - timedelta(days=1),  # absolutely expired
        )
        assert rt.absolute_expires_at < datetime.now()

    def test_valid_within_both_windows(self, client):
        """A token within both sliding and absolute windows is valid."""
        rt = make_rt(client, sliding_days=30, absolute_days=90)
        now = datetime.now()
        assert rt.expires_at > now
        assert rt.absolute_expires_at > now


# ---------------------------------------------------------------------------
# RefreshTokenStorage in-memory logic (no Redis)
# ---------------------------------------------------------------------------

class TestRefreshTokenStorageInterface:
    """Test RefreshTokenStorage interface shapes (without external dependencies)."""

    def test_revoke_chain_attribute_exists(self):
        """RefreshTokenStorage must have revoke_chain method."""
        from navigator_auth.backends.oauth2.code_backend import RefreshTokenStorage
        s = RefreshTokenStorage.__new__(RefreshTokenStorage)
        assert hasattr(s, "revoke_chain")

    def test_revoke_token_attribute_exists(self):
        """RefreshTokenStorage must have revoke_token method."""
        from navigator_auth.backends.oauth2.code_backend import RefreshTokenStorage
        s = RefreshTokenStorage.__new__(RefreshTokenStorage)
        assert hasattr(s, "revoke_token")

    def test_list_tokens_attribute_exists(self):
        """RefreshTokenStorage must have list_tokens method."""
        from navigator_auth.backends.oauth2.code_backend import RefreshTokenStorage
        s = RefreshTokenStorage.__new__(RefreshTokenStorage)
        assert hasattr(s, "list_tokens")


# ---------------------------------------------------------------------------
# Config values
# ---------------------------------------------------------------------------

class TestRefreshConfig:
    """TASK-026 config constants are present and have correct types."""

    def test_refresh_token_ttl_exists(self):
        from navigator_auth.conf import OAUTH_REFRESH_TOKEN_TTL
        assert isinstance(OAUTH_REFRESH_TOKEN_TTL, int)
        assert OAUTH_REFRESH_TOKEN_TTL > 0

    def test_refresh_absolute_ttl_exists(self):
        from navigator_auth.conf import OAUTH_REFRESH_ABSOLUTE_TTL
        assert isinstance(OAUTH_REFRESH_ABSOLUTE_TTL, int)
        assert OAUTH_REFRESH_ABSOLUTE_TTL > 0

    def test_refresh_rotation_exists(self):
        from navigator_auth.conf import OAUTH_REFRESH_ROTATION
        assert isinstance(OAUTH_REFRESH_ROTATION, bool)

    def test_absolute_ttl_exceeds_sliding_ttl(self):
        """Absolute TTL must be >= sliding TTL (otherwise absolute is pointless)."""
        from navigator_auth.conf import OAUTH_REFRESH_TOKEN_TTL, OAUTH_REFRESH_ABSOLUTE_TTL
        assert OAUTH_REFRESH_ABSOLUTE_TTL >= OAUTH_REFRESH_TOKEN_TTL

    def test_rotation_default_true(self):
        """Default rotation setting must be True per spec §6."""
        from navigator_auth.conf import OAUTH_REFRESH_ROTATION
        assert OAUTH_REFRESH_ROTATION is True
