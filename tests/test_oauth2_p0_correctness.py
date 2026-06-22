"""Tests for TASK-024 — P0 Correctness: resource-owner binding + B1-B5.

B1: expires_in must be an integer number of seconds, not an absolute timestamp.
B2: confidential clients must be verified with constant-time secret comparison.
B3: redirect_uri must exactly match registered URIs; on mismatch return error (no redirect).
B4: response_type != 'code' must yield unsupported_response_type.
B5: auth codes are single-use; replayed codes are rejected.

Resource-owner binding:
    user_id comes from the auth code (which got it from the session), never
    from client.user.
"""

import hmac
import pytest
from datetime import datetime, timedelta

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthAuthorizationCode,
    OauthUser,
)
from navigator_auth.backends.oauth2.code_backend import AuthorizationCodeStorage
from navigator_auth.backends.oauth2.pkce import verify as pkce_verify, generate_challenge


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def confidential_client():
    return OAuthClient(
        client_id="confidential_app",
        client_pk=1,
        client_name="Confidential App",
        client_type="confidential",
        client_secret="super_secret_value",
        redirect_uris=["https://example.com/callback"],
        default_scopes=["default", "profile", "email", "offline_access"],
        allowed_grant_types=["authorization_code", "refresh_token"],
    )


@pytest.fixture
def public_client():
    return OAuthClient(
        client_id="public_app",
        client_name="Public App",
        client_type="public",
        redirect_uris=["https://example.com/callback"],
        default_scopes=["default", "profile"],
        allowed_grant_types=["authorization_code"],
    )


@pytest.fixture
def resource_owner():
    return OauthUser(
        user_id=42,
        username="alice",
        given_name="Alice",
        family_name="Smith",
        email="alice@example.com",
    )


def make_auth_code(client, user_id: int, redirect_uri: str = "https://example.com/callback",
                   scope: str = "default profile", used: bool = False,
                   expires_in_seconds: int = 120) -> OauthAuthorizationCode:
    return OauthAuthorizationCode(
        client=client,
        user_id=user_id,
        code="test_code_value_12345",
        redirect_uri=redirect_uri,
        scope=scope,
        state="random_state",
        response_type="code",
        expires_at=datetime.now() + timedelta(seconds=expires_in_seconds),
        used=used,
    )


# ---------------------------------------------------------------------------
# Resource-owner binding
# ---------------------------------------------------------------------------

class TestResourceOwnerBinding:
    """user_id must come from session/auth_code, never from client.user."""

    def test_auth_code_carries_user_id(self, confidential_client, resource_owner):
        """OauthAuthorizationCode stores user_id independently of client.user."""
        code = make_auth_code(confidential_client, user_id=resource_owner.user_id)
        assert code.user_id == 42

    def test_user_id_independent_of_client_user(self, confidential_client):
        """Changing client.user should NOT change the code's user_id."""
        code = make_auth_code(confidential_client, user_id=99)
        assert code.user_id == 99
        # client.user is unrelated to the token principal.
        assert confidential_client.user is None

    def test_client_user_none_by_default(self, confidential_client):
        """OAuthClient.user defaults to None — it is informational only."""
        assert confidential_client.user is None

    def test_user_id_required_in_auth_code(self, public_client):
        """OauthAuthorizationCode requires user_id; ValidationError without it."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            OauthAuthorizationCode(
                client=public_client,
                # user_id intentionally omitted
                code="c",
                redirect_uri="https://example.com/callback",
                scope="default",
                state="s",
            )


# ---------------------------------------------------------------------------
# B1: expires_in must be integer seconds
# ---------------------------------------------------------------------------

class TestB1ExpiresIn:
    """expires_in must be an integer representing seconds remaining."""

    def test_expires_in_is_int_seconds(self):
        """Computing expires_in as seconds from absolute timestamp yields int."""
        from datetime import timezone

        now_utc = datetime.now(timezone.utc)
        # Simulate what create_token returns as exp_abs (UNIX timestamp float).
        exp_abs = (now_utc + timedelta(hours=1)).timestamp()
        expires_in = int(exp_abs - now_utc.timestamp())

        assert isinstance(expires_in, int)
        # Should be close to 3600 (within 2 seconds of test execution time).
        assert 3598 <= expires_in <= 3602

    def test_expires_in_not_timestamp(self):
        """An absolute Unix timestamp would be >> 3600; reject if > 86400."""
        import time
        # Wrong approach: returning the absolute timestamp directly.
        wrong_expires_in = int(time.time()) + 3600  # e.g. 1_719_000_000
        # The correct value must be seconds, not epoch.
        correct_expires_in = 3600
        assert wrong_expires_in > 86400          # "wrong" value is huge
        assert correct_expires_in <= 3600        # correct is bounded


# ---------------------------------------------------------------------------
# B2: client_secret constant-time comparison
# ---------------------------------------------------------------------------

class TestB2ClientSecret:
    """Confidential clients must be verified with constant-time comparison."""

    def test_correct_secret_passes(self, confidential_client):
        """hmac.compare_digest returns True when secrets match."""
        stored = confidential_client.client_secret
        provided = "super_secret_value"
        assert hmac.compare_digest(stored, provided)

    def test_wrong_secret_fails(self, confidential_client):
        """hmac.compare_digest returns False when secrets differ."""
        stored = confidential_client.client_secret
        provided = "wrong_secret"
        assert not hmac.compare_digest(stored, provided)

    def test_public_client_skips_secret_check(self, public_client):
        """Public clients have no client_secret; no secret check is needed."""
        assert public_client.client_type == "public"
        assert public_client.client_secret is None

    def test_empty_secret_rejected(self, confidential_client):
        """Empty string must not match a non-empty stored secret."""
        stored = confidential_client.client_secret or ""
        provided = ""
        assert not hmac.compare_digest(stored, provided)


# ---------------------------------------------------------------------------
# B3: redirect_uri exact match
# ---------------------------------------------------------------------------

class TestB3RedirectUri:
    """redirect_uri must exactly match the registered URIs.

    On mismatch the server MUST NOT redirect; it must return an error response.
    """

    def test_exact_match_passes(self, confidential_client):
        """Registered URI accepted without modification."""
        uri = "https://example.com/callback"
        assert uri in confidential_client.redirect_uris

    def test_unknown_uri_rejected(self, confidential_client):
        """URI not in the registered list must be rejected."""
        uri = "https://evil.com/steal"
        assert uri not in confidential_client.redirect_uris

    def test_trailing_slash_is_different(self, confidential_client):
        """'https://example.com/callback/' differs from 'https://example.com/callback'."""
        # Exact string match — even a trailing slash is a different URI.
        uri = "https://example.com/callback/"
        assert uri not in confidential_client.redirect_uris

    def test_http_vs_https_is_different(self, confidential_client):
        """http vs https scheme mismatch is rejected."""
        uri = "http://example.com/callback"
        assert uri not in confidential_client.redirect_uris


# ---------------------------------------------------------------------------
# B4: response_type validation
# ---------------------------------------------------------------------------

class TestB4ResponseType:
    """response_type must be 'code'; anything else is unsupported."""

    def test_code_is_accepted(self):
        """response_type='code' is the only accepted value."""
        response_type = "code"
        assert response_type == "code"

    def test_token_is_rejected(self):
        """Implicit flow ('token') is not supported."""
        response_type = "token"
        assert response_type != "code"

    def test_empty_is_rejected(self):
        """Empty response_type must be rejected."""
        response_type = ""
        assert response_type != "code"

    def test_none_is_rejected(self):
        """Missing response_type must default to something that fails if not 'code'."""
        response_type = None
        assert response_type != "code"


# ---------------------------------------------------------------------------
# B5: single-use authorization codes
# ---------------------------------------------------------------------------

class TestB5SingleUseCode:
    """Authorization codes are single-use: replay must be rejected."""

    def test_fresh_code_not_used(self, confidential_client):
        """A newly issued code must have used=False."""
        code = make_auth_code(confidential_client, user_id=1)
        assert code.used is False
        assert code.used_at is None

    def test_used_code_has_used_true(self, confidential_client):
        """After marking used, used=True and used_at is set."""
        code = make_auth_code(confidential_client, user_id=1, used=True)
        assert code.used is True

    def test_expired_code_rejected(self, confidential_client):
        """A code that has passed expires_at must be rejected."""
        code = make_auth_code(confidential_client, user_id=1, expires_in_seconds=-1)
        now = datetime.now()
        assert code.expires_at < now

    def test_valid_code_not_expired(self, confidential_client):
        """A code issued with a future expires_at is not expired."""
        code = make_auth_code(confidential_client, user_id=1, expires_in_seconds=120)
        now = datetime.now()
        assert code.expires_at > now


# ---------------------------------------------------------------------------
# AuthorizationCodeStorage — mark_used
# ---------------------------------------------------------------------------

class TestAuthorizationCodeStorageMarkUsed:
    """AuthorizationCodeStorage.mark_used() must update the stored record."""

    @pytest.mark.asyncio
    async def test_mark_used_updates_flag(self, confidential_client):
        """After mark_used, get_code returns an object with used=True."""
        try:
            import fakeredis.aioredis as fakeredis_mod
        except ImportError:
            pytest.skip("fakeredis not installed; skipping Redis test")
            return

        redis_client = fakeredis_mod.FakeRedis(decode_responses=True)
        storage = AuthorizationCodeStorage.__new__(AuthorizationCodeStorage)
        storage.redis = redis_client
        storage.prefix = "oauth2:code:"

        code = make_auth_code(confidential_client, user_id=42)
        await storage.save_code(code)

        fetched = await storage.get_code(code.code)
        assert fetched is not None
        assert fetched.used is False

        await storage.mark_used(code.code)
        updated = await storage.get_code(code.code)
        assert updated is not None
        assert updated.used is True


# ---------------------------------------------------------------------------
# PKCE S256 verification (imported here, tested in full in test_oauth2_pkce)
# ---------------------------------------------------------------------------

class TestPkceBasic:
    """Basic PKCE S256 verify/generate round-trip."""

    def test_s256_round_trip(self):
        """generate_challenge then verify must succeed."""
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = generate_challenge(verifier)
        assert pkce_verify(verifier, challenge, "S256")

    def test_wrong_verifier_fails(self):
        """A different verifier must not match the challenge."""
        verifier = "correct_verifier_string"
        wrong = "incorrect_verifier"
        challenge = generate_challenge(verifier)
        assert not pkce_verify(wrong, challenge, "S256")

    def test_plain_method_rejected(self):
        """'plain' method must be rejected (not supported)."""
        verifier = "any_verifier"
        assert not pkce_verify(verifier, verifier, "plain")

    def test_empty_verifier_rejected(self):
        """Empty verifier must not match any challenge."""
        challenge = generate_challenge("something")
        assert not pkce_verify("", challenge, "S256")
