"""Tests for TASK-025 — P1 PKCE (S256).

Covers:
  - S256 match / mismatch
  - plain method rejected
  - empty verifier / challenge edge cases
  - OAUTH_REQUIRE_PKCE_PUBLIC enforcement (conceptual test — the enforcement
    is in backend.py token handler, exercised here via the pkce.verify helper)
"""

import base64
import hashlib
import pytest

from navigator_auth.backends.oauth2.pkce import verify, generate_challenge


# ---------------------------------------------------------------------------
# RFC 7636 test vector (Appendix B)
# https://www.rfc-editor.org/rfc/rfc7636#appendix-B
# ---------------------------------------------------------------------------

RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
# SHA-256 of RFC_VERIFIER ASCII bytes, base64url without padding:
RFC_CHALLENGE_S256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class TestS256Verification:
    """S256 (SHA-256 base64url) verifier matching."""

    def test_rfc_vector_match(self):
        """RFC 7636 Appendix B test vector must verify correctly."""
        assert verify(RFC_VERIFIER, RFC_CHALLENGE_S256, "S256")

    def test_rfc_vector_mismatch(self):
        """Wrong verifier must not match the RFC challenge."""
        assert not verify("wrong_verifier", RFC_CHALLENGE_S256, "S256")

    def test_generate_and_verify_round_trip(self):
        """generate_challenge then verify must succeed."""
        verifier = "some_random_verifier_string_long_enough"
        challenge = generate_challenge(verifier)
        assert verify(verifier, challenge, "S256")

    def test_verify_different_verifier_fails(self):
        """Different verifier produces different challenge; mismatch detected."""
        v1 = "verifier_one_string"
        v2 = "verifier_two_string"
        challenge = generate_challenge(v1)
        assert not verify(v2, challenge, "S256")

    def test_challenge_is_base64url_without_padding(self):
        """generate_challenge produces base64url-safe string with no '=' padding."""
        challenge = generate_challenge("any_verifier")
        assert "=" not in challenge
        assert "+" not in challenge
        assert "/" not in challenge

    def test_case_sensitivity(self):
        """S256 challenges are case-sensitive (base64url is case-sensitive)."""
        verifier = "CaseSensitiveVerifier"
        challenge = generate_challenge(verifier)
        upper_challenge = challenge.upper()
        # Unless the challenge happens to be all same case, this should fail.
        # The important thing is that hmac.compare_digest is exact.
        if challenge != upper_challenge:
            assert not verify(verifier, upper_challenge, "S256")

    def test_unicode_verifier_ascii_required(self):
        """Non-ASCII verifier must raise (RFC 7636 §4.1 requires ASCII only)."""
        with pytest.raises((UnicodeEncodeError, ValueError)):
            verify("vérifier_unicode", "any_challenge", "S256")


class TestPlainMethodRejected:
    """plain method must be rejected — S256 is the only supported method."""

    def test_plain_rejected(self):
        """verify() with method='plain' returns False."""
        verifier = "my_plain_verifier"
        # Even if challenge == verifier (plain equality), must be rejected.
        assert not verify(verifier, verifier, "plain")

    def test_plain_uppercase_rejected(self):
        """PLAIN (uppercase) must also be rejected."""
        verifier = "my_plain_verifier"
        assert not verify(verifier, verifier, "PLAIN")

    def test_unknown_method_rejected(self):
        """Unknown method strings must be rejected."""
        verifier = "verifier"
        challenge = generate_challenge(verifier)
        assert not verify(verifier, challenge, "SHA512")
        assert not verify(verifier, challenge, "none")
        assert not verify(verifier, challenge, "")


class TestEdgeCases:
    """Edge cases for malformed inputs."""

    def test_empty_verifier_rejected(self):
        """Empty verifier string must return False."""
        challenge = generate_challenge("something")
        assert not verify("", challenge, "S256")

    def test_empty_challenge_rejected(self):
        """Empty challenge string must return False."""
        assert not verify("some_verifier", "", "S256")

    def test_none_verifier_rejected(self):
        """None verifier must return False without raising."""
        challenge = generate_challenge("v")
        assert not verify(None, challenge, "S256")

    def test_none_challenge_rejected(self):
        """None challenge must return False without raising."""
        assert not verify("verifier", None, "S256")

    def test_method_case_insensitive_for_s256(self):
        """Method matching for S256 must be case-insensitive ('s256' == 'S256')."""
        verifier = "some_verifier"
        challenge = generate_challenge(verifier)
        # Lowercase 's256' should also be accepted.
        assert verify(verifier, challenge, "s256")

    def test_very_long_verifier(self):
        """RFC 7636 allows verifiers up to 128 chars; verify must handle them."""
        verifier = "A" * 128
        challenge = generate_challenge(verifier)
        assert verify(verifier, challenge, "S256")

    def test_minimum_length_verifier(self):
        """RFC 7636 §4.1: verifier must be 43+ chars; we accept shorter (no length gate)."""
        # We don't enforce length in verify() — the server can gate length separately.
        short = "short"
        challenge = generate_challenge(short)
        assert verify(short, challenge, "S256")


class TestPkceConfig:
    """OAUTH_REQUIRE_PKCE_PUBLIC flag is in conf.py — spot-check its presence."""

    def test_config_flag_exists(self):
        """OAUTH_REQUIRE_PKCE_PUBLIC must be importable from conf."""
        from navigator_auth.conf import OAUTH_REQUIRE_PKCE_PUBLIC
        assert isinstance(OAUTH_REQUIRE_PKCE_PUBLIC, bool)

    def test_config_flag_default_true(self):
        """By default, PKCE must be required for public clients."""
        from navigator_auth.conf import OAUTH_REQUIRE_PKCE_PUBLIC
        # Default is True per spec §3 M3 (S256 required for public clients).
        assert OAUTH_REQUIRE_PKCE_PUBLIC is True


class TestS256Implementation:
    """Correctness of the S256 hash implementation."""

    def test_s256_uses_sha256(self):
        """S256 challenge is BASE64URL(SHA256(verifier))."""
        verifier = "testing_sha256_implementation"
        expected_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = (
            base64.urlsafe_b64encode(expected_hash).rstrip(b"=").decode("ascii")
        )
        assert generate_challenge(verifier) == expected_challenge

    def test_s256_matches_manual_computation(self):
        """Manual S256 computation must produce the same result as pkce.py."""
        verifier = "manual_test_verifier_abc123"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        manual_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert verify(verifier, manual_challenge, "S256")
