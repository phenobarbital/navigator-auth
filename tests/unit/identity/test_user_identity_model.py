"""Contract tests for the real `UserIdentity` model (FEAT-104, TASK-114).

These deliberately use `navigator_auth.models.UserIdentity` itself rather
than the `FakeUserIdentity` stubs used elsewhere in the identity suite. The
stubs are why FEAT-104 shipped: they covered the store logic and never the
model's column contract.
"""
from navigator_auth.models import UserIdentity


class TestUserIdentityNullableTokens:
    def test_bare_construction(self):
        """A profile-only identity (legacy pre-vault row) hydrates."""
        identity = UserIdentity(user_id=1, auth_provider="github")
        assert identity.access_token is None
        assert identity.refresh_token is None
        assert identity.id_token is None

    def test_accepts_null_refresh_and_id_token(self):
        """The GitHub shape: an access token, no refresh token, no id token."""
        identity = UserIdentity(
            user_id=1,
            auth_provider="github",
            access_token=b"sealed",
            refresh_token=None,
            id_token=None,
        )
        assert identity.access_token == b"sealed"
        assert identity.refresh_token is None
        assert identity.id_token is None

    def test_still_accepts_bytes(self):
        """No regression on the sealed path: bytes round-trip unchanged."""
        identity = UserIdentity(
            user_id=1,
            auth_provider="github",
            access_token=b"at",
            refresh_token=b"rt",
            id_token=b"id",
        )
        assert identity.access_token == b"at"
        assert identity.refresh_token == b"rt"
        assert identity.id_token == b"id"
