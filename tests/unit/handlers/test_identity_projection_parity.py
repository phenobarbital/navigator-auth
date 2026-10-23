"""The CRUD identity projection agrees with IdentityStore.masked() (FEAT-105).

Spec §4 row `test_identity_projection_matches_masked`, spec §8 Q6.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from navigator_auth.handlers.redaction import redact_row
from navigator_auth.handlers.userattrs import UserIdentityHandler
from navigator_auth.identity.store import IdentityStore

MASKED_KEYS = frozenset(
    {
        "expired",
        "identity_id",
        "auth_provider",
        "provider_user_id",
        "scopes",
        "token_type",
        "expires_at",
        "refreshed_at",
        "created_at",
        "enabled",
        "has_refresh_token",
        "has_id_token",
        "profile",
    }
)
CREDS = ("access_token", "refresh_token", "id_token", "key_version")


def _identity(**kw):
    base = dict(
        identity_id=uuid4(),
        user_id=42,
        auth_provider="git",
        provider_user_id="p1",
        scopes=["a"],
        token_type="Bearer",
        expires_at=None,
        refreshed_at=None,
        created_at=datetime.now(timezone.utc),
        enabled=True,
        access_token=b"at",
        refresh_token=b"rt",
        id_token=None,
        key_version=1,
        auth_data={"k": "v"},
        display_name="n",
        title=None,
        nickname=None,
        email="e@x",
        phone=None,
        short_bio=None,
        avatar=None,
        attributes={},
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _project(identity):
    h = UserIdentityHandler.__new__(UserIdentityHandler)
    red = redact_row(identity, h.public_columns)
    return h._masked_shape(red, identity)


def _masked(identity):
    return IdentityStore.masked(None, identity)


class TestProjectionParity:
    def test_masked_key_set_is_still_what_we_think(self):
        assert set(_masked(_identity())) == MASKED_KEYS

    def test_credential_related_keys_agree(self):
        out = _project(_identity())
        assert MASKED_KEYS <= set(out)
        assert not (set(out) & set(CREDS))
        assert set(out) != MASKED_KEYS  # PII columns are served here too
        m = _masked(_identity(expires_at=None))
        o = _project(_identity(expires_at=None))
        for key in ("scopes", "token_type", "profile", "expired", "enabled"):
            assert m[key] == o[key]

    def test_has_refresh_token_true_and_false(self):
        assert _project(_identity(refresh_token=b"ct"))["has_refresh_token"] is True
        assert _project(_identity(refresh_token=None))["has_refresh_token"] is False

    def test_has_id_token_uses_getattr_default(self):
        ident = _identity()
        del ident.id_token
        assert _project(ident)["has_id_token"] is False

    def test_expired_for_naive_and_aware_expires_at(self):
        now = datetime.now(timezone.utc)
        past, future = now - timedelta(hours=1), now + timedelta(hours=1)
        assert _project(_identity(expires_at=past.replace(tzinfo=None)))["expired"] is True
        assert _project(_identity(expires_at=future.replace(tzinfo=None)))["expired"] is False
        assert _project(_identity(expires_at=past))["expired"] is True
        assert _project(_identity(expires_at=future))["expired"] is False

    def test_expired_is_false_when_expires_at_is_none(self):
        assert _project(_identity(expires_at=None))["expired"] is False

    def test_profile_defaults_to_empty_dict(self):
        assert _project(_identity(auth_data=None))["profile"] == {}
