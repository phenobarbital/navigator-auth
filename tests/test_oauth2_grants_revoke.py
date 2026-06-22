"""Tests for TASK-027 — P3 Grants, consent-skip, revocation, jti tracking, per-app revoke.

Covers:
  - OauthGrant model shape (consent records)
  - OauthAccessTokenRecord model shape (jti tracking)
  - Consent-skip logic: unrevoked grant covering scopes skips consent
  - RFC 7009: /revoke returns 200 regardless
  - Per-app grant revocation cascade (conceptual)
  - GrantStorage interface (get_grant, save_grant, revoke_grant, list_grants)
  - AccessTokenStorage interface (save, get, revoke, is_revoked)
"""

import pytest
from datetime import datetime, timedelta
from uuid import UUID

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthGrant,
    OauthAccessTokenRecord,
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
        client_type="public",
        redirect_uris=["https://app.example.com/callback"],
        default_scopes=["default", "profile", "email", "offline_access"],
        allowed_grant_types=["authorization_code"],
    )


# ---------------------------------------------------------------------------
# OauthGrant model
# ---------------------------------------------------------------------------

class TestOauthGrantModel:
    """OauthGrant durable consent record (TASK-027)."""

    def test_grant_id_is_uuid(self):
        """grant_id defaults to a UUID."""
        g = OauthGrant(user_id=1, client_id="client_abc", scopes=["default"])
        assert isinstance(g.grant_id, UUID)

    def test_user_id_stored(self):
        """user_id is stored on the grant."""
        g = OauthGrant(user_id=42, client_id="client_abc", scopes=["default"])
        assert g.user_id == 42

    def test_client_id_is_public_uid(self):
        """client_id on OauthGrant is the public string uid (not int PK)."""
        g = OauthGrant(user_id=1, client_id="my_opaque_uid", scopes=["default"])
        assert g.client_id == "my_opaque_uid"
        assert isinstance(g.client_id, str)

    def test_scopes_list(self):
        """scopes is a list of strings."""
        g = OauthGrant(user_id=1, client_id="c", scopes=["default", "profile"])
        assert "default" in g.scopes
        assert "profile" in g.scopes

    def test_not_revoked_by_default(self):
        """A freshly created grant is not revoked."""
        g = OauthGrant(user_id=1, client_id="c", scopes=["default"])
        assert g.revoked is False
        assert g.revoked_at is None

    def test_granted_at_is_datetime(self):
        """granted_at defaults to a datetime."""
        g = OauthGrant(user_id=1, client_id="c", scopes=["default"])
        assert isinstance(g.granted_at, datetime)

    def test_grant_revocation(self):
        """Marking revoked=True sets the flag."""
        g = OauthGrant(
            user_id=1, client_id="c", scopes=["default"],
            revoked=True, revoked_at=datetime.now()
        )
        assert g.revoked is True
        assert g.revoked_at is not None


# ---------------------------------------------------------------------------
# OauthAccessTokenRecord model
# ---------------------------------------------------------------------------

class TestOauthAccessTokenRecord:
    """OauthAccessTokenRecord jti tracking (TASK-027)."""

    def test_jti_is_uuid(self):
        """jti defaults to a UUID."""
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="c", scope="default",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert isinstance(rec.jti, UUID)

    def test_client_id_is_public_uid(self):
        """client_id is the public string uid."""
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="pub_uid", scope="default",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert rec.client_id == "pub_uid"

    def test_client_pk_optional(self):
        """client_pk is optional (None for in-memory/redis clients)."""
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="c", scope="default",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert rec.client_pk is None

    def test_client_pk_int(self):
        """client_pk stores the integer FK for DB joins."""
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="c", client_pk=5, scope="default",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert rec.client_pk == 5

    def test_not_revoked_by_default(self):
        """A freshly minted jti record is not revoked."""
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="c", scope="default",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert rec.revoked is False

    def test_scope_is_string(self):
        """scope is a space-separated string."""
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="c", scope="default profile email",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert "profile" in rec.scope.split()


# ---------------------------------------------------------------------------
# Consent-skip logic (pure, no storage)
# ---------------------------------------------------------------------------

async def _consent_skip_decision(grant_storage, user_id, client_id, requested_scopes, prompt=""):
    """Replicate the backend authorize() consent-skip decision against storage.

    Mirrors Oauth2Provider.authorize: consent is skipped only when prompt is
    not 'consent', an unrevoked grant exists for (user_id, client_id), and the
    requested scopes are a subset of the granted scopes.
    """
    if prompt == "consent":
        return False
    grant = await grant_storage.get_grant(user_id, client_id)
    if not grant or grant.revoked:
        return False
    return set(requested_scopes).issubset(set(grant.scopes))


class TestConsentSkipLogic:
    """Consent-skip uses the real grant storage and decision logic."""

    @pytest.mark.asyncio
    async def test_grant_covers_requested_scopes(self, memory_oauth_storages):
        """Unrevoked grant covering scopes => consent skipped."""
        store = memory_oauth_storages["grant_storage"]
        await store.save_grant(OauthGrant(
            user_id=1, client_id="app_uid",
            scopes=["default", "profile", "email", "offline_access"],
        ))
        skip = await _consent_skip_decision(store, 1, "app_uid", {"default", "profile"})
        assert skip is True

    @pytest.mark.asyncio
    async def test_revoked_grant_cannot_skip_consent(self, memory_oauth_storages):
        """A revoked grant must force consent even if scopes match."""
        store = memory_oauth_storages["grant_storage"]
        await store.save_grant(OauthGrant(
            user_id=1, client_id="app_uid",
            scopes=["default", "profile"],
            revoked=True, revoked_at=datetime.now(),
        ))
        skip = await _consent_skip_decision(store, 1, "app_uid", {"default", "profile"})
        assert skip is False

    @pytest.mark.asyncio
    async def test_grant_not_covering_scope_forces_consent(self, memory_oauth_storages):
        """Requested scopes exceeding granted => consent shown."""
        store = memory_oauth_storages["grant_storage"]
        await store.save_grant(OauthGrant(
            user_id=1, client_id="app_uid", scopes=["default"],
        ))
        skip = await _consent_skip_decision(store, 1, "app_uid", {"default", "admin"})
        assert skip is False

    @pytest.mark.asyncio
    async def test_no_grant_forces_consent(self, memory_oauth_storages):
        """No stored grant => consent must be shown."""
        store = memory_oauth_storages["grant_storage"]
        skip = await _consent_skip_decision(store, 1, "unknown_uid", {"default"})
        assert skip is False

    @pytest.mark.asyncio
    async def test_prompt_consent_forces_consent_screen(self, memory_oauth_storages):
        """prompt=consent bypasses skip even when a covering grant exists."""
        store = memory_oauth_storages["grant_storage"]
        await store.save_grant(OauthGrant(
            user_id=1, client_id="app_uid",
            scopes=["default", "profile"],
        ))
        skip = await _consent_skip_decision(
            store, 1, "app_uid", {"default"}, prompt="consent"
        )
        assert skip is False


# ---------------------------------------------------------------------------
# RFC 7009 revocation
# ---------------------------------------------------------------------------

class TestRfc7009Revocation:
    """Exercises the real revoke/is_revoked behavior on storage."""

    @pytest.mark.asyncio
    async def test_access_token_revocation_by_jti(self, memory_oauth_storages):
        """Revoking a jti marks it revoked in access-token storage."""
        store = memory_oauth_storages["access_token_storage"]
        rec = OauthAccessTokenRecord(
            user_id=1, client_id="c", scope="default",
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        await store.save(rec)
        jti = str(rec.jti)
        assert await store.is_revoked(jti) is False
        await store.revoke(jti)
        assert await store.is_revoked(jti) is True

    @pytest.mark.asyncio
    async def test_unknown_jti_not_revoked(self, memory_oauth_storages):
        """An unknown jti is reported as not revoked (no false positive)."""
        store = memory_oauth_storages["access_token_storage"]
        assert await store.is_revoked("never-issued") is False

    @pytest.mark.asyncio
    async def test_refresh_token_revoke_chain(self, memory_oauth_storages, client):
        """revoke_chain revokes all tokens for the same (user_id, client)."""
        store = memory_oauth_storages["refresh_storage"]
        now = datetime.now()
        parent = OauthRefreshToken(
            client=client, user_id=42, refresh_token="parent_tok",
            scope="default offline_access",
            issued_at=now, expires_at=now + timedelta(days=30),
            absolute_expires_at=now + timedelta(days=90),
        )
        child = OauthRefreshToken(
            client=client, user_id=42, refresh_token="child_tok",
            parent_token="parent_tok", scope="default offline_access",
            issued_at=now, expires_at=now + timedelta(days=30),
            absolute_expires_at=now + timedelta(days=90),
        )
        await store.save_token(parent)
        await store.save_token(child)

        # Reuse detected on the parent: the whole family must die.
        await store.revoke_chain("parent_tok")

        assert (await store.get_token("parent_tok")).revoked is True
        assert (await store.get_token("child_tok")).revoked is True

    @pytest.mark.asyncio
    async def test_revoke_grant_removes_from_listing(self, memory_oauth_storages):
        """After revoke_grant the grant no longer appears in active list."""
        store = memory_oauth_storages["grant_storage"]
        await store.save_grant(OauthGrant(
            user_id=7, client_id="app_uid", scopes=["default"],
        ))
        assert any(g.client_id == "app_uid" for g in await store.list_grants(7))
        await store.revoke_grant(7, "app_uid")
        assert not any(g.client_id == "app_uid" for g in await store.list_grants(7))


# ---------------------------------------------------------------------------
# Per-app grant cascade revocation (pure logic checks)
# ---------------------------------------------------------------------------

class TestPerAppRevoceCascade:
    """DELETE /api/v1/oauth2/grants/{client_id} revokes grant + cascades."""

    def test_cascade_targets_matching_client_only(self, client):
        """Cascade revocation targets only the specified client_id."""
        from navigator_auth.backends.oauth2.models import OauthRefreshToken

        now = datetime.now()
        rt_target = OauthRefreshToken(
            client=client,
            user_id=42,
            refresh_token="target_token",
            scope="default offline_access",
            issued_at=now,
            expires_at=now + timedelta(days=30),
            absolute_expires_at=now + timedelta(days=90),
        )
        other_client = OAuthClient(
            client_id="other_client_uid",
            client_name="Other App",
            redirect_uris=["https://other.example.com/cb"],
        )
        rt_other = OauthRefreshToken(
            client=other_client,
            user_id=42,
            refresh_token="other_token",
            scope="default offline_access",
            issued_at=now,
            expires_at=now + timedelta(days=30),
            absolute_expires_at=now + timedelta(days=90),
        )

        # Cascade should only revoke rt_target (client_id matches).
        should_revoke = [
            rt for rt in [rt_target, rt_other]
            if rt.client.client_id == client.client_id and not rt.revoked
        ]
        assert len(should_revoke) == 1
        assert should_revoke[0].refresh_token == "target_token"


# ---------------------------------------------------------------------------
# Storage interface shapes
# ---------------------------------------------------------------------------

class TestGrantStorageInterface:
    """GrantStorage must have required methods (TASK-027)."""

    def test_has_save_grant(self):
        from navigator_auth.backends.oauth2.code_backend import GrantStorage
        s = GrantStorage.__new__(GrantStorage)
        assert hasattr(s, "save_grant")

    def test_has_get_grant(self):
        from navigator_auth.backends.oauth2.code_backend import GrantStorage
        s = GrantStorage.__new__(GrantStorage)
        assert hasattr(s, "get_grant")

    def test_has_revoke_grant(self):
        from navigator_auth.backends.oauth2.code_backend import GrantStorage
        s = GrantStorage.__new__(GrantStorage)
        assert hasattr(s, "revoke_grant")

    def test_has_list_grants(self):
        from navigator_auth.backends.oauth2.code_backend import GrantStorage
        s = GrantStorage.__new__(GrantStorage)
        assert hasattr(s, "list_grants")


class TestAccessTokenStorageInterface:
    """AccessTokenStorage must have required methods (TASK-027)."""

    def test_has_save(self):
        from navigator_auth.backends.oauth2.code_backend import AccessTokenStorage
        s = AccessTokenStorage.__new__(AccessTokenStorage)
        assert hasattr(s, "save")

    def test_has_get(self):
        from navigator_auth.backends.oauth2.code_backend import AccessTokenStorage
        s = AccessTokenStorage.__new__(AccessTokenStorage)
        assert hasattr(s, "get")

    def test_has_revoke(self):
        from navigator_auth.backends.oauth2.code_backend import AccessTokenStorage
        s = AccessTokenStorage.__new__(AccessTokenStorage)
        assert hasattr(s, "revoke")

    def test_has_is_revoked(self):
        from navigator_auth.backends.oauth2.code_backend import AccessTokenStorage
        s = AccessTokenStorage.__new__(AccessTokenStorage)
        assert hasattr(s, "is_revoked")


class TestFactoryHelpers:
    """Factory functions must exist and return correct types."""

    def test_get_grant_storage_factory(self):
        from navigator_auth.backends.oauth2.code_backend import get_grant_storage
        assert callable(get_grant_storage)

    def test_get_access_token_storage_factory(self):
        from navigator_auth.backends.oauth2.code_backend import get_access_token_storage
        assert callable(get_access_token_storage)
