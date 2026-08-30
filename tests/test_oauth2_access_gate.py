"""Tests for FEAT-095 TASK-042 — per-client access gate + approval queue.

Covers spec §4:
  test_gate_blocks_before_consent, test_gate_disabled_by_default,
  test_gate_revoke_cascade, test_gate_device_flow, test_gate_pending_queue
  + test_gate_lifecycle (activate → works → deactivate → revoked everywhere)
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from navigator_auth.backends.oauth2.client_access import (
    STATUS_ACTIVE,
    STATUS_PENDING,
    STATUS_REVOKED,
    MemoryClientAccessStorage,
    get_client_access_storage,
)
from navigator_auth.backends.oauth2.models import OAuthClient

USER_ID = 42
CLIENT_UID = "cli_mcp_9f3a"
REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
STATE = "csrfSTATE123"


def _client(gated: bool = True) -> OAuthClient:
    return OAuthClient(
        client_id=CLIENT_UID,
        client_name="Claude",
        client_type="public",
        redirect_uris=[REDIRECT_URI],
        enforce_access_gate=gated,
        registration_source="dcr",
    )


@pytest.fixture
def storage():
    return MemoryClientAccessStorage()


@pytest.fixture
def provider(storage):
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.client_access_storage = storage
    return prov


def _request():
    request = MagicMock()
    request.app = {}
    return request


# ---------------------------------------------------------------------------
# Storage semantics
# ---------------------------------------------------------------------------

class TestGateStorage:
    @pytest.mark.asyncio
    async def test_check_fails_closed_for_unknown_user(self, storage):
        assert await storage.check(USER_ID, CLIENT_UID) is False

    @pytest.mark.asyncio
    async def test_grant_then_check(self, storage):
        row = await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        assert row.status == STATUS_ACTIVE
        assert await storage.check(USER_ID, CLIENT_UID) is True

    @pytest.mark.asyncio
    async def test_revoke_then_check(self, storage):
        await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        assert await storage.revoke(USER_ID, CLIENT_UID) is True
        assert await storage.check(USER_ID, CLIENT_UID) is False

    @pytest.mark.asyncio
    async def test_access_is_per_client(self, storage):
        await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        assert await storage.check(USER_ID, "other_client") is False

    @pytest.mark.asyncio
    async def test_access_is_per_user(self, storage):
        await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        assert await storage.check(999, CLIENT_UID) is False

    @pytest.mark.asyncio
    async def test_list_for_client(self, storage):
        await storage.grant(1, CLIENT_UID, granted_by=1)
        await storage.grant(2, CLIENT_UID, granted_by=1)
        await storage.grant(3, "other", granted_by=1)
        rows = await storage.list_for_client(CLIENT_UID)
        assert {r.user_id for r in rows} == {1, 2}

    def test_factory_returns_expected_tiers(self):
        from navigator_auth.backends.oauth2.client_access import (
            MemoryClientAccessStorage as Mem,
            PostgresClientAccessStorage as Pg,
        )

        assert isinstance(get_client_access_storage("memory"), Mem)
        assert isinstance(get_client_access_storage("postgres"), Pg)


# ---------------------------------------------------------------------------
# Approval queue (D7)
# ---------------------------------------------------------------------------

class TestApprovalQueue:
    @pytest.mark.asyncio
    async def test_gate_pending_queue_no_duplicates(self, storage):
        """Repeated denied attempts upsert exactly one pending row."""
        for _ in range(5):
            await storage.request_access(USER_ID, CLIENT_UID)

        rows = await storage.list_for_client(CLIENT_UID)
        assert len(rows) == 1
        assert rows[0].status == STATUS_PENDING
        assert await storage.check(USER_ID, CLIENT_UID) is False

    @pytest.mark.asyncio
    async def test_approve_activates(self, storage):
        await storage.request_access(USER_ID, CLIENT_UID)
        row = await storage.approve(USER_ID, CLIENT_UID, granted_by=7)
        assert row.status == STATUS_ACTIVE
        assert row.granted_by == 7
        assert await storage.check(USER_ID, CLIENT_UID) is True

    @pytest.mark.asyncio
    async def test_reject_keeps_user_denied(self, storage):
        await storage.request_access(USER_ID, CLIENT_UID)
        assert await storage.reject(USER_ID, CLIENT_UID) is True
        assert await storage.check(USER_ID, CLIENT_UID) is False
        row = await storage.get(USER_ID, CLIENT_UID)
        assert row.status == STATUS_REVOKED

    @pytest.mark.asyncio
    async def test_list_pending_is_the_queue(self, storage):
        await storage.request_access(1, CLIENT_UID)
        await storage.request_access(2, CLIENT_UID)
        await storage.grant(3, CLIENT_UID, granted_by=1)
        pending = await storage.list_pending(CLIENT_UID)
        assert {r.user_id for r in pending} == {1, 2}

    @pytest.mark.asyncio
    async def test_request_never_downgrades_active(self, storage):
        await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        await storage.request_access(USER_ID, CLIENT_UID)
        assert await storage.check(USER_ID, CLIENT_UID) is True

    @pytest.mark.asyncio
    async def test_request_never_reopens_revoked(self, storage):
        """A revoked user cannot re-queue themselves back into pending."""
        await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        await storage.revoke(USER_ID, CLIENT_UID)
        await storage.request_access(USER_ID, CLIENT_UID)
        row = await storage.get(USER_ID, CLIENT_UID)
        assert row.status == STATUS_REVOKED

    @pytest.mark.asyncio
    async def test_approve_requires_a_pending_row(self, storage):
        assert await storage.approve(USER_ID, CLIENT_UID, granted_by=1) is None

    @pytest.mark.asyncio
    async def test_reject_requires_a_pending_row(self, storage):
        await storage.grant(USER_ID, CLIENT_UID, granted_by=1)
        assert await storage.reject(USER_ID, CLIENT_UID) is False
        assert await storage.check(USER_ID, CLIENT_UID) is True


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

class TestGateEnforcement:
    @pytest.mark.asyncio
    async def test_gate_disabled_by_default(self, provider, monkeypatch):
        """Global switch off + client flag off ⇒ FEAT-093 behaviour."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_ACCESS_GATE_ENABLED",
            False,
        )
        result = await provider._enforce_access_gate(
            _request(), _client(gated=False), USER_ID, REDIRECT_URI, STATE
        )
        assert result is None
        # Nothing was queued either — the gate is entirely inert.
        assert await provider.client_access_storage.list_for_client(CLIENT_UID) == []

    @pytest.mark.asyncio
    async def test_gate_blocks_before_consent(self, provider, monkeypatch):
        """Non-activated user ⇒ access_denied redirect carrying state."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_ACCESS_GATE_ENABLED",
            False,
        )
        response = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, STATE
        )

        assert response is not None
        assert isinstance(response, web.HTTPFound)
        location = response.headers["Location"]
        assert location.startswith(REDIRECT_URI)
        assert "error=access_denied" in location
        assert f"state={STATE}" in location

    @pytest.mark.asyncio
    async def test_denied_attempt_queues_pending_row(self, provider, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_ACCESS_GATE_QUEUE",
            True,
        )
        await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, STATE
        )
        rows = await provider.client_access_storage.list_for_client(CLIENT_UID)
        assert len(rows) == 1
        assert rows[0].status == STATUS_PENDING

    @pytest.mark.asyncio
    async def test_queue_can_be_switched_off(self, provider, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_ACCESS_GATE_QUEUE",
            False,
        )
        await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, STATE
        )
        assert await provider.client_access_storage.list_for_client(CLIENT_UID) == []

    @pytest.mark.asyncio
    async def test_activated_user_passes(self, provider):
        await provider.client_access_storage.grant(USER_ID, CLIENT_UID, 1)
        result = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, STATE
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_global_switch_gates_every_client(self, provider, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_ACCESS_GATE_ENABLED",
            True,
        )
        response = await provider._enforce_access_gate(
            _request(), _client(gated=False), USER_ID, REDIRECT_URI, STATE
        )
        assert response is not None

    @pytest.mark.asyncio
    async def test_gate_fails_closed_when_storage_missing(
        self, provider, monkeypatch
    ):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_ACCESS_GATE_ENABLED",
            True,
        )
        provider.client_access_storage = None
        response = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, STATE
        )
        assert response is not None

    @pytest.mark.asyncio
    async def test_gate_fails_closed_when_storage_errors(self, provider):
        provider.client_access_storage = MagicMock()
        provider.client_access_storage.check = AsyncMock(
            side_effect=RuntimeError("redis down")
        )
        provider.client_access_storage.request_access = AsyncMock()
        response = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, STATE
        )
        assert response is not None

    @pytest.mark.asyncio
    async def test_denial_without_redirect_uri_renders_error(self, provider):
        """No validated redirect_uri ⇒ render, never emit a bare redirect."""
        response = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, None, ""
        )
        assert response.status == 403
        assert not isinstance(response, web.HTTPFound)
        assert b"access_denied" in response.body

    @pytest.mark.asyncio
    async def test_denial_omits_state_when_absent(self, provider):
        response = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, REDIRECT_URI, ""
        )
        assert "state=" not in response.headers["Location"]


# ---------------------------------------------------------------------------
# Device-flow parity
# ---------------------------------------------------------------------------

class TestDeviceFlowGate:
    def test_gate_device_flow_is_wired(self):
        """The gate must cover device verification or it is bypassable."""
        import inspect
        from navigator_auth.backends.oauth2.backend import Oauth2Provider

        source = inspect.getsource(Oauth2Provider.device_verification)
        assert "_enforce_access_gate" in source

    def test_gate_authorize_is_wired_before_consent(self):
        import inspect
        from navigator_auth.backends.oauth2.backend import Oauth2Provider

        source = inspect.getsource(Oauth2Provider.authorize)
        assert "_enforce_access_gate" in source
        # The gate must run before the consent-skip / consent handoff.
        assert source.index("_enforce_access_gate") < source.index(
            "nav_oauth2_consent"
        )

    @pytest.mark.asyncio
    async def test_device_denial_renders_not_redirects(self, provider):
        """The device flow has no redirect_uri to send the user to."""
        response = await provider._enforce_access_gate(
            _request(), _client(gated=True), USER_ID, redirect_uri=None, state=""
        )
        assert response.status == 403


# ---------------------------------------------------------------------------
# Deactivation cascade
# ---------------------------------------------------------------------------

class _Grants:
    def __init__(self):
        self.revoked = []

    async def revoke_grant(self, user_id, client_id):
        self.revoked.append((user_id, client_id))
        return True


class _RefreshTokens:
    def __init__(self, tokens):
        self._tokens = tokens
        self.chains = []

    async def list_tokens(self, user_id):
        return self._tokens

    async def revoke_chain(self, refresh_token):
        self.chains.append(refresh_token)


class _FakeJtiRedis:
    def __init__(self, records):
        self.records = records

    async def scan_iter(self, match=None):
        for key in list(self.records):
            yield key

    async def get(self, key):
        import json as _json

        value = self.records.get(key)
        return _json.dumps(value) if value else None


class _AccessTokens:
    prefix = "oauth2:jti:"
    revoked_prefix = "oauth2:jti:revoked:"

    def __init__(self, records):
        self.redis = _FakeJtiRedis(records)
        self.revoked = []

    async def revoke(self, jti):
        self.revoked.append(jti)
        return True


def _refresh(token, client_uid, revoked=False):
    rt = MagicMock()
    rt.refresh_token = token
    rt.revoked = revoked
    rt.client = MagicMock()
    rt.client.client_id = client_uid
    return rt


class TestRevocationCascade:
    @pytest.mark.asyncio
    async def test_gate_revoke_cascade(self, provider):
        """Grants, refresh chains and live jtis all go."""
        provider.grant_storage = _Grants()
        provider.refresh_token_storage = _RefreshTokens(
            [
                _refresh("rt-mine-1", CLIENT_UID),
                _refresh("rt-mine-2", CLIENT_UID),
                _refresh("rt-other", "another_client"),
                _refresh("rt-already", CLIENT_UID, revoked=True),
            ]
        )
        provider.access_token_storage = _AccessTokens(
            {
                "oauth2:jti:aaa": {
                    "jti": "aaa", "user_id": USER_ID,
                    "client_id": CLIENT_UID, "revoked": False,
                },
                "oauth2:jti:bbb": {
                    "jti": "bbb", "user_id": USER_ID,
                    "client_id": "another_client", "revoked": False,
                },
                "oauth2:jti:ccc": {
                    "jti": "ccc", "user_id": 999,
                    "client_id": CLIENT_UID, "revoked": False,
                },
                "oauth2:jti:ddd": {
                    "jti": "ddd", "user_id": USER_ID,
                    "client_id": CLIENT_UID, "revoked": True,
                },
            }
        )

        result = await provider.cascade_access_revocation(USER_ID, CLIENT_UID)

        assert result["grants"] == 1
        assert provider.grant_storage.revoked == [(USER_ID, CLIENT_UID)]
        # Only this client's live chains.
        assert set(provider.refresh_token_storage.chains) == {
            "rt-mine-1", "rt-mine-2"
        }
        # Only this (user, client)'s live jtis.
        assert provider.access_token_storage.revoked == ["aaa"]
        assert result["access_tokens"] == 1

    @pytest.mark.asyncio
    async def test_cascade_skips_revocation_markers(self, provider):
        provider.grant_storage = None
        provider.refresh_token_storage = None
        provider.access_token_storage = _AccessTokens(
            {
                "oauth2:jti:revoked:aaa": {
                    "jti": "aaa", "user_id": USER_ID,
                    "client_id": CLIENT_UID, "revoked": False,
                },
            }
        )
        result = await provider.cascade_access_revocation(USER_ID, CLIENT_UID)
        assert result["access_tokens"] == 0
        assert provider.access_token_storage.revoked == []

    @pytest.mark.asyncio
    async def test_cascade_survives_storage_failures(self, provider):
        """A partial failure must not abort the rest of the cascade."""
        provider.grant_storage = MagicMock()
        provider.grant_storage.revoke_grant = AsyncMock(
            side_effect=RuntimeError("boom")
        )
        provider.refresh_token_storage = _RefreshTokens(
            [_refresh("rt-1", CLIENT_UID)]
        )
        provider.access_token_storage = None

        result = await provider.cascade_access_revocation(USER_ID, CLIENT_UID)

        assert result["grants"] == 0
        assert provider.refresh_token_storage.chains == ["rt-1"]


# ---------------------------------------------------------------------------
# End-to-end lifecycle
# ---------------------------------------------------------------------------

class TestGateLifecycle:
    @pytest.mark.asyncio
    async def test_gate_lifecycle(self, provider):
        """denied → queued → approved → works → revoked → denied again."""
        client = _client(gated=True)
        request = _request()
        storage = provider.client_access_storage

        # 1. First attempt is denied and queued.
        denied = await provider._enforce_access_gate(
            request, client, USER_ID, REDIRECT_URI, STATE
        )
        assert denied is not None
        queue = await storage.list_pending(CLIENT_UID)
        assert [r.user_id for r in queue] == [USER_ID]

        # 2. An admin approves.
        await storage.approve(USER_ID, CLIENT_UID, granted_by=1)

        # 3. Authorization now proceeds.
        assert await provider._enforce_access_gate(
            request, client, USER_ID, REDIRECT_URI, STATE
        ) is None

        # 4. Deactivation cascades.
        provider.grant_storage = _Grants()
        provider.refresh_token_storage = _RefreshTokens(
            [_refresh("rt-live", CLIENT_UID)]
        )
        provider.access_token_storage = _AccessTokens(
            {
                "oauth2:jti:live": {
                    "jti": "live", "user_id": USER_ID,
                    "client_id": CLIENT_UID, "revoked": False,
                }
            }
        )
        assert await storage.revoke(USER_ID, CLIENT_UID) is True
        cascade = await provider.cascade_access_revocation(USER_ID, CLIENT_UID)
        assert cascade == {
            "grants": 1, "refresh_chains": 1, "access_tokens": 1
        }

        # 5. A new authorize is denied again.
        assert await provider._enforce_access_gate(
            request, client, USER_ID, REDIRECT_URI, STATE
        ) is not None
        # And the revoked row was not silently re-queued as pending.
        assert (await storage.get(USER_ID, CLIENT_UID)).status == STATUS_REVOKED
