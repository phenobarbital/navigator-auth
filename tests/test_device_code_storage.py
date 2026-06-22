"""Unit tests for FEAT-094 TASK-032.

Tests:
  test_user_code_alphabet_entropy   — generate_user_code uses the unambiguous
                                       alphabet, configured length.
  test_poll_decision_state_machine  — poll_decision returns the correct state
                                       across interval/expiry/status.
  test_device_storage_roundtrip     — MemoryDeviceCodeStorage
                                       save/get_by_device_code/get_by_user_code/
                                       update/delete.
"""

import secrets
from datetime import datetime, timedelta

import pytest

from navigator_auth.backends.oauth2.devicecode import (
    DEFAULT_USER_CODE_ALPHABET,
    DEFAULT_USER_CODE_LENGTH,
    SLOW_DOWN,
    AUTHORIZATION_PENDING,
    ACCESS_DENIED,
    EXPIRED_TOKEN,
    APPROVED,
    generate_user_code,
    poll_decision,
)
from navigator_auth.backends.oauth2.models import DeviceCodeStatus, OauthDeviceCode
from navigator_auth.backends.oauth2.code_backend import MemoryDeviceCodeStorage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dc(**kwargs) -> OauthDeviceCode:
    """Create a minimal pending OauthDeviceCode record."""
    now = datetime.now()
    defaults = dict(
        device_code=secrets.token_urlsafe(32),
        user_code=generate_user_code(),
        client_id="public_test_client",
        scopes=["default"],
        status=DeviceCodeStatus.PENDING,
        interval=5,
        issued_at=now,
        expires_at=now + timedelta(seconds=600),
    )
    defaults.update(kwargs)
    return OauthDeviceCode(**defaults)


# ---------------------------------------------------------------------------
# test_user_code_alphabet_entropy
# ---------------------------------------------------------------------------

class TestGenerateUserCode:
    """Tests for generate_user_code helper."""

    def test_default_length(self):
        code = generate_user_code()
        assert len(code) == DEFAULT_USER_CODE_LENGTH

    def test_custom_length(self):
        code = generate_user_code(length=12)
        assert len(code) == 12

    def test_only_allowed_chars(self):
        for _ in range(200):
            code = generate_user_code()
            for ch in code:
                assert ch in DEFAULT_USER_CODE_ALPHABET, (
                    f"Character {ch!r} not in alphabet"
                )

    def test_no_vowels(self):
        """The default alphabet excludes A E I O U."""
        for _ in range(200):
            code = generate_user_code()
            for ch in code:
                assert ch not in "AEIOU", f"Vowel {ch!r} found in code {code!r}"

    def test_no_visually_confusable(self):
        """No 0 (zero) or 1 (one) — common confusables."""
        for _ in range(200):
            code = generate_user_code()
            assert "0" not in code
            assert "1" not in code

    def test_custom_alphabet(self):
        code = generate_user_code(length=4, alphabet="ABCD")
        assert len(code) == 4
        for ch in code:
            assert ch in "ABCD"

    def test_entropy_not_constant(self):
        """100 generated codes should not all be identical."""
        codes = {generate_user_code() for _ in range(100)}
        assert len(codes) > 1, "generate_user_code appears to return a constant value"

    def test_empty_alphabet_raises(self):
        with pytest.raises(ValueError):
            generate_user_code(alphabet="")

    def test_length_zero_raises(self):
        with pytest.raises(ValueError):
            generate_user_code(length=0)


# ---------------------------------------------------------------------------
# test_poll_decision_state_machine
# ---------------------------------------------------------------------------

class TestPollDecision:
    """Tests for poll_decision pure state machine."""

    def _now(self, offset_seconds: int = 0) -> datetime:
        return datetime.now() + timedelta(seconds=offset_seconds)

    def test_pending_returns_authorization_pending(self):
        dc = _make_dc(last_polled_at=None)
        result = poll_decision(dc, self._now())
        assert result == AUTHORIZATION_PENDING

    def test_approved_returns_approved(self):
        dc = _make_dc(status=DeviceCodeStatus.APPROVED, last_polled_at=None)
        result = poll_decision(dc, self._now())
        assert result == APPROVED

    def test_denied_returns_access_denied(self):
        dc = _make_dc(status=DeviceCodeStatus.DENIED, last_polled_at=None)
        result = poll_decision(dc, self._now())
        assert result == ACCESS_DENIED

    def test_expired_returns_expired_token(self):
        dc = _make_dc(expires_at=self._now(-1))  # expired 1 second ago
        result = poll_decision(dc, self._now())
        assert result == EXPIRED_TOKEN

    def test_consumed_returns_expired_token(self):
        """Consumed device codes are treated as expired (single-use guard)."""
        dc = _make_dc(status=DeviceCodeStatus.CONSUMED, last_polled_at=None)
        result = poll_decision(dc, self._now())
        assert result == EXPIRED_TOKEN

    def test_too_soon_returns_slow_down(self):
        """Polling within interval → slow_down."""
        now = self._now()
        # last_polled_at = 2 seconds ago, interval = 5 → too soon
        last_polled = now - timedelta(seconds=2)
        dc = _make_dc(interval=5, last_polled_at=last_polled)
        result = poll_decision(dc, now)
        assert result == SLOW_DOWN

    def test_after_interval_not_slow_down(self):
        """Polling after interval has passed → not slow_down."""
        now = self._now()
        # last_polled_at = 10 seconds ago, interval = 5 → ok
        last_polled = now - timedelta(seconds=10)
        dc = _make_dc(interval=5, last_polled_at=last_polled)
        result = poll_decision(dc, now)
        assert result == AUTHORIZATION_PENDING  # still pending but not slow_down

    def test_expiry_takes_priority_over_slow_down(self):
        """Expired code reports expired_token even if within interval."""
        now = self._now()
        last_polled = now - timedelta(seconds=1)  # 1 s ago (< 5 s interval)
        dc = _make_dc(
            interval=5,
            last_polled_at=last_polled,
            expires_at=now - timedelta(seconds=1),  # expired
        )
        result = poll_decision(dc, now)
        assert result == EXPIRED_TOKEN

    def test_approved_after_interval(self):
        """Approved + sufficient interval → approved (not slow_down)."""
        now = self._now()
        last_polled = now - timedelta(seconds=10)
        dc = _make_dc(status=DeviceCodeStatus.APPROVED, interval=5, last_polled_at=last_polled)
        result = poll_decision(dc, now)
        assert result == APPROVED

    def test_slow_down_on_approved_when_too_soon(self):
        """Polling too soon on an APPROVED code still triggers slow_down."""
        now = self._now()
        last_polled = now - timedelta(seconds=2)
        dc = _make_dc(status=DeviceCodeStatus.APPROVED, interval=5, last_polled_at=last_polled)
        result = poll_decision(dc, now)
        assert result == SLOW_DOWN


# ---------------------------------------------------------------------------
# test_device_storage_roundtrip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_storage_roundtrip():
    """MemoryDeviceCodeStorage: save / get_by_device_code / get_by_user_code /
    update / delete roundtrip."""
    store = MemoryDeviceCodeStorage()
    dc = _make_dc()

    # save
    assert await store.save(dc) is True

    # get_by_device_code
    retrieved = await store.get_by_device_code(dc.device_code)
    assert retrieved is not None
    assert retrieved.device_code == dc.device_code
    assert retrieved.user_code == dc.user_code
    assert retrieved.client_id == dc.client_id

    # get_by_user_code (case-insensitive normalisation)
    retrieved2 = await store.get_by_user_code(dc.user_code.lower())
    assert retrieved2 is not None
    assert retrieved2.device_code == dc.device_code

    # update (change status to APPROVED)
    dc.status = DeviceCodeStatus.APPROVED
    dc.user_id = 42
    dc.granted_scopes = ["default"]
    assert await store.update(dc) is True

    updated = await store.get_by_device_code(dc.device_code)
    assert updated.status == DeviceCodeStatus.APPROVED
    assert updated.user_id == 42

    # delete
    assert await store.delete(dc.device_code) is True
    assert await store.get_by_device_code(dc.device_code) is None
    # user_code index also cleaned up
    assert await store.get_by_user_code(dc.user_code) is None


@pytest.mark.asyncio
async def test_device_storage_missing_returns_none():
    """Lookups for non-existent keys return None."""
    store = MemoryDeviceCodeStorage()
    assert await store.get_by_device_code("does_not_exist") is None
    assert await store.get_by_user_code("XXXXXXXX") is None


@pytest.mark.asyncio
async def test_device_storage_update_returns_false_for_missing():
    """update() returns False for an unknown device_code."""
    store = MemoryDeviceCodeStorage()
    dc = _make_dc()
    result = await store.update(dc)
    assert result is False


@pytest.mark.asyncio
async def test_device_storage_delete_returns_false_for_missing():
    """delete() returns False for an unknown device_code."""
    store = MemoryDeviceCodeStorage()
    result = await store.delete("nonexistent")
    assert result is False


@pytest.mark.asyncio
async def test_device_storage_user_code_normalization():
    """get_by_user_code strips hyphens and is case-insensitive."""
    store = MemoryDeviceCodeStorage()
    dc = _make_dc(user_code="BCDF")
    await store.save(dc)

    # Hyphen-stripped lowercase
    assert await store.get_by_user_code("bc-df") is not None
    # Mixed case
    assert await store.get_by_user_code("BCDf") is not None
