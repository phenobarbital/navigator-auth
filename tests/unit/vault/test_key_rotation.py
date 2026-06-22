"""Unit tests for navigator_session.vault.key_rotation module."""
import struct
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from navigator_session.vault.crypto import encrypt_for_db, decrypt_for_db
from navigator_session.vault.key_rotation import rotate_master_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key_v1() -> bytes:
    return b"\x00" * 32


@pytest.fixture
def master_key_v2() -> bytes:
    return b"\x01" * 32


@pytest.fixture
def master_keys(master_key_v1, master_key_v2) -> dict[int, bytes]:
    return {1: master_key_v1, 2: master_key_v2}


def _make_row(row_id, user_id, key, ciphertext_db, key_version):
    """Create a dict-like mock row mimicking an asyncpg Record."""
    data = {
        "id": row_id,
        "user_id": user_id,
        "key": key,
        "ciphertext_db": ciphertext_db,
        "key_version": key_version,
    }
    row = MagicMock()
    row.__getitem__ = lambda self, k: data[k]
    row.get = lambda k, default=None: data.get(k, default)
    return row


def _make_mock_pool(rows_batches: list[list]):
    """Create a mock pool that yields rows in batches via fetch calls.

    rows_batches: list of lists, each inner list is returned by successive fetch() calls.
    """
    pool = AsyncMock()
    conn = AsyncMock()

    # fetch returns batches sequentially, then empty list
    fetch_side_effects = list(rows_batches) + [[]]
    conn.fetch = AsyncMock(side_effect=fetch_side_effects)
    conn.execute = AsyncMock()
    conn.fetchval = AsyncMock(return_value=0)

    # Context manager for transaction
    tx = AsyncMock()
    tx.__aenter__ = AsyncMock(return_value=tx)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)

    # Context manager for pool.acquire()
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=pool_ctx)

    return pool, conn


# ---------------------------------------------------------------------------
# Stats dict structure
# ---------------------------------------------------------------------------

class TestRotateReturnsStats:
    @pytest.mark.asyncio
    async def test_returns_stats_dict(self, master_keys):
        """Rotation returns a dict with total/rotated/errors/skipped."""
        pool, _ = _make_mock_pool([])
        stats = await rotate_master_key(pool, 1, 2, master_keys)
        assert isinstance(stats, dict)
        assert "total" in stats
        assert "rotated" in stats
        assert "errors" in stats
        assert "skipped" in stats

    @pytest.mark.asyncio
    async def test_no_rows_returns_zeroes(self, master_keys):
        """No secrets to rotate returns all zeroes."""
        pool, _ = _make_mock_pool([])
        stats = await rotate_master_key(pool, 1, 2, master_keys)
        assert stats["total"] == 0
        assert stats["rotated"] == 0
        assert stats["errors"] == 0
        assert stats["skipped"] == 0


# ---------------------------------------------------------------------------
# Rotation logic
# ---------------------------------------------------------------------------

class TestRotationLogic:
    @pytest.mark.asyncio
    async def test_re_encrypts_secrets(self, master_keys, master_key_v1, master_key_v2):
        """Secrets encrypted with v1 are re-encrypted with v2."""
        ct_v1 = encrypt_for_db(b"my-secret", key_id=1, master_key=master_key_v1)
        row = _make_row("uuid-1", 42, "api_key", ct_v1, 1)
        pool, conn = _make_mock_pool([[row]])

        stats = await rotate_master_key(pool, 1, 2, master_keys)

        assert stats["rotated"] == 1
        assert stats["total"] == 1
        assert stats["errors"] == 0

        # Verify execute was called to update the row
        update_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "UPDATE" in str(c.args[0]).upper()
        ]
        assert len(update_calls) >= 1

    @pytest.mark.asyncio
    async def test_rotated_ciphertext_decrypts_with_new_key(
        self, master_keys, master_key_v1, master_key_v2
    ):
        """After rotation, the new ciphertext is decryptable with new key version."""
        original = b"my-secret-data"
        ct_v1 = encrypt_for_db(original, key_id=1, master_key=master_key_v1)
        row = _make_row("uuid-1", 42, "token", ct_v1, 1)
        pool, conn = _make_mock_pool([[row]])

        await rotate_master_key(pool, 1, 2, master_keys)

        # Extract the new ciphertext from the UPDATE call
        update_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "UPDATE" in str(c.args[0]).upper()
        ]
        assert len(update_calls) >= 1
        # The new ciphertext should be in the positional args
        new_ct = None
        for c in update_calls:
            for arg in c.args[1:]:
                if isinstance(arg, bytes) and len(arg) > 14:
                    new_ct = arg
                    break
            if new_ct:
                break
        assert new_ct is not None
        # Verify key_id is 2
        key_id = struct.unpack("!H", new_ct[:2])[0]
        assert key_id == 2
        # Verify it decrypts to original
        decrypted = decrypt_for_db(new_ct, master_keys)
        assert decrypted == original

    @pytest.mark.asyncio
    async def test_multiple_secrets_rotated(self, master_keys, master_key_v1):
        """Multiple secrets in one batch are all rotated."""
        rows = []
        for i in range(5):
            ct = encrypt_for_db(f"secret-{i}".encode(), key_id=1, master_key=master_key_v1)
            rows.append(_make_row(f"uuid-{i}", 42, f"key_{i}", ct, 1))

        pool, conn = _make_mock_pool([rows])
        stats = await rotate_master_key(pool, 1, 2, master_keys)

        assert stats["total"] == 5
        assert stats["rotated"] == 5
        assert stats["errors"] == 0


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

class TestIdempotency:
    @pytest.mark.asyncio
    async def test_skips_already_rotated(self, master_keys, master_key_v2):
        """Secrets already at new_key_id are skipped."""
        ct_v2 = encrypt_for_db(b"already-rotated", key_id=2, master_key=master_key_v2)
        row = _make_row("uuid-1", 42, "token", ct_v2, 2)

        # The query should filter by key_version = old_key_id,
        # so already-rotated rows should not appear.
        # We simulate this by returning no rows (DB filters them).
        pool, _ = _make_mock_pool([])
        stats = await rotate_master_key(pool, 1, 2, master_keys)

        assert stats["total"] == 0
        assert stats["skipped"] == 0
        assert stats["rotated"] == 0


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

class TestBatchProcessing:
    @pytest.mark.asyncio
    async def test_processes_in_batches(self, master_keys, master_key_v1):
        """Secrets are fetched and processed in configurable batch sizes."""
        batch1 = []
        for i in range(3):
            ct = encrypt_for_db(f"secret-{i}".encode(), key_id=1, master_key=master_key_v1)
            batch1.append(_make_row(f"uuid-{i}", 42, f"key_{i}", ct, 1))

        batch2 = []
        for i in range(3, 5):
            ct = encrypt_for_db(f"secret-{i}".encode(), key_id=1, master_key=master_key_v1)
            batch2.append(_make_row(f"uuid-{i}", 42, f"key_{i}", ct, 1))

        pool, conn = _make_mock_pool([batch1, batch2])
        stats = await rotate_master_key(pool, 1, 2, master_keys, batch_size=3)

        assert stats["total"] == 5
        assert stats["rotated"] == 5

    @pytest.mark.asyncio
    async def test_custom_batch_size(self, master_keys, master_key_v1):
        """batch_size parameter controls fetch size."""
        pool, conn = _make_mock_pool([])
        await rotate_master_key(pool, 1, 2, master_keys, batch_size=50)

        # Verify the batch_size was used in the query (LIMIT parameter)
        fetch_calls = conn.fetch.call_args_list
        assert len(fetch_calls) >= 1
        # Check that 50 appears in the args (as LIMIT)
        first_call_args = fetch_calls[0].args
        assert 50 in first_call_args or any(
            a == 50 for a in first_call_args
        )


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

class TestAuditLogging:
    @pytest.mark.asyncio
    async def test_audit_entry_for_rotated_secret(self, master_keys, master_key_v1):
        """Each rotated secret gets an audit log entry with operation='rotate'."""
        ct = encrypt_for_db(b"secret", key_id=1, master_key=master_key_v1)
        row = _make_row("uuid-1", 42, "api_key", ct, 1)
        pool, conn = _make_mock_pool([[row]])

        await rotate_master_key(pool, 1, 2, master_keys)

        # Check for audit INSERT calls
        audit_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "vault_audit" in str(c.args[0]).lower()
        ]
        assert len(audit_calls) >= 1
        # Verify 'rotate' operation is in the args
        audit_args = audit_calls[0].args
        assert any(a == "rotate" for a in audit_args)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_per_row_error_continues(self, master_keys):
        """A decryption error on one row doesn't abort the rotation."""
        # First row: corrupted ciphertext
        bad_ct = b"\x00\x01" + b"\x00" * 30  # invalid: key_id=1, garbage
        bad_row = _make_row("uuid-bad", 42, "bad_key", bad_ct, 1)

        # Second row: valid
        good_ct = encrypt_for_db(b"good-secret", key_id=1, master_key=master_keys[1])
        good_row = _make_row("uuid-good", 42, "good_key", good_ct, 1)

        pool, conn = _make_mock_pool([[bad_row, good_row]])
        stats = await rotate_master_key(pool, 1, 2, master_keys)

        assert stats["total"] == 2
        assert stats["errors"] == 1
        assert stats["rotated"] == 1

    @pytest.mark.asyncio
    async def test_validates_key_ids_in_master_keys(self, master_key_v1):
        """Raises KeyError if new_key_id is not in master_keys."""
        pool, _ = _make_mock_pool([])
        with pytest.raises(KeyError):
            await rotate_master_key(
                pool, 1, 99, {1: master_key_v1}
            )

    @pytest.mark.asyncio
    async def test_validates_old_key_in_master_keys(self, master_key_v2):
        """Raises KeyError if old_key_id is not in master_keys."""
        pool, _ = _make_mock_pool([])
        with pytest.raises(KeyError):
            await rotate_master_key(
                pool, 1, 2, {2: master_key_v2}
            )
