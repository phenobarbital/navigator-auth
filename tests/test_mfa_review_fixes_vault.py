"""FEAT-106 review fix #2: dedicated MFA secret storage and vault rotation."""

import os
import secrets
import tomllib
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from navigator_session.vault import KeyRing, rotate_master_key
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets import UserVaultTarget

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.migrations import MFA_TABLES, ensure_mfa_tables
from navigator_auth.mfa.store import MfaChallengeStore
from navigator_auth.mfa.targets import MfaSecretTarget, factory
from navigator_auth.mfa.totp import TOTP_VAULT_KEY, TOTPProvider, mfa_seed_context
from navigator_auth.mfa.types import PROVIDER_TOTP
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY, setup_vault_tables
from tests.fixtures.mfa import frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory  # noqa: F401

SECRETS = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"
VAULT = "auth.user_vault_secrets"
ROOT = Path(__file__).resolve().parents[1]


def test_mfa_secret_target_context_matches_seed():
    """The target rebuilds the exact AAD context used to seal a TOTP seed."""
    target = MfaSecretTarget(object())
    row = VaultRow(
        ref="r",
        pk=None,
        identity={"user_id": "42", "provider": PROVIDER_TOTP, "key": TOTP_VAULT_KEY},
        values={},
    )
    assert target.context_for(row, "ciphertext_db") == mfa_seed_context(42)


def test_mfa_target_factory_requires_pool():
    """The entry-point factory is absent when authdb is not configured."""
    assert factory({}) is None
    assert isinstance(factory({"db_pool": object()}), MfaSecretTarget)


def test_vault_target_entry_point_declared():
    """The MFA target is registered and its relation is part of readiness checks."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    entry_points = data["project"]["entry-points"]["navigator_session.vault_targets"]
    assert entry_points["mfa"] == "navigator_auth.mfa.targets:factory"
    assert "user_mfa_secrets" in MFA_TABLES


async def _fetch_rows(pool, sql, *args):
    async with await pool.acquire() as conn:
        return [dict(row) for row in (await conn.fetch_all(sql, *args) or [])]


@pytest.mark.asyncio
async def test_mfa_secrets_migration_moves_rows(mfa_db, mfa_user_factory):
    """AC8: migration moves bytes atomically, is idempotent, and rolls back on delete failure."""
    await setup_vault_tables(mfa_db)
    user = await mfa_user_factory()
    active_id, deleted_id = uuid.uuid4(), uuid.uuid4()
    active_blob, deleted_blob = b"active-mfa-ciphertext", b"deleted-mfa-ciphertext"

    async with await mfa_db.acquire() as conn:
        await conn.fetchval(
            f"INSERT INTO {VAULT} (id, user_id, key, ciphertext_db, key_version) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            active_id,
            user["user_id"],
            "mfa:totp",
            active_blob,
            41001,
        )
        await conn.fetchval(
            f"INSERT INTO {VAULT} (id, user_id, key, ciphertext_db, key_version, deleted_at) VALUES ($1, $2, $3, $4, $5, now()) RETURNING id",
            deleted_id,
            user["user_id"],
            "mfa:totp-old",
            deleted_blob,
            41002,
        )
        await conn.fetchval(
            f"INSERT INTO {VAULT} (user_id, key, ciphertext_db, key_version) VALUES ($1, $2, $3, $4) RETURNING id",
            user["user_id"],
            "jira:token",
            b"ordinary-ciphertext",
            41003,
        )

    source_rows = await _fetch_rows(
        mfa_db,
        f"SELECT id, key, ciphertext_db, key_version, created_at, updated_at, deleted_at FROM {VAULT} WHERE id = ANY($1::uuid[]) ORDER BY id",
        [active_id, deleted_id],
    )
    await ensure_mfa_tables(mfa_db)
    moved = await _fetch_rows(
        mfa_db,
        f"SELECT id, provider, key, ciphertext_db, key_version, created_at, updated_at, deleted_at FROM {SECRETS} WHERE id = ANY($1::uuid[]) ORDER BY id",
        [active_id, deleted_id],
    )
    assert len(moved) == 2
    assert {row["id"] for row in moved} == {active_id, deleted_id}
    assert all(row["provider"] == PROVIDER_TOTP for row in moved)
    assert {row["ciphertext_db"] for row in moved} == {active_blob, deleted_blob}
    assert {row["key_version"] for row in moved} == {41001, 41002}
    assert [
        {
            key: row[key]
            for key in ("id", "key", "ciphertext_db", "key_version", "created_at", "updated_at", "deleted_at")
        }
        for row in moved
    ] == source_rows
    assert await _fetch_rows(mfa_db, f"SELECT id FROM {VAULT} WHERE key LIKE 'mfa:%'") == []
    ordinary = await _fetch_rows(mfa_db, f"SELECT key, ciphertext_db FROM {VAULT} WHERE user_id = $1", user["user_id"])
    assert ordinary == [{"key": "jira:token", "ciphertext_db": b"ordinary-ciphertext"}]

    await ensure_mfa_tables(mfa_db)
    moved_again = await _fetch_rows(
        mfa_db, f"SELECT id, ciphertext_db FROM {SECRETS} WHERE id = ANY($1::uuid[])", [active_id, deleted_id]
    )
    assert len(moved_again) == 2
    assert {row["ciphertext_db"] for row in moved_again} == {active_blob, deleted_blob}

    trigger_suffix = secrets.token_hex(6)
    function_name = f"mfa_migration_failure_{trigger_suffix}"
    trigger_name = f"mfa_migration_failure_trigger_{trigger_suffix}"
    failed_id = uuid.uuid4()
    try:
        async with await mfa_db.acquire() as conn:
            await conn.fetchval(
                f"INSERT INTO {VAULT} (id, user_id, key, ciphertext_db, key_version) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                failed_id,
                user["user_id"],
                "mfa:rollback",
                b"rollback-ciphertext",
                41004,
            )
            await conn.execute(
                f"CREATE OR REPLACE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'blocked MFA delete'; END; $$"
            )
            await conn.execute(
                f"CREATE TRIGGER {trigger_name} BEFORE DELETE ON {VAULT} FOR EACH ROW WHEN (OLD.key LIKE 'mfa:%') EXECUTE FUNCTION {function_name}()"
            )
        with pytest.raises(MfaStorageError):
            await ensure_mfa_tables(mfa_db)
        assert await _fetch_rows(mfa_db, f"SELECT id, ciphertext_db FROM {VAULT} WHERE id = $1", failed_id) == [
            {"id": failed_id, "ciphertext_db": b"rollback-ciphertext"}
        ]
        assert await _fetch_rows(mfa_db, f"SELECT id FROM {SECRETS} WHERE id = $1", failed_id) == []
    finally:
        async with await mfa_db.acquire() as conn:
            await conn.execute(f"DROP TRIGGER IF EXISTS {trigger_name} ON {VAULT}")
            await conn.execute(f"DROP FUNCTION IF EXISTS {function_name}()")
        await ensure_mfa_tables(mfa_db)


@pytest.mark.asyncio
async def test_rotate_master_key_rotates_mfa_seeds(
    mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock
):
    """AC7: a rotated seed verifies with the new key and no longer needs the old key."""
    await setup_vault_tables(mfa_db)
    user = await mfa_user_factory()
    old_id = 40000 + secrets.randbelow(10000)
    new_id = 50000 + secrets.randbelow(10000)
    old_key, new_key = os.urandom(32), os.urandom(32)
    old_ring = KeyRing({old_id: old_key}, old_id)
    provider = TOTPProvider(
        app={VAULT_KEYRING_APP_KEY: old_ring},
        db_pool=mfa_db,
        store=MfaChallengeStore(mfa_redis_pool, mfa_secret),
        clock=frozen_totp_clock,
    )
    seed = b"01234567890123456789"
    async with await mfa_db.acquire() as conn:
        await provider._install_seed(conn, user["user_id"], seed)

    # navigator_session's PostgresTarget.transaction() calls ``conn.transaction().start()`` (asyncpg API);
    # asyncdb's driver ``transaction()`` is an awaitable that already started it. Rotate through the raw
    # asyncpg pool the asyncdb pool wraps, which the library supports.
    raw_pool = getattr(mfa_db, "_pool", mfa_db)
    target = MfaSecretTarget(raw_pool)
    stats = await rotate_master_key(
        [UserVaultTarget(raw_pool), target],
        old_id,
        new_id,
        KeyRing({old_id: old_key, new_id: new_key}, new_id),
    )
    assert stats[target.name]["errors"] == 0
    assert stats[target.name]["rotated"] == 1
    assert await _fetch_rows(
        mfa_db, f"SELECT key_version FROM {SECRETS} WHERE user_id = $1 AND deleted_at IS NULL", user["user_id"]
    ) == [{"key_version": new_id}]

    new_provider = TOTPProvider(
        app={VAULT_KEYRING_APP_KEY: KeyRing({new_id: new_key}, new_id)},
        db_pool=mfa_db,
        store=MfaChallengeStore(mfa_redis_pool, mfa_secret),
        clock=frozen_totp_clock,
    )
    code = TOTP(seed, 6, SHA1(), 30).generate(frozen_totp_clock()).decode("ascii")
    assert await new_provider.verify(None, user, code) is True
