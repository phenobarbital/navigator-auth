"""FEAT-101 TASK-88 — PasskeyStore against live Postgres (skipped when unavailable)."""

import secrets

import pytest
import pytest_asyncio

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, default_dsn
from navigator_auth.passkey.migrations import ensure_passkey_tables
from navigator_auth.passkey.store import PasskeyStore
from navigator_auth.passkey.types import StoredCredential

pytestmark = pytest.mark.asyncio

USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"


@pytest_asyncio.fixture
async def pool():
    """asyncdb pool on live Postgres; skips when unavailable."""
    asyncdb = pytest.importorskip("asyncdb")
    try:
        p = asyncdb.AsyncPool("pg", dsn=default_dsn)
        await p.connect()
        await ensure_passkey_tables(p)
    except Exception as err:  # pylint: disable=W0703
        pytest.skip(f"Postgres unavailable: {err}")
    yield p
    await p.close()


@pytest_asyncio.fixture
async def users(pool):
    """Two throwaway users; removed (cascade) on teardown."""
    ids = []
    async with await pool.acquire() as conn:
        for name in ("pk_store_a", "pk_store_b"):
            await conn.execute(f"DELETE FROM {USERS} WHERE username = '{name}'")
            await conn.execute(
                f"INSERT INTO {USERS} (username, password, email, first_name, last_name, "
                f"is_active, is_superuser, is_new, is_staff) VALUES ('{name}', 'x', "
                f"'{name}@example.com', 'T', 'T', true, false, false, false)"
            )
            ids.append(await conn.fetchval(f"SELECT user_id FROM {USERS} WHERE username = '{name}'"))
    yield ids
    async with await pool.acquire() as conn:
        for name in ("pk_store_a", "pk_store_b"):
            await conn.execute(f"DELETE FROM {USERS} WHERE username = '{name}'")


def _cred(user_id, rp_id="a.com", **kw):
    data = dict(
        credential_id=secrets.token_bytes(16),
        user_id=user_id,
        rp_id=rp_id,
        public_key=b"pk",
        sign_count=1,
        transports=["internal"],
        aaguid="00000000-0000-0000-0000-000000000001",
        device_type="multi_device",
        backed_up=True,
        label="Laptop",
    )
    data.update(kw)
    return StoredCredential(**data)


async def test_store_crud(pool, users):
    """Insert, get, list by user and RP, update_usage, rename, delete; handles stable and unique."""
    ua, ub = users
    store = PasskeyStore(pool)
    c1, c2 = _cred(ua), _cred(ua, rp_id="b.com")
    await store.save_credential(c1)
    await store.save_credential(c2)

    got = await store.get_credential(c1.credential_id)
    assert got.user_id == ua and got.aaguid == c1.aaguid and got.transports == ["internal"]
    assert got.created_at is not None and got.last_used_at is None
    assert await store.get_credential(b"missing") is None

    assert len(await store.list_credentials(ua)) == 2
    only = await store.list_credentials(ua, "a.com")
    assert [c.credential_id for c in only] == [c1.credential_id]
    assert await store.count_credentials(ua) == 2

    await store.update_usage(c1.credential_id, sign_count=9, backed_up=False)
    got = await store.get_credential(c1.credential_id)
    assert got.sign_count == 9 and got.backed_up is False and got.last_used_at is not None

    # ownership boundary
    assert await store.rename_credential(ub, c1.credential_id, "x") is False
    assert await store.delete_credential(ub, c1.credential_id) is False
    assert await store.rename_credential(ua, c1.credential_id, "Phone") is True
    assert (await store.get_credential(c1.credential_id)).label == "Phone"
    assert await store.delete_credential(ua, c1.credential_id) is True
    assert await store.count_credentials(ua) == 1


async def test_handles_stable_and_unique(pool, users):
    """Same (user, rp) → same 32-byte handle; other RP/user → different."""
    ua, ub = users
    store = PasskeyStore(pool)
    assert await store.get_handle(ua, "a.com") is None
    h1 = await store.get_or_create_handle(ua, "a.com")
    assert len(h1) == 32
    assert await store.get_or_create_handle(ua, "a.com") == h1
    assert await store.get_handle(ua, "a.com") == h1
    assert await store.get_or_create_handle(ua, "b.com") != h1
    assert await store.get_or_create_handle(ub, "a.com") != h1


async def test_update_usage_never_lowers_sign_count(pool, users):
    store = PasskeyStore(pool)
    c = _cred(users[0], sign_count=0)
    await store.save_credential(c)
    await store.update_usage(c.credential_id, sign_count=7, backed_up=False)
    await store.update_usage(c.credential_id, sign_count=3, backed_up=False)
    assert (await store.get_credential(c.credential_id)).sign_count == 7


async def test_delete_keep_last_is_atomic(pool, users):
    store = PasskeyStore(pool)
    c1, c2 = _cred(users[0]), _cred(users[0])
    await store.save_credential(c1)
    await store.save_credential(c2)
    assert await store.delete_credential(users[0], c1.credential_id, keep_last=True) is True
    assert await store.delete_credential(users[0], c2.credential_id, keep_last=True) is False
    assert await store.count_credentials(users[0]) == 1
