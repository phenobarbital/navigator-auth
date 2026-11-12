"""refresh_linked_identity: one refresh per account at a time, re-read under the guard."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from navigator_auth.backends.external import ExternalAuth
from navigator_auth.exceptions import ConfigError, UserNotFound
from navigator_auth.identity.refresh import refresh_linked_identity
from navigator_auth.identity.types import TokenResponse

LEEWAY = 60


class FakeBackend:
    """Borrows ExternalAuth's real per-account guard; the refresh grant is faked.

    Each instance has its own in-process guard map, like a separate worker.
    """

    refresh_guard = ExternalAuth._refresh_guard
    _service_name = "azure"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def refresh_identity_tokens(self, refresh_token: str) -> TokenResponse:
        self.calls.append(refresh_token)
        await asyncio.sleep(0.05)  # the provider round-trip other callers queue behind
        n = len(self.calls)
        return TokenResponse(access_token=f"at-{n}", refresh_token=f"rt-{n}", expires_in=3600)


class FakeStore:
    """The shared database: one identity row plus the cross-process lock table.

    Every read returns a fresh copy of what is stored. Backends that share one
    FakeStore behave like workers sharing one Postgres.
    """

    def __init__(self, token: TokenResponse, *, cross_process_lock: bool = True) -> None:
        self.token = token
        self.refreshed_at = datetime(2026, 11, 11, 13, 0, tzinfo=timezone.utc)
        self.exists = True
        self.enabled = True
        self.writes = 0
        self.cross_process_lock = cross_process_lock
        self.locks: dict[tuple, asyncio.Lock] = {}
        self.lock_keys: list[tuple] = []

    @asynccontextmanager
    async def refresh_lock(self, provider, user_id, provider_user_id):
        key = (provider, user_id, provider_user_id)
        self.lock_keys.append(key)
        if not self.cross_process_lock:
            yield
            return
        async with self.locks.setdefault(key, asyncio.Lock()):
            yield

    def row(self) -> SimpleNamespace:
        return SimpleNamespace(
            identity_id="row-1", user_id=35, auth_provider="azure", provider_user_id="acct",
            refreshed_at=self.refreshed_at, enabled=self.enabled, token=self.token,
        )

    async def get_one(self, user_id, identity_id):
        await asyncio.sleep(0)
        return self.row() if self.exists else None

    def decrypt_credential(self, row) -> TokenResponse:
        return row.token

    async def update_tokens(self, row, token: TokenResponse):
        self.token = token
        self.refreshed_at = datetime.now(timezone.utc)
        self.writes += 1
        return self.row()


def _expiring() -> TokenResponse:
    return TokenResponse(
        access_token="at-old", refresh_token="rt-old",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=10),
    )


def _fresh() -> TokenResponse:
    return TokenResponse(access_token="at-old", refresh_token="rt-old", expires_in=3600)


@pytest.mark.asyncio
async def test_concurrent_callers_refresh_once():
    """A double click: both callers read the expiring row, only one spends the refresh token."""
    store, backend = FakeStore(_expiring()), FakeBackend()
    first_read = store.row()
    results = await asyncio.gather(
        refresh_linked_identity(store, backend, first_read, leeway=LEEWAY),
        refresh_linked_identity(store, backend, first_read, leeway=LEEWAY),
    )
    assert backend.calls == ["rt-old"]
    assert store.writes == 1
    assert [token.access_token for _, token in results] == ["at-1", "at-1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cross_process_lock, provider_calls", [(True, 1), (False, 2)])
async def test_two_workers_refresh_once(cross_process_lock, provider_calls):
    """Two workers (separate in-process guards) share one database.

    With the store's cross-process lock they spend the refresh token once;
    the in-process guard alone cannot stop the second worker.
    """
    store = FakeStore(_expiring(), cross_process_lock=cross_process_lock)
    worker_a, worker_b = FakeBackend(), FakeBackend()
    first_read = store.row()
    await asyncio.gather(
        refresh_linked_identity(store, worker_a, first_read, leeway=LEEWAY),
        refresh_linked_identity(store, worker_b, first_read, leeway=LEEWAY),
    )
    assert len(worker_a.calls) + len(worker_b.calls) == provider_calls
    # same key as the session-refresh path: provider, str(user), str(account)
    assert set(store.lock_keys) == {("azure", "35", "acct")}


@pytest.mark.asyncio
async def test_concurrent_renews_refresh_once():
    """Explicit renew (no leeway): the one that waited returns the renewal it waited behind."""
    store, backend = FakeStore(_fresh()), FakeBackend()
    first_read = store.row()
    results = await asyncio.gather(
        refresh_linked_identity(store, backend, first_read),
        refresh_linked_identity(store, backend, first_read),
    )
    assert backend.calls == ["rt-old"]
    assert [token.access_token for _, token in results] == ["at-1", "at-1"]


@pytest.mark.asyncio
async def test_renew_refreshes_a_credential_that_is_not_expiring():
    store, backend = FakeStore(_fresh()), FakeBackend()
    _, token = await refresh_linked_identity(store, backend, store.row())
    assert backend.calls == ["rt-old"] and token.access_token == "at-1"


@pytest.mark.asyncio
async def test_fresh_credential_is_not_refreshed():
    store, backend = FakeStore(_fresh()), FakeBackend()
    _, token = await refresh_linked_identity(store, backend, store.row(), leeway=LEEWAY)
    assert backend.calls == [] and token.access_token == "at-old"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["unlinked", "disabled"])
async def test_identity_gone_meanwhile_raises(change):
    store, backend = FakeStore(_expiring()), FakeBackend()
    first_read = store.row()
    if change == "unlinked":
        store.exists = False
    else:
        store.enabled = False
    with pytest.raises(UserNotFound):
        await refresh_linked_identity(store, backend, first_read, leeway=LEEWAY)
    assert backend.calls == []


@pytest.mark.asyncio
async def test_missing_refresh_token_raises():
    store, backend = FakeStore(
        TokenResponse(access_token="at-old", expires_at=datetime.now(timezone.utc))
    ), FakeBackend()
    with pytest.raises(ConfigError):
        await refresh_linked_identity(store, backend, store.row(), leeway=LEEWAY)


@pytest.mark.asyncio
async def test_waits_for_the_session_refresh_guard():
    """Same guard key as get_live_provider_token, whose user id comes from the session as a string."""
    store, backend = FakeStore(_expiring()), FakeBackend()
    async with backend.refresh_guard("35", "acct"):
        task = asyncio.create_task(
            refresh_linked_identity(store, backend, store.row(), leeway=LEEWAY)
        )
        await asyncio.sleep(0.02)
        assert not task.done() and backend.calls == []
    await task
    assert backend.calls == ["rt-old"]
