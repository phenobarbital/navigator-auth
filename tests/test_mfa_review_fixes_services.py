"""FEAT-106 review fixes — self-healing MFA services with leases (M1; AC12, AC34)."""

import asyncio

import pytest

from navigator_auth.mfa import services as services_mod
from navigator_auth.mfa.services import (
    MFA_APP_KEY,
    MfaServices,
    MfaServicesSlot,
    build_mfa_services,
    get_ready_mfa_services,
    mfa_services_lease,
)


class _Redis:
    """Fake Redis pool recording disconnect()."""

    def __init__(self) -> None:
        self.closed = False

    async def disconnect(self) -> None:
        self.closed = True


def _unavailable(backend: object = None) -> MfaServices:
    return MfaServices(backend=backend or object(), available=False, redis_pool=_Redis())


def _available() -> MfaServices:
    return MfaServices(backend=object(), available=True, redis_pool=_Redis())


def _counting_stub(result_factory, delay: float = 0):
    calls = []

    async def stub(app, backend):
        calls.append(1)
        if delay:
            await asyncio.sleep(delay)
        return result_factory()

    return stub, calls


@pytest.mark.asyncio
async def test_ready_rebuilds_after_interval(monkeypatch):
    """Not before the interval; after it the slot swaps and the retired pool closes (AC12)."""
    old = _unavailable()
    fresh = _available()
    stub, calls = _counting_stub(lambda: fresh)
    monkeypatch.setattr(services_mod, "build_mfa_services", stub)
    slot = MfaServicesSlot(old)
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 60)
    assert await slot.ready({}) is old
    assert calls == []
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 0)
    assert await slot.ready({}) is fresh
    assert slot.services is fresh
    assert len(calls) == 1
    assert old.redis_pool.closed is True
    assert fresh.redis_pool.closed is False


@pytest.mark.asyncio
async def test_ready_still_unavailable_keeps_old(monkeypatch):
    """A rebuild that is still unavailable is discarded and closed; the old object stays."""
    old = _unavailable()
    bad = _unavailable()
    stub, _ = _counting_stub(lambda: bad)
    monkeypatch.setattr(services_mod, "build_mfa_services", stub)
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 0)
    slot = MfaServicesSlot(old)
    assert await slot.ready({}) is old
    assert bad.redis_pool.closed is True
    assert old.redis_pool.closed is False


@pytest.mark.asyncio
async def test_ready_rebuild_inflight(monkeypatch):
    """A lease on the old object survives the swap; its pool closes only after release (AC34)."""
    old = _unavailable()
    fresh = _available()
    stub, _ = _counting_stub(lambda: fresh)
    monkeypatch.setattr(services_mod, "build_mfa_services", stub)
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 0)
    slot = MfaServicesSlot(old)
    async with old.lease():
        assert await slot.ready({}) is fresh
        assert old.redis_pool.closed is False
    assert old.redis_pool.closed is True


@pytest.mark.asyncio
async def test_ready_single_flight(monkeypatch):
    """20 concurrent ready() calls trigger exactly one rebuild."""
    old = _unavailable()
    fresh = _available()
    stub, calls = _counting_stub(lambda: fresh, delay=0.05)
    monkeypatch.setattr(services_mod, "build_mfa_services", stub)
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 0)
    slot = MfaServicesSlot(old)
    results = await asyncio.gather(*(slot.ready({}) for _ in range(20)))
    assert len(calls) == 1
    assert all(r is fresh for r in results)


@pytest.mark.asyncio
async def test_ready_permanent_not_retried(monkeypatch):
    """Missing secret / authdb -> permanent=True and build_mfa_services is never called again."""
    monkeypatch.setattr("navigator_auth.conf.AUTH_OTP_SECRET", None)
    no_secret = await build_mfa_services({}, object())
    assert no_secret.permanent is True and no_secret.available is False
    monkeypatch.setattr("navigator_auth.conf.AUTH_OTP_SECRET", b"x" * 32)
    no_db = await build_mfa_services({}, object())
    assert no_db.permanent is True and no_db.available is False

    stub, calls = _counting_stub(_available)
    monkeypatch.setattr(services_mod, "build_mfa_services", stub)
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 0)
    for permanent in (no_secret, no_db):
        slot = MfaServicesSlot(permanent)
        assert await slot.ready({}) is permanent
    assert calls == []


@pytest.mark.asyncio
async def test_lease_helper_and_shutdown(monkeypatch):
    """mfa_services_lease yields None without a slot; slot.close() drains leases then closes pools."""
    async with mfa_services_lease({}) as none_services:
        assert none_services is None
    assert await get_ready_mfa_services(None) is None

    svc = _available()
    slot = MfaServicesSlot(svc)
    app = {MFA_APP_KEY: slot}
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_LOCK_TIMEOUT", 2.0)
    async with mfa_services_lease(app) as leased:
        assert leased is svc
        closer = asyncio.create_task(slot.close())
        await asyncio.sleep(0.05)
        assert svc.redis_pool.closed is False
    await closer
    assert svc.redis_pool.closed is True
    assert slot.services is None
    await slot.close()  # idempotent


@pytest.mark.asyncio
async def test_shutdown_forces_close_on_timeout(monkeypatch):
    """A lease that never ends does not block shutdown beyond the bound."""
    svc = _available()
    slot = MfaServicesSlot(svc)
    monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_LOCK_TIMEOUT", 0.05)
    async with svc.lease():
        await slot.close()
        assert svc.redis_pool.closed is True
