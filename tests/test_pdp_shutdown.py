"""PDP.on_shutdown cancels the reload task and closes storages (FEAT-113)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.abac.pdp import PDP


@pytest.fixture(autouse=True)
def _stub_audit_log(monkeypatch):
    """Keep PDP tests local; audit-log construction otherwise resolves host DNS."""
    monkeypatch.setattr("navigator_auth.abac.pdp.AuditLog", lambda: MagicMock(log=AsyncMock()))


def _pdp() -> tuple[PDP, AsyncMock, AsyncMock]:
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    yaml_storage = AsyncMock()
    return PDP(storage=storage, yaml_storage=yaml_storage), storage, yaml_storage


@pytest.mark.asyncio
async def test_on_shutdown_cancels_reload_task_and_closes_storages(monkeypatch):
    monkeypatch.setattr("navigator_auth.abac.pdp.ABAC_RELOAD_INTERVAL", 3600)
    pdp, storage, yaml_storage = _pdp()
    task = asyncio.ensure_future(pdp._periodic_reload())
    pdp._reload_task = task
    await asyncio.sleep(0)  # let the task reach its first sleep

    await pdp.on_shutdown(MagicMock())

    assert task.done()
    storage.close.assert_awaited_once_with()
    yaml_storage.close.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_on_shutdown_without_reload_task_closes_storages():
    pdp, storage, yaml_storage = _pdp()
    assert pdp._reload_task is None

    await pdp.on_shutdown(MagicMock())

    storage.close.assert_awaited_once_with()
    yaml_storage.close.assert_awaited_once_with()
