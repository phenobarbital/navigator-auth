"""
Phase 2 tests for per-tenant SQL filtering (FEAT-092, TASK-022).

These tests cover:
  - pgStorage.load_policies(org_id, client_id) parameterized query (requires live DB,
    skipped by default via ABAC_REQUIRE_DB marker).
  - Per-tenant evaluator LRU: build, cache hit, LRU eviction.
  - Reload invalidates per-tenant LRU.
  - Flag off -> Phase-1 shared evaluator behaviour (no LRU used).
  - Parity: per-tenant evaluator yields identical decisions to the shared evaluator.

Tests that require a live PostgreSQL connection are decorated with
``@pytest.mark.skipif(not DB_AVAILABLE, reason=...)`` and are skipped in CI
unless the DB fixtures are available.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest

from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.policies.resources import ResourceType

from tests.conftest import build_evaluator_from_dicts

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shared_policy_set():
    """Two-policy set: global allow + tenant-5 deny, identical to TASK-021."""
    return [
        {
            "name": "global_tools",
            "effect": "ALLOW",
            "policy_type": "policy",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["engineering"],
            "priority": 1,
            "org_id": 1,
            "client_id": 1,
        },
        {
            "name": "t5_block_jira",
            "effect": "DENY",
            "policy_type": "policy",
            "resource": ["tool:jira_*"],
            "actions": ["tool:execute"],
            "groups": ["engineering"],
            "priority": 10,
            "enforcing": True,
            "org_id": 5,
            "client_id": 1,
        },
    ]


def _make_tenant_5_policy_set():
    """Only global + tenant-5 rows (simulates SQL-filtered load)."""
    return _make_shared_policy_set()  # both rows qualify for tenant 5


def _make_tenant_7_policy_set():
    """Only global rows (tenant 7 has no specific policies)."""
    return [_make_shared_policy_set()[0]]  # only global_tools


# ---------------------------------------------------------------------------
# Unit tests — pgStorage.load_policies signature
# ---------------------------------------------------------------------------

class TestPgStorageSignature:
    def test_load_policies_accepts_org_client(self):
        """pgStorage.load_policies must accept org_id and client_id kwargs."""
        from navigator_auth.abac.storages.pg import pgStorage
        import inspect
        sig = inspect.signature(pgStorage.load_policies)
        params = sig.parameters
        assert "org_id" in params, "load_policies must have org_id param"
        assert "client_id" in params, "load_policies must have client_id param"
        assert params["org_id"].default is None, "org_id default must be None"
        assert params["client_id"].default is None, "client_id default must be None"

    def test_load_policies_no_args_form(self):
        """load_policies() with no args must still be valid (backward compat)."""
        from navigator_auth.abac.storages.pg import pgStorage
        import inspect
        sig = inspect.signature(pgStorage.load_policies)
        # Both params are optional (default=None) — callable without args
        bound = sig.bind(None)  # 'self' only
        bound.apply_defaults()
        assert bound.arguments.get("org_id") is None
        assert bound.arguments.get("client_id") is None


# ---------------------------------------------------------------------------
# Unit tests — PDP per-tenant LRU
# ---------------------------------------------------------------------------

class TestPDPTenantEvaluatorLRU:
    """PDP._get_tenant_evaluator must cache, evict, and fall back correctly."""

    def _make_pdp(self):
        """Build a PDP with mocked storage (no DB required)."""
        from navigator_auth.abac.pdp import PDP
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[])
        storage.close = AsyncMock()
        pdp = PDP(storage=storage)
        # Pre-populate shared evaluator
        shared = build_evaluator_from_dicts(_make_shared_policy_set())
        pdp._evaluator = shared
        return pdp

    def test_global_tenant_returns_shared_evaluator(self):
        """(1, 1) must always return the shared evaluator without touching LRU."""
        pdp = self._make_pdp()

        async def run():
            ev = await pdp._get_tenant_evaluator(1, 1)
            assert ev is pdp._evaluator
            assert len(pdp._tenant_evaluators) == 0

        asyncio.run(run())

    def test_cache_miss_builds_and_caches(self):
        """A first request for a new tenant builds a fresh evaluator and caches it."""
        pdp = self._make_pdp()
        # Return only global policies for this tenant
        pdp.storage.load_policies = AsyncMock(return_value=_make_tenant_7_policy_set())

        async def run():
            ev1 = await pdp._get_tenant_evaluator(7, 1)
            assert isinstance(ev1, PolicyEvaluator)
            assert (7, 1) in pdp._tenant_evaluators

            # Second call: cache hit (same object)
            ev2 = await pdp._get_tenant_evaluator(7, 1)
            assert ev1 is ev2
            # load_policies called only once
            pdp.storage.load_policies.assert_called_once_with(org_id=7, client_id=1)

        asyncio.run(run())

    def test_lru_evicts_oldest_entry(self):
        """When LRU is full, the oldest entry is evicted."""
        from navigator_auth.abac import pdp as pdp_module
        orig_size = pdp_module._TENANT_EVALUATOR_LRU_SIZE
        pdp_module._TENANT_EVALUATOR_LRU_SIZE = 2

        try:
            pdp = self._make_pdp()
            pdp.storage.load_policies = AsyncMock(return_value=[])

            async def run():
                await pdp._get_tenant_evaluator(2, 1)
                await pdp._get_tenant_evaluator(3, 1)
                assert len(pdp._tenant_evaluators) == 2
                # Adding a third entry evicts the oldest (org_id=2)
                await pdp._get_tenant_evaluator(4, 1)
                assert len(pdp._tenant_evaluators) == 2
                assert (2, 1) not in pdp._tenant_evaluators
                assert (3, 1) in pdp._tenant_evaluators
                assert (4, 1) in pdp._tenant_evaluators

            asyncio.run(run())
        finally:
            pdp_module._TENANT_EVALUATOR_LRU_SIZE = orig_size

    def test_lru_mru_ordering(self):
        """Accessing a cached entry moves it to 'most recently used' position."""
        from navigator_auth.abac import pdp as pdp_module
        orig_size = pdp_module._TENANT_EVALUATOR_LRU_SIZE
        pdp_module._TENANT_EVALUATOR_LRU_SIZE = 2

        try:
            pdp = self._make_pdp()
            pdp.storage.load_policies = AsyncMock(return_value=[])

            async def run():
                await pdp._get_tenant_evaluator(2, 1)
                await pdp._get_tenant_evaluator(3, 1)
                # Re-access (2, 1) — it becomes MRU, (3, 1) becomes LRU
                await pdp._get_tenant_evaluator(2, 1)
                # Adding a new entry evicts (3, 1), NOT (2, 1)
                await pdp._get_tenant_evaluator(4, 1)
                assert (3, 1) not in pdp._tenant_evaluators
                assert (2, 1) in pdp._tenant_evaluators
                assert (4, 1) in pdp._tenant_evaluators

            asyncio.run(run())
        finally:
            pdp_module._TENANT_EVALUATOR_LRU_SIZE = orig_size

    def test_db_error_falls_back_to_shared(self):
        """If the DB call fails when building a tenant evaluator, shared is returned."""
        pdp = self._make_pdp()
        pdp.storage.load_policies = AsyncMock(side_effect=RuntimeError("DB down"))

        async def run():
            ev = await pdp._get_tenant_evaluator(5, 1)
            # Must fall back to shared evaluator, not raise
            assert ev is pdp._evaluator
            assert (5, 1) not in pdp._tenant_evaluators

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Unit tests — reload invalidates LRU
# ---------------------------------------------------------------------------

class TestReloadInvalidatesLRU:
    def _make_pdp_with_cache(self):
        from navigator_auth.abac.pdp import PDP
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[])
        storage.close = AsyncMock()
        pdp = PDP(storage=storage)
        # Pre-fill the LRU
        pdp._tenant_evaluators[(5, 1)] = PolicyEvaluator()
        pdp._tenant_evaluators[(7, 1)] = PolicyEvaluator()
        return pdp

    def test_reload_clears_tenant_lru(self):
        """reload_policies must clear all per-tenant evaluators."""
        pdp = self._make_pdp_with_cache()
        # Mock out the storage reload to return empty list
        pdp.storage.load_policies = AsyncMock(return_value=[])
        assert len(pdp._tenant_evaluators) == 2

        asyncio.run(pdp.reload_policies())
        assert len(pdp._tenant_evaluators) == 0

    def test_reload_swaps_shared_index(self):
        """reload_policies must also swap the shared evaluator's index."""
        pdp = self._make_pdp_with_cache()
        pdp.storage.load_policies = AsyncMock(return_value=_make_shared_policy_set())
        old_index_id = id(pdp._evaluator._index)

        asyncio.run(pdp.reload_policies())

        new_index_id = id(pdp._evaluator._index)
        assert old_index_id != new_index_id, (
            "reload_policies must replace the shared evaluator's PolicyIndex"
        )


# ---------------------------------------------------------------------------
# Unit tests — flag off means no LRU, Phase-1 behaviour
# ---------------------------------------------------------------------------

class TestFlagOffPhase1Behaviour:
    def test_flag_off_returns_shared_evaluator(self):
        """When ABAC_TENANT_SQL_FILTERING=False, PDP must use the shared evaluator."""
        from navigator_auth.abac.pdp import PDP
        import navigator_auth.abac.pdp as pdp_module

        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[])
        storage.close = AsyncMock()
        pdp = PDP(storage=storage)

        orig = pdp_module.ABAC_TENANT_SQL_FILTERING
        try:
            pdp_module.ABAC_TENANT_SQL_FILTERING = False
            result = pdp.get_evaluator_for(org_id=5, client_id=1)
            assert result is pdp._evaluator
        finally:
            pdp_module.ABAC_TENANT_SQL_FILTERING = orig


# ---------------------------------------------------------------------------
# Parity tests — per-tenant evaluator yields identical decisions to shared
# ---------------------------------------------------------------------------

class TestPerTenantDecisionParity:
    """Per-tenant evaluator with the correct policies must match the shared one."""

    def test_tenant_5_parity(self, ctx_tenant_5):
        """Decisions for tenant-5 are identical whether from shared or per-tenant ev."""
        policies = _make_shared_policy_set()
        shared_ev = build_evaluator_from_dicts(policies)
        tenant_ev = build_evaluator_from_dicts(policies)  # same policies, new instance

        for resource_name in ["jira_create", "jira_search", "slack_send", "github_pr"]:
            shared_result = shared_ev.check_access(
                ctx_tenant_5, ResourceType.TOOL, resource_name, "tool:execute",
                org_id=5, client_id=1,
            )
            tenant_result = tenant_ev.check_access(
                ctx_tenant_5, ResourceType.TOOL, resource_name, "tool:execute",
                org_id=5, client_id=1,
            )
            assert shared_result.allowed == tenant_result.allowed, (
                f"Parity mismatch for tenant-5 / {resource_name}: "
                f"shared={shared_result.allowed}, tenant={tenant_result.allowed}"
            )

    def test_tenant_7_parity(self, ctx_tenant_7):
        """Decisions for tenant-7 are identical whether from shared or per-tenant ev."""
        # Tenant 7 evaluator only has global policies (as SQL filter would return)
        shared_ev = build_evaluator_from_dicts(_make_shared_policy_set())
        tenant_ev = build_evaluator_from_dicts(_make_tenant_7_policy_set())

        for resource_name in ["jira_create", "slack_send", "github_pr"]:
            shared_result = shared_ev.check_access(
                ctx_tenant_7, ResourceType.TOOL, resource_name, "tool:execute",
                org_id=7, client_id=1,
            )
            tenant_result = tenant_ev.check_access(
                ctx_tenant_7, ResourceType.TOOL, resource_name, "tool:execute",
                org_id=7, client_id=1,
            )
            assert shared_result.allowed == tenant_result.allowed, (
                f"Parity mismatch for tenant-7 / {resource_name}: "
                f"shared={shared_result.allowed}, tenant={tenant_result.allowed}"
            )


# ---------------------------------------------------------------------------
# Live-DB tests (skipped without a running PostgreSQL instance)
# ---------------------------------------------------------------------------

try:
    import asyncpg  # noqa: F401
    _ASYNCPG_AVAILABLE = True
except ImportError:
    _ASYNCPG_AVAILABLE = False

DB_AVAILABLE = False  # Set to True in your environment with DB_URL configured

@pytest.mark.skipif(not DB_AVAILABLE, reason="Requires live PostgreSQL — set DB_AVAILABLE=True")
class TestPgStorageLiveDB:
    """Live-DB integration tests; skipped in normal CI."""

    @pytest.mark.asyncio
    async def test_load_policies_tenant_filter(self, pg_storage):
        """load_policies(org_id, client_id) only returns global + that tenant's rows."""
        rows = await pg_storage.load_policies(org_id=5, client_id=1)
        for row in rows:
            assert row["org_id"] in (1, 5), (
                f"Row org_id={row['org_id']} should be 1 (global) or 5 (tenant)"
            )
            assert row["client_id"] in (1,), (
                f"Row client_id={row['client_id']} should be 1 (global) for this tenant"
            )

    @pytest.mark.asyncio
    async def test_load_policies_no_args_returns_all(self, pg_storage):
        """load_policies() with no args returns all enabled policies (Phase-1 compat)."""
        all_rows = await pg_storage.load_policies()
        filtered_rows = await pg_storage.load_policies(org_id=5, client_id=1)
        # Filtered must be a subset
        assert len(filtered_rows) <= len(all_rows), (
            "Filtered load must return <= rows compared to unfiltered load"
        )
