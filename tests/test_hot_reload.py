import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyIndex
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType

@pytest.mark.filterwarnings("ignore:It is recommended to use web.AppKey instances for keys:aiohttp.web_exceptions.NotAppKeyWarning")
class TestHotReload:
    @pytest.fixture
    def mock_storage(self):
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[
            {
                "name": "v1",
                "policy_type": "resource",
                "effect": "allow",
                "resources": ["tool:old_*"],
                "subjects": {"groups": ["*"]},
                "priority": 10
            }
        ])
        storage.close = AsyncMock()
        return storage

    @pytest.fixture
    def pdp(self, mock_storage):
        return PDP(storage=mock_storage)

    @pytest.mark.asyncio
    async def test_reload_swaps_policies(self, pdp, mock_storage):
        """After reload, new policies are active."""
        await pdp._load_policies()
        assert len(pdp.evaluator._index.all()) == 1
        assert pdp.evaluator._index.get_by_name("v1") is not None

        # Change storage to return new policy
        mock_storage.load_policies.return_value = [
            {
                "name": "v2",
                "policy_type": "resource",
                "effect": "allow",
                "resources": ["tool:new_*"],
                "subjects": {"groups": ["*"]},
                "priority": 20
            }
        ]

        count = await pdp.reload_policies()
        assert count == 1
        
        # Verify old policy is gone, new is active
        assert len(pdp.evaluator._index.all()) == 1
        assert pdp.evaluator._index.get_by_name("v1") is None
        assert pdp.evaluator._index.get_by_name("v2") is not None
        assert pdp.evaluator._index.all()[0].priority == 20

    @pytest.mark.asyncio
    async def test_reload_clears_cache(self, pdp, mock_storage):
        """Reload clears the evaluator LRU cache."""
        await pdp._load_policies()
        
        # Mock check_access to populate cache
        ctx = MagicMock()
        ctx.userinfo = {"username": "test", "groups": []}
        
        # Populate cache
        pdp.evaluator.check_access(ctx, ResourceType.TOOL, "old_1", "read")
        assert len(pdp.evaluator._cache) == 1
        
        # Reload
        await pdp.reload_policies()
        
        # Cache should be empty
        assert len(pdp.evaluator._cache) == 0

    @pytest.mark.asyncio
    async def test_periodic_reload_starts(self, mock_storage):
        """Periodic reload task starts if interval > 0."""
        with patch("navigator_auth.abac.pdp.ABAC_RELOAD_INTERVAL", 60):
            pdp = PDP(storage=mock_storage)
            app = web.Application()
            # We need to mock setup to not fail on other things
            pdp.setup(app)
            assert pdp._reload_task is not None
            assert not pdp._reload_task.done()
            
            # Cleanup
            pdp._reload_task.cancel()
            try:
                await pdp._reload_task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_periodic_reload_disabled(self, mock_storage):
        """Periodic reload task does NOT start if interval <= 0."""
        with patch("navigator_auth.abac.pdp.ABAC_RELOAD_INTERVAL", 0):
            pdp = PDP(storage=mock_storage)
            app = web.Application()
            pdp.setup(app)
            assert pdp._reload_task is None

    @pytest.mark.asyncio
    async def test_reload_endpoint_superuser(self, pdp, mock_storage):
        """POST /api/v1/abac/reload triggers reload."""
        from navigator_auth.abac.policyhandler import PolicyHandler
        from navigator_auth.conf import AUTH_SESSION_OBJECT
        
        app = web.Application()
        app['abac'] = pdp
        app.router.add_post("/api/v1/abac/reload", PolicyHandler.reload)
        
        # Mock authentication to allow superuser
        mock_request = MagicMock(spec=web.Request)
        mock_request.app = app
        mock_request.get.return_value = True # authenticated
        
        # Mock session/user for groups_protected
        session = MagicMock()
        userinfo = {"username": "admin", "groups": ["superuser"]}
        session.__getitem__.return_value = userinfo
        session.get.return_value = userinfo
        
        with patch("navigator_auth.abac.decorators.get_session", AsyncMock(return_value=session)):
            with patch.object(pdp, 'reload_policies', AsyncMock(return_value=5)) as mock_reload:
                handler = PolicyHandler(mock_request)
                response = await handler.reload(mock_request)
                
                assert response.status == 202
                mock_reload.assert_called_once()
