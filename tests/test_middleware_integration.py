import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from unittest.mock import AsyncMock, MagicMock, patch
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.context import EvalContext

@pytest_asyncio.fixture
async def app_with_abac():
    app = web.Application()
    
    # Mock storage
    mock_storage = MagicMock()
    mock_storage.load_policies = AsyncMock(return_value=[
        {
            "name": "allow_test",
            "policy_type": "resource",
            "effect": "allow",
            "resources": ["tool:test_tool"],
            "actions": ["tool:execute"],
            "subjects": {"groups": ["*"]},
            "priority": 10
        },
        {
            "name": "allow_uri",
            "policy_type": "resource",
            "effect": "allow",
            "resources": ["uri:/test/protected"],
            "actions": ["uri:read"],
            "subjects": {"groups": ["*"]},
            "priority": 5
        }
    ])
    mock_storage.close = AsyncMock()
    
    pdp = PDP(storage=mock_storage)
    pdp.setup(app)
    
    # Manually trigger startup to load policies and register evaluator
    await pdp.on_startup(app)
    
    async def test_handler(request):
        evaluator = request.app.get('policy_evaluator')
        if not evaluator:
            return web.json_response({"error": "evaluator missing"}, status=500)
        
        # Build a dummy context
        ctx = EvalContext.__new__(EvalContext)
        ctx.store = {}
        ctx.userinfo = {"username": "testuser", "groups": ["engineering"]}
        
        # Test check_access
        result = evaluator.check_access(
            ctx, ResourceType.TOOL, "test_tool", "tool:execute"
        )
        
        # Test filter_resources
        filtered = evaluator.filter_resources(
            ctx, ResourceType.TOOL, ["test_tool", "unknown_tool"], "tool:execute"
        )
        
        return web.json_response({
            "allowed": result.allowed,
            "matched_policy": result.matched_policy,
            "filtered_allowed": filtered.allowed,
            "filtered_denied": filtered.denied
        })

    app.router.add_get("/test/protected", test_handler)
    
    return app

@pytest.mark.filterwarnings("ignore:It is recommended to use web.AppKey instances for keys:aiohttp.web_exceptions.NotAppKeyWarning")
@pytest.mark.filterwarnings("ignore:old-style middleware:DeprecationWarning")
class TestMiddlewareIntegration:
    @pytest.mark.asyncio
    async def test_evaluator_on_app(self, app_with_abac):
        """PolicyEvaluator is registered on app."""
        assert 'policy_evaluator' in app_with_abac
        from navigator_auth.abac.policies.evaluator import PolicyEvaluator
        assert isinstance(app_with_abac['policy_evaluator'], PolicyEvaluator)

    @pytest.mark.asyncio
    async def test_handler_check_access(self, app_with_abac):
        """Handler can use policy_evaluator for resource checks."""
        async with TestClient(TestServer(app_with_abac)) as client:
            resp = await client.get("/test/protected")
            assert resp.status == 200
            data = await resp.json()
            assert data['allowed'] is True
            assert data['matched_policy'] == "allow_test"
            assert "test_tool" in data['filtered_allowed']
            assert "unknown_tool" in data['filtered_denied']

    @pytest.mark.asyncio
    async def test_middleware_authorize_flow(self, app_with_abac):
        """Verify the normal authorize flow still works (uses evaluator internally)."""
        class User:
            def __init__(self):
                self.username = "testuser"
                self.groups = []
        
        # Mock session and user
        user = User()
        session = MagicMock()
        userinfo = {"username": "testuser", "groups": ["engineering"]}
        session.__getitem__.return_value = userinfo
        session.get.return_value = userinfo
        session.decode.return_value = user
        
        @web.middleware
        async def mock_auth_middleware(request, handler):
            request['authenticated'] = True
            from navigator_session import SESSION_KEY
            request[SESSION_KEY] = session
            return await handler(request)
            
        app_with_abac.middlewares.insert(0, mock_auth_middleware)
        
        # Also mock get_session in guardian to return our mock session
        with patch("navigator_auth.abac.guardian.get_session", AsyncMock(return_value=session)):
            async with TestClient(TestServer(app_with_abac)) as client:
                # This will trigger abac_middleware -> Guardian.authorize -> PDP.authorize -> Evaluator
                resp = await client.get("/test/protected")
                assert resp.status == 200
