import pytest
import time
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.storages.yaml_storage import YAMLStorage

def make_ctx(username="testuser", groups=None, path="/", method="GET"):
    request = MagicMock(spec=web.Request)
    request.remote = "127.0.0.1"
    request.method = method
    request.path = path
    request.headers = {}
    
    user = MagicMock()
    user.username = username
    user.groups = groups or []
    user.__dict__ = {"username": username, "groups": groups or []}
    
    userinfo = {
        "username": username,
        "groups": groups or []
    }
    
    # We need to manually set store for EvalContext if we don't call __init__ properly
    # but here we can call __init__
    ctx = EvalContext(request, user, userinfo, None)
    return ctx

@pytest.mark.filterwarnings("ignore:It is recommended to use web.AppKey instances for keys:aiohttp.web_exceptions.NotAppKeyWarning")
@pytest.mark.filterwarnings("ignore:old-style middleware:DeprecationWarning")
class TestE2EAbacRust:
    """End-to-end tests for unified ABAC with Rust evaluation."""

    @pytest.fixture
    def mixed_policies(self):
        """Mix of classic and resource policy dicts."""
        return [
            # Classic policy with URN
            {"name": "admin_api", "policy_type": "policy", "effect": "allow",
             "groups": ["admin"], "resources": ["urn:uri:/api/v1/admin/*"],
             "actions": ["uri:read"], "priority": 10},
            # Resource policy
            {"name": "eng_tools", "policy_type": "resource", "effect": "allow",
             "resources": ["tool:jira_*", "tool:github_*"],
             "actions": ["tool:execute"],
             "subjects": {"groups": ["engineering"]}, "priority": 5},
            # Regex URI deny
            {"name": "block_printers", "policy_type": "policy", "effect": "deny",
             "groups": ["*"], "resources": ["urn:uri:/epson.*$"],
             "priority": 100, "enforcing": True},
        ]

    @pytest.fixture
    def mock_storage(self, mixed_policies):
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=mixed_policies)
        storage.close = AsyncMock()
        return storage

    @pytest.fixture
    def yaml_storage(self):
        path = Path(__file__).parent / "fixtures"
        return YAMLStorage(directory=path)

    @pytest.mark.asyncio
    async def test_classic_policy_through_rust(self, mock_storage):
        """Classic policy evaluates correctly through Rust engine."""
        pdp = PDP(storage=mock_storage)
        await pdp._load_policies()
        
        ctx = make_ctx(username="admin_user", groups=["admin"],
                       path="/api/v1/admin/users", method="GET")
        
        # Note: PDP maps GET to uri:read internally, but here we test evaluator directly
        result = pdp.evaluator.check_access(
            ctx, ResourceType.URI, "/api/v1/admin/users", "uri:read"
        )
        assert result.allowed is True
        assert result.matched_policy == "admin_api"

    @pytest.mark.asyncio
    async def test_regex_uri_blocking(self, mock_storage):
        """Regex URN pattern blocks matching requests."""
        pdp = PDP(storage=mock_storage)
        await pdp._load_policies()
        
        ctx = make_ctx(username="user", groups=["engineering"],
                       path="/epson_lx350/status", method="GET")
        result = pdp.evaluator.check_access(
            ctx, ResourceType.URI, "/epson_lx350/status", "uri:read"
        )
        assert result.allowed is False
        assert result.matched_policy == "block_printers"

    @pytest.mark.asyncio
    async def test_resource_policy_tools(self, mock_storage):
        """Resource policy allows tool access for matching groups."""
        pdp = PDP(storage=mock_storage)
        await pdp._load_policies()
        
        ctx = make_ctx(username="dev", groups=["engineering"])
        result = pdp.evaluator.filter_resources(
            ctx, ResourceType.TOOL,
            ["jira_create", "slack_send", "github_pr"],
            "tool:execute"
        )
        assert set(result.allowed) == {"jira_create", "github_pr"}
        assert "slack_send" in result.denied

    @pytest.mark.asyncio
    async def test_yaml_loading_and_evaluation(self, mock_storage, yaml_storage):
        """Verify YAML policies load and evaluate alongside DB policies."""
        pdp = PDP(storage=mock_storage, yaml_storage=yaml_storage)
        await pdp._load_policies()
        
        # Count should be 3 (mixed) + 2 (yaml) = 5
        assert len(pdp.evaluator._index.all()) == 5
        
        ctx = make_ctx(username="guest", groups=["visitors"])
        
        # Test allow from YAML
        r1 = pdp.evaluator.check_access(ctx, ResourceType.TOOL, "yaml_tool", "tool:execute")
        assert r1.allowed is True
        assert r1.matched_policy == "allow_by_yaml"
        
        # Test deny from YAML (enforcing)
        r2 = pdp.evaluator.check_access(ctx, ResourceType.URI, "/api/v1/forbidden/secret", "uri:read")
        assert r2.allowed is False
        assert r2.matched_policy == "deny_by_yaml"

    @pytest.mark.asyncio
    async def test_hot_reload_changes_behavior(self, mock_storage):
        """After reload, new policies take effect."""
        pdp = PDP(storage=mock_storage)
        await pdp._load_policies()
        
        ctx = make_ctx(username="dev", groups=["engineering"])
        r1 = pdp.evaluator.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r1.allowed is True

        # Change mock to return restrictive policies
        mock_storage.load_policies.return_value = [
            {"name": "deny_all", "policy_type": "resource", "effect": "deny",
             "resources": ["tool:*"], "subjects": {"groups": ["*"]}, "priority": 1000}
        ]
        
        await pdp.reload_policies()

        r2 = pdp.evaluator.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r2.allowed is False
        assert r2.matched_policy == "deny_all"

    @pytest.mark.asyncio
    async def test_middleware_full_stack(self, mock_storage):
        """Full HTTP request flow through middleware to Rust engine."""
        app = web.Application()
        pdp = PDP(storage=mock_storage)
        pdp.setup(app)
        await pdp.on_startup(app)
        
        async def handler(request):
            return web.Response(text="OK")
            
        app.router.add_get("/api/v1/admin/dashboard", handler)
        
        # Mock session/user
        session = MagicMock()
        userinfo = {"username": "admin", "groups": ["admin"]}
        session.__getitem__.return_value = userinfo
        session.get.return_value = userinfo
        class User:
            def __init__(self):
                self.username = "admin"
                self.groups = ["admin"]
        session.decode.return_value = User()
        
        @web.middleware
        async def mock_auth(request, handler):
            request['authenticated'] = True
            from navigator_session import SESSION_KEY
            request[SESSION_KEY] = session
            return await handler(request)
            
        app.middlewares.insert(0, mock_auth)
        
        with patch("navigator_auth.abac.guardian.get_session", AsyncMock(return_value=session)):
            async with TestClient(TestServer(app)) as client:
                resp = await client.get("/api/v1/admin/dashboard")
                assert resp.status == 200
                
                # Try forbidden path
                resp2 = await client.get("/api/v1/forbidden")
                # Default deny (PreconditionFailed -> 428)
                assert resp2.status == 428

    def test_performance_under_10ms(self, mock_storage):
        """Policy evaluation completes within 10ms p99."""
        # Setup 50 policies
        policies = []
        for i in range(50):
            policies.append({
                "name": f"policy_{i}",
                "policy_type": "resource",
                "effect": "allow" if i % 2 == 0 else "deny",
                "resources": [f"tool:tool_{i}"],
                "subjects": {"groups": ["engineering"]},
                "priority": i
            })
        
        mock_storage.load_policies = AsyncMock(return_value=policies)
        pdp = PDP(storage=mock_storage)
        # We need a loop to run async _load_policies
        loop = asyncio.new_event_loop()
        loop.run_until_complete(pdp._load_policies())
        
        ctx = make_ctx(username="dev", groups=["engineering"])
        env = Environment()

        times = []
        for _ in range(100):
            start = time.perf_counter()
            # Random resource to avoid cache hit every time if possible
            # but here we want to test engine speed
            pdp.evaluator.check_access(
                ctx, ResourceType.TOOL, "tool_0", "tool:execute", env
            )
            times.append((time.perf_counter() - start) * 1000)

        # Exclude first call (cold cache)
        # Sorted times from 1 to end
        warm_times = sorted(times[1:])
        p99_idx = int(len(warm_times) * 0.99)
        p99 = warm_times[p99_idx]
        
        print(f"P99 Latency: {p99:.4f}ms")
        assert p99 < 10.0, f"p99 latency {p99:.2f}ms exceeds 10ms target"
        loop.close()
