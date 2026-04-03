import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, EvaluationResult
# We need the actual exception classes returned by the factory functions
# PreconditionFailed -> web.HTTPPreconditionRequired (status 428)
# AccessDenied -> web.HTTPForbidden (status 403)

@pytest.mark.filterwarnings("ignore:body argument is deprecated for http web exceptions:DeprecationWarning")
class TestPDPDelegation:
    @pytest.fixture
    def mock_user(self):
        user = MagicMock()
        user.__dict__ = {}
        return user

    @pytest.fixture
    def mock_request(self):
        request = MagicMock(spec=web.Request)
        request.remote = "127.0.0.1"
        request.method = "GET"
        request.headers = {}
        request.path = "/api/v1/admin/users"
        request.path_qs = "/api/v1/admin/users"
        request.rel_url = MagicMock()
        return request

    @pytest.fixture
    def mock_storage(self):
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[
            {
                "name": "admin_api",
                "policy_type": "policy",
                "effect": "allow",
                "groups": ["admin"],
                "resources": ["urn:uri:/api/v1/admin/*"],
                "priority": 10
            },
            {
                "name": "tools",
                "policy_type": "resource",
                "effect": "allow",
                "resources": ["tool:jira_*"],
                "actions": ["tool:execute"],
                "subjects": {"groups": ["engineering"]},
                "priority": 5
            },
        ])
        return storage

    @pytest.fixture
    def pdp(self, mock_storage):
        return PDP(storage=mock_storage)

    @pytest.mark.asyncio
    async def test_load_policies_populates_evaluator(self, pdp):
        await pdp._load_policies()
        assert len(pdp.evaluator._index.all()) == 2
        assert pdp.evaluator._index.get_by_name("admin_api") is not None
        assert pdp.evaluator._index.get_by_name("tools") is not None

    @pytest.mark.asyncio
    async def test_authorize_delegates_to_evaluator(self, pdp, mock_request, mock_user):
        await pdp._load_policies()
        
        session = {
            "session_object": {
                "username": "admin_user",
                "groups": ["admin"]
            }
        }

        with patch.object(pdp.evaluator, 'check_access') as mock_check:
            mock_check.return_value = EvaluationResult(
                allowed=True,
                effect=PolicyEffect.ALLOW,
                matched_policy="admin_api",
                reason="Matched"
            )
            
            response = await pdp.authorize(mock_request, session=session, user=mock_user)
            
            assert response.effect == PolicyEffect.ALLOW
            assert response.rule == "admin_api"
            mock_check.assert_called_once()
            # Verify ResourceType.URI and request.path were passed
            args, _ = mock_check.call_args
            assert args[1] == ResourceType.URI
            assert args[2] == "/api/v1/admin/users"
            assert args[3] == "uri:read"

    @pytest.mark.asyncio
    async def test_authorize_raises_precondition_failed(self, pdp, mock_request, mock_user):
        await pdp._load_policies()
        
        mock_request.path = "/public"
        session = {"session_object": {"username": "guest", "groups": []}}

        with patch.object(pdp.evaluator, 'check_access') as mock_check:
            mock_check.return_value = EvaluationResult(
                allowed=False,
                effect=PolicyEffect.DENY,
                matched_policy=None,
                reason="No match"
            )
            
            # PreconditionFailed returns web.HTTPPreconditionRequired (428)
            with pytest.raises(web.HTTPPreconditionRequired):
                await pdp.authorize(mock_request, session=session, user=mock_user)

    @pytest.mark.asyncio
    async def test_authorize_raises_access_denied(self, pdp, mock_request, mock_user):
        await pdp._load_policies()
        
        session = {"session_object": {"username": "user", "groups": ["user"]}}

        with patch.object(pdp.evaluator, 'check_access') as mock_check:
            mock_check.return_value = EvaluationResult(
                allowed=False,
                effect=PolicyEffect.DENY,
                matched_policy="some_deny_policy",
                reason="Denied"
            )
            
            # AccessDenied returns web.HTTPForbidden (403)
            with pytest.raises(web.HTTPForbidden):
                await pdp.authorize(mock_request, session=session, user=mock_user)

    @pytest.mark.asyncio
    async def test_is_allowed_delegates_to_evaluator(self, pdp, mock_request, mock_user):
        await pdp._load_policies()
        
        session = {"session_object": {"username": "eng_user", "groups": ["engineering"]}}
        
        with patch.object(pdp.evaluator, 'check_access') as mock_check:
            mock_check.return_value = EvaluationResult(
                allowed=True,
                effect=PolicyEffect.ALLOW,
                matched_policy="tools",
                reason="Matched"
            )
            
            response = await pdp.is_allowed(
                mock_request, session=session, user=mock_user,
                resource="tool:jira_123", 
                action="tool:execute"
            )
            
            assert response.effect == PolicyEffect.ALLOW
            assert response.rule == "tools"
            mock_check.assert_called_once()
            args, _ = mock_check.call_args
            assert args[1] == ResourceType.TOOL
            assert args[2] == "jira_123"
            assert args[3] == "tool:execute"

    def test_evaluator_property(self, pdp):
        assert pdp.evaluator is not None
        assert isinstance(pdp.evaluator, PolicyEvaluator)
