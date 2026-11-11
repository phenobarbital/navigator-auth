"""Write-column allowlist on OwnerOrSuperuserGuard (FEAT-107, TASK-149)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.partners import PartnerKeyHandler
from navigator_auth.handlers.userattrs import UserAccountHandler, UserIdentityHandler

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

POLICY = "users_admin_access"
ACTIONS = frozenset({"user:read", "user:create", "user:update", "user:delete"})
OWNER = frozenset({"first_name", "last_name", "display_name", "title", "avatar", "timezone"})
ADMIN = OWNER | {"is_active", "email", "alt_email"}
PRIVILEGED = frozenset(
    {"is_superuser", "user_role", "is_staff", "password", "userid", "user_id", "created_at", "last_login"}
)


class Host(OwnerOrSuperuserGuard):
    """Synthetic host configured like the users CRUD surface."""

    owner_column = "user_id"
    policy_name = POLICY
    superuser_actions = ACTIONS
    writable_by_owner = OWNER
    writable_by_admin = ADMIN
    creatable_by_admin = ADMIN | {"username"}
    privileged_columns = PRIVILEGED

    def __init__(self, request):
        self.request = request

    def error(self, response=None, status=400, **kwargs):
        """Mirror BaseHandler.error(): raise, never return."""
        cls = {
            400: web.HTTPBadRequest,
            401: web.HTTPUnauthorized,
            403: web.HTTPForbidden,
            404: web.HTTPNotFound,
        }.get(status, web.HTTPBadRequest)
        raise cls(text=json.dumps(response or {}), content_type="application/json")


class MappingHost(Host):
    """UserGroupManager-shaped host: no owner, PK columns creatable only."""

    owner_column = None
    policy_name = "user_groups_admin_access"
    superuser_actions = frozenset({"user_group:read", "user_group:create", "user_group:delete"})
    writable_by_owner = frozenset()
    writable_by_admin = frozenset()
    creatable_by_admin = frozenset({"user_id", "group_id"})
    privileged_columns = frozenset()


class FakePDP:
    """Minimal PDP fixture used by ``policy_allows``."""

    def __init__(self, policies, auditlog=None):
        self._evaluator = None
        self._policies = policies
        self._auditlog = auditlog

    @property
    def policies(self):
        """Return configured policies."""
        return self._policies


def _policy(name, actions):
    return Policy(name, effect=PolicyEffect.ALLOW, actions=list(actions), groups=["superuser"], priority=1)


def _audit():
    log = MagicMock()
    log.log = AsyncMock()
    return log


def _request(pdp=None, path="/api/v1/users/42"):
    app = web.Application()
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", path, app=app)
    request["authenticated"] = True
    return request


def _session(user_id=42, groups=("users",), **extra):
    info = {"user_id": user_id, "username": "u", "groups": list(groups), **extra}
    data = {"session": info}
    session = MagicMock()
    session.__contains__ = lambda s, k: k in data
    session.__getitem__ = lambda s, k: data[k]
    session.decode = MagicMock(return_value=None)
    return session


def _patch_session(session):
    return patch("navigator_auth.handlers.guards.get_session", new=AsyncMock(return_value=session)), patch(
        "navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)
    )


class _Sess:
    """Context manager patching get_session in guards and decorators."""

    def __init__(self, session):
        self.ps = _patch_session(session)

    def __enter__(self):
        for patcher in self.ps:
            patcher.start()

    def __exit__(self, *args):
        for patcher in self.ps:
            patcher.stop()


def S(session):
    """Patch request-session resolution for a test."""
    return _Sess(session)


class TestOwnerPath:
    @pytest.mark.asyncio
    async def test_owner_cannot_write_privileged_column(self):
        with S(_session()), pytest.raises(web.HTTPForbidden):
            await Host(_request()).authorize_row("user:update", 42, payload={"is_superuser"})

    @pytest.mark.asyncio
    async def test_owner_can_write_profile_allowlist(self):
        with S(_session()), patch("navigator_auth.handlers.guards.policy_allows") as policy_allows:
            assert await Host(_request()).authorize_row("user:update", 42, payload={"first_name", "timezone"}) is True
        policy_allows.assert_not_called()

    @pytest.mark.asyncio
    async def test_unknown_column_refused_by_default(self):
        with S(_session()), pytest.raises(web.HTTPForbidden):
            await Host(_request()).authorize_row("user:update", 42, payload={"attributes", "is_new"})
        pdp = FakePDP([_policy(POLICY, ACTIONS)])
        with S(_session(groups=("superuser",))), pytest.raises(web.HTTPForbidden):
            await Host(_request(pdp)).authorize_row("user:update", 7, payload={"attributes"})

    @pytest.mark.asyncio
    async def test_owner_create_refused(self):
        with S(_session()), pytest.raises(web.HTTPForbidden):
            await Host(_request()).authorize_row("user:create", 42, payload={"first_name"}, creating=True)


class TestAdminPath:
    @pytest.mark.asyncio
    async def test_admin_cannot_write_privileged_column(self):
        pdp = FakePDP([_policy(POLICY, ACTIONS)])
        with S(_session(groups=("superuser",))), pytest.raises(web.HTTPForbidden):
            await Host(_request(pdp)).authorize_row("user:update", 7, payload={"is_staff"})

    @pytest.mark.asyncio
    async def test_admin_can_write_admin_allowlist(self):
        pdp = FakePDP([_policy(POLICY, ACTIONS)])
        with S(_session(groups=("superuser",))):
            assert await Host(_request(pdp)).authorize_row("user:update", 7, payload={"email", "is_active"}) is True

    @pytest.mark.asyncio
    async def test_create_uses_creatable_allowlist(self):
        pdp = FakePDP([_policy(POLICY, ACTIONS)])
        with S(_session(groups=("superuser",))):
            assert await Host(_request(pdp)).authorize_row(
                "user:create", None, payload={"username", "email"}, creating=True
            ) is True
        with S(_session(groups=("superuser",))), pytest.raises(web.HTTPForbidden):
            await Host(_request(pdp)).authorize_row(
                "user:create", None, payload={"username", "password"}, creating=True
            )
        fallback = Host(_request(pdp))
        fallback.creatable_by_admin = None
        with S(_session(groups=("superuser",))):
            assert await fallback.authorize_row("user:create", None, payload={"email"}, creating=True) is True

    @pytest.mark.asyncio
    async def test_mapping_row_create_allowed_for_admin(self):
        policy = _policy(MappingHost.policy_name, MappingHost.superuser_actions)
        with S(_session(groups=("superuser",))):
            assert await MappingHost(_request(FakePDP([policy]))).authorize_row(
                "user_group:create", None, payload={"user_id", "group_id"}, creating=True
            ) is True

    @pytest.mark.asyncio
    async def test_mapping_row_update_refused(self):
        policy = _policy(MappingHost.policy_name, MappingHost.superuser_actions)
        with S(_session(groups=("superuser",))), pytest.raises(web.HTTPForbidden):
            await MappingHost(_request(FakePDP([policy]))).authorize_row("user_group:update", None, payload=set())


class TestRefusals:
    @pytest.mark.asyncio
    async def test_refusal_names_no_hidden_column(self):
        with S(_session()), pytest.raises(web.HTTPForbidden) as error:
            await Host(_request()).authorize_row("user:update", 42, payload={"is_superuser", "user_role", "password"})
        assert all(column not in error.value.text for column in ("is_superuser", "user_role", "password"))

    @pytest.mark.asyncio
    async def test_column_refusal_is_audited(self):
        audit = _audit()
        with S(_session()), pytest.raises(web.HTTPForbidden):
            await Host(_request(FakePDP([], audit))).authorize_row("user:update", 42, payload={"is_superuser"})
        audit.log.assert_awaited_once()
        answer, status = audit.log.await_args.args[:2]
        assert status == "DENY" and "is_superuser" in answer.response

    @pytest.mark.asyncio
    async def test_string_payload_rejected(self):
        with pytest.raises(TypeError), S(_session()):
            await Host(_request()).authorize_columns("email", is_owner=True)


class TestBackwardCompatibility:
    @pytest.mark.asyncio
    async def test_payload_none_keeps_owner_blanket_allow(self):
        with S(_session()):
            assert await Host(_request()).authorize_row("user:update", 42) is True

    def test_feat105_handlers_unchanged(self):
        for handler in (UserIdentityHandler, UserAccountHandler, PartnerKeyHandler):
            assert handler.writable_by_owner == frozenset()
            assert handler.writable_by_admin == frozenset()
            assert handler.creatable_by_admin is None
            assert handler.privileged_columns == frozenset()
