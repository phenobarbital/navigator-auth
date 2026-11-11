"""UserManager behind the guard (FEAT-107, TASK-153)."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from datamodel.parsers.json import JSONContent

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.handlers.guard_hooks import GuardedModelViewHooks
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.handler import ModelHandler
from navigator_auth.handlers.users import user as user_module
from navigator_auth.handlers.users.user import UserManager

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

OWNER_ID = 42
OTHER_ID = 99
ESCALATION_PAYLOAD = {
    "is_superuser": True,
    "is_staff": True,
    "user_role": 10,
    "email": "attacker@evil.test",
    "password": "hunter2",
}


class FakeSession(dict):
    """Session carrying the authenticated user payload."""

    def decode(self, key):
        """Return the stored decoded value."""
        return self.get(key)


def _session(user_id=OWNER_ID, groups=("users",)):
    """Build an auth session for a synthetic request."""
    return FakeSession({"session": {"user_id": user_id, "username": "u", "groups": list(groups)}})


class _SessionPatches:
    """Patch both session import locations used by the auth implementation."""

    def __init__(self, session):
        self.patches = [
            patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)),
            patch("navigator_auth.handlers.guards.get_session", new=AsyncMock(return_value=session)),
        ]

    def __enter__(self):
        for session_patch in self.patches:
            session_patch.start()

    def __exit__(self, *args):
        for session_patch in self.patches:
            session_patch.stop()


def _patch_sessions(session):
    """Return the session patch context manager."""
    return _SessionPatches(session)


class FakePDP:
    """Minimal policy holder used by ``policy_allows``."""

    def __init__(self, policy):
        self._evaluator = None
        self._policies = [policy]
        self._auditlog = MagicMock(log=AsyncMock())

    @property
    def policies(self):
        """Return configured policies."""
        return self._policies


def _pdp(actions):
    """Build an allowing superuser policy for actions."""
    return FakePDP(
        Policy(
            "users_admin_access",
            description="test",
            effect=PolicyEffect.ALLOW,
            actions=actions,
            groups=["superuser"],
            priority=1,
        )
    )


class FakeModel:
    """Minimal model API for direct guard-hook tests."""

    columns = {
        "user_id": None,
        "first_name": None,
        "last_name": None,
        "display_name": None,
        "email": None,
        "username": None,
        "is_active": None,
        "is_superuser": None,
        "is_staff": None,
        "user_role": None,
        "password": None,
    }

    class Meta:
        connection = None
        name = "users"
        schema = "auth"

    def __init__(self):
        self.update = AsyncMock()
        self.insert = AsyncMock()

    def get_columns(self):
        """Return declared columns."""
        return self.columns


class Row:
    """Simple user row with an owner."""

    def __init__(self, owner=OWNER_ID):
        self.user_id = owner
        self.first_name = "Before"
        self.email = "before@example.test"


def _handler(path="/api/v1/users/42", query="", body=None, pdp=None):
    """Build a direct UserManager hook host with an aiohttp request."""
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("PATCH", path + query, app=app)
    request["authenticated"] = True
    handler = UserManager.__new__(UserManager)
    handler._request = request
    handler._json = JSONContent()
    handler.model = FakeModel()
    handler.get_model = handler.model
    handler.json_data = AsyncMock(return_value=body)
    handler._session = _session()
    return handler


class TestConfiguration:
    """Declarative envelope and MRO coverage."""

    def test_usermanager_guard_first_in_mro(self):
        """The guard and verb hooks precede the ModelView-based handler."""
        mro = UserManager.__mro__
        assert mro.index(OwnerOrSuperuserGuard) < mro.index(ModelHandler)
        assert mro.index(GuardedModelViewHooks) < mro.index(ModelHandler)

    def test_usermanager_has_no_password_hooks(self):
        """Generic CRUD exposes no password setter or calculator hook."""
        assert not hasattr(UserManager, "_set_password")
        assert not hasattr(UserManager, "_calculate_password")

    def test_no_set_basic_password_reference(self):
        """The handler source no longer imports or references password hashing."""
        assert "set_basic_password" not in Path(user_module.__file__).read_text()

    def test_usermanager_required_lists_are_writable(self):
        """Every required create or upsert column belongs to its envelope."""
        manager = UserManager.__new__(UserManager)
        assert set(manager.required_by_put()) <= UserManager.creatable_by_admin
        assert set(manager.required_by_post()) <= UserManager.writable_by_admin

    def test_privileged_never_writable(self):
        """Privileged columns belong to no CRUD write envelope."""
        writable = UserManager.writable_by_owner | UserManager.writable_by_admin | UserManager.creatable_by_admin
        assert not (UserManager.privileged_columns & writable)

    def test_config_matches_policy_pack(self):
        """The configured admin actions exactly match the shipped policy."""
        policy_path = Path(__file__).parents[3] / "navigator_auth/abac/default_policies/auth_crud_admin_access.yaml"
        policies = YAMLStorage._parse_file(policy_path)
        policy = next(item for item in policies if item["name"] == UserManager.policy_name)
        assert set(policy["actions"]) == UserManager.superuser_actions


class TestWrites:
    """Write authorization coverage."""

    @pytest.mark.asyncio
    async def test_usermanager_escalation_payload_refused(self):
        """An owner cannot escalate through a PATCH payload."""
        handler = _handler(body=ESCALATION_PAYLOAD)
        row = Row()
        with (
            _patch_sessions(_session()),
            pytest.raises(web.HTTPForbidden),
            patch.object(ModelHandler, "_set_update", new=AsyncMock()) as update,
        ):
            await handler._pre_patch()
            await handler._set_update(row, dict(ESCALATION_PAYLOAD))
        update.assert_not_awaited()
        handler.model.update.assert_not_awaited()
        handler.model.insert.assert_not_awaited()
        assert row.email == "before@example.test"

    @pytest.mark.asyncio
    async def test_usermanager_escalation_payload_refused_for_admin(self):
        """An authorized superuser cannot escalate through a PATCH payload."""
        handler = _handler(body=ESCALATION_PAYLOAD, pdp=_pdp(UserManager.superuser_actions))
        row = Row(owner=OTHER_ID)
        with (
            _patch_sessions(_session(groups=["superuser"])),
            pytest.raises(web.HTTPForbidden),
            patch.object(ModelHandler, "_set_update", new=AsyncMock()) as update,
        ):
            await handler._pre_patch()
            await handler._set_update(row, dict(ESCALATION_PAYLOAD))
        update.assert_not_awaited()
        handler.model.update.assert_not_awaited()
        handler.model.insert.assert_not_awaited()
        assert row.email == "before@example.test"

    @pytest.mark.asyncio
    async def test_owner_can_edit_profile(self):
        """An owner may PATCH a profile allowlist column on their own row."""
        handler = _handler(body={"first_name": "After"})
        with _patch_sessions(_session()), patch.object(ModelHandler, "_set_update", new=AsyncMock()) as update:
            await handler._pre_patch()
            await handler._set_update(Row(), {"first_name": "After"})
        update.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_admin_can_update_non_privileged_column(self):
        """An approved superuser may PATCH another user's e-mail address."""
        handler = _handler(body={"email": "after@example.test"}, pdp=_pdp(UserManager.superuser_actions))
        with (
            _patch_sessions(_session(groups=["superuser"])),
            patch.object(ModelHandler, "_set_update", new=AsyncMock()) as update,
            patch("navigator_auth.handlers.guards.policy_allows", new=AsyncMock(return_value=(True, "allowed", None))),
        ):
            await handler._pre_patch()
            await handler._set_update(Row(owner=OTHER_ID), {"email": "after@example.test"})
        update.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_username_not_updatable(self):
        """An admin cannot change a username after user creation."""
        handler = _handler(body={"username": "different"}, pdp=_pdp(UserManager.superuser_actions))
        with (
            _patch_sessions(_session(groups=["superuser"])),
            pytest.raises(web.HTTPForbidden),
            patch.object(ModelHandler, "_set_update", new=AsyncMock()) as update,
        ):
            await handler._pre_patch()
            await handler._set_update(Row(owner=OTHER_ID), {"username": "different"})
        update.assert_not_awaited()
        handler.model.update.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_usermanager_create_without_password(self):
        """An approved superuser may create through PUT without password data."""
        body = {"first_name": "New", "last_name": "User", "username": "newuser", "email": "new@example.test"}
        handler = _handler(path="/api/v1/users", body=body, pdp=_pdp(UserManager.superuser_actions))
        with (
            _patch_sessions(_session(groups=["superuser"])),
            patch("navigator_auth.handlers.guards.policy_allows", new=AsyncMock(return_value=(True, "allowed", None))),
        ):
            assert await handler._pre_put() is True
        assert "password" not in handler._guard_write_keys
        assert not (handler._guard_write_keys & UserManager.privileged_columns)
        handler.model.insert.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_usermanager_create_refuses_privileged_and_password(self):
        """PUT rejects privileged and password keys instead of dropping them."""
        handler = _handler(path="/api/v1/users", body=ESCALATION_PAYLOAD, pdp=_pdp(UserManager.superuser_actions))
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await handler._pre_put()
        handler.model.insert.assert_not_awaited()


class TestReads:
    """Owned read-path coverage."""

    @pytest.mark.asyncio
    async def test_non_superuser_list_bound_to_own_row(self):
        """A non-superuser list binds the owner filter to the acting user."""
        handler = _handler(path="/api/v1/users")
        with _patch_sessions(_session()), patch.object(ModelHandler, "_get_data", new=AsyncMock(return_value=[])):
            await handler._pre_get()
            await handler._get_data({}, {})
        assert await handler._filter_user_id() == OWNER_ID

    @pytest.mark.asyncio
    async def test_foreign_user_id_param_refused(self):
        """A non-superuser cannot name another user's identifier in a read query."""
        handler = _handler(path="/api/v1/users", query=f"?user_id={OTHER_ID}")
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await handler._pre_get()
