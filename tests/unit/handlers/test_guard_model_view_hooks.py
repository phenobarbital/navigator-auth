"""GuardedModelViewHooks over the ModelView-based ModelHandler (FEAT-107)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from datamodel.parsers.json import JSONContent

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.guard_hooks import GuardedModelViewHooks
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.handler import ModelHandler
from navigator_auth.handlers.partners import PartnerKeyHandler
from navigator_auth.handlers.userattrs import UserAccountHandler, UserIdentityHandler
from navigator_auth.models import User, UserGroup

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

OWNER_ID = 42
OTHER_ID = 99


class OwnedHost(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Synthetic owned ModelView host."""

    model = User
    pk = "user_id"
    action_object = "user"
    owner_column = "user_id"
    policy_name = "users_admin_access"
    superuser_actions = frozenset({"user:read", "user:create", "user:update", "user:delete"})
    writable_by_owner = frozenset({"first_name"})
    writable_by_admin = frozenset({"first_name", "email"})
    creatable_by_admin = frozenset({"first_name", "username"})
    privileged_columns = frozenset({"is_superuser", "user_id", "created_by"})


class OwnerlessHost(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Synthetic ownerless ModelView host."""

    model = UserGroup
    pk = ["user_id", "group_id"]
    action_object = "user_group"
    owner_column = None
    policy_name = "user_groups_admin_access"
    superuser_actions = frozenset({"user_group:read", "user_group:create", "user_group:delete"})
    creatable_by_admin = frozenset({"user_id", "group_id"})


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
        for item in self.patches:
            item.start()

    def __exit__(self, *args):
        for item in self.patches:
            item.stop()


def _patch_sessions(session):
    """Return the session patch context manager."""
    return _SessionPatches(session)


class FakePDP:
    """Minimal policy holder used by policy_allows."""

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
    """Minimal model API for direct hook tests."""

    columns = {"user_id": None, "first_name": None, "email": None, "username": None, "is_superuser": None}

    class Meta:
        connection = None
        name = "users"
        schema = "auth"

    def __init__(self, rows=None):
        self.rows = rows or []
        self.calls = []

    def get_columns(self):
        """Return declared columns."""
        return self.columns

    async def get(self, **kwargs):
        """Return the configured row or signal no result."""
        self.calls.append(("get", kwargs))
        if not self.rows:
            from asyncdb.exceptions import NoDataFound

            raise NoDataFound("missing")
        return self.rows[0]


class FakeConnection:
    """Async connection context used for delete target lookup."""

    async def __aenter__(self):
        """Enter the context."""
        return self

    async def __aexit__(self, *args):
        """Leave the context."""
        return False


class Row:
    """Simple owned row."""

    def __init__(self, owner=OWNER_ID):
        self.user_id = owner


def _handler(host=OwnedHost, path="/api/v1/users/42", query="", body=None, model=None, pdp=None):
    """Build a direct hook host with an aiohttp request."""
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", path + query, app=app)
    request["authenticated"] = True
    handler = host.__new__(host)
    handler._request = request
    handler._json = JSONContent()
    handler.model = model or FakeModel()
    handler.get_model = handler.model
    handler.handler = AsyncMock(return_value=FakeConnection())
    handler.json_data = AsyncMock(return_value=body)
    handler._session = _session()
    return handler


class TestWrites:
    """Write hook coverage."""

    @pytest.mark.asyncio
    async def test_put_checks_raw_keys_as_create(self):
        handler = _handler(body={"is_superuser": True})
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await handler._pre_put()

    @pytest.mark.asyncio
    async def test_put_counts_query_string_columns(self):
        handler = _handler(query="?is_superuser=true", body={"first_name": "n"})
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await handler._pre_put()

    @pytest.mark.asyncio
    async def test_post_requires_create_and_update(self):
        handler = _handler(body={"first_name": "n"}, pdp=_pdp(["user:create"]))
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await handler._pre_post()

    @pytest.mark.asyncio
    async def test_post_refuses_slash_in_str_pk(self):
        handler = _handler(path="/api/v1/users/5/6", body={"user_id": "5/6"})
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPBadRequest):
            await handler._pre_post()

    @pytest.mark.asyncio
    async def test_patch_refuses_non_object_body(self):
        handler = _handler(body="text")
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await handler._pre_patch()

    @pytest.mark.asyncio
    async def test_set_update_owner_uses_owner_allowlist(self):
        handler = _handler()
        handler._guard_write_keys = frozenset({"email"})
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await handler._set_update(Row(), {"email": "x@example.test"})

    @pytest.mark.asyncio
    async def test_set_update_without_prehook_fails_closed(self):
        handler = _handler()
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await handler._set_update(Row(), {"first_name": "N"})

    @pytest.mark.asyncio
    async def test_delete_requires_pk(self):
        handler = _handler()
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await handler._del_primary_data({})

    @pytest.mark.asyncio
    async def test_delete_foreign_row_is_404_for_non_superuser(self):
        handler = _handler(model=FakeModel([Row(OTHER_ID)]))
        with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound):
            await handler._del_primary_data({"id": "99"})


class TestReads:
    """Read hook coverage."""

    @pytest.mark.asyncio
    async def test_ownerless_get_superuser_only(self):
        handler = _handler(host=OwnerlessHost)
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await handler._pre_get()

    @pytest.mark.asyncio
    async def test_owned_get_foreign_owner_param_refused(self):
        handler = _handler(query=f"?user_id={OTHER_ID}")
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await handler._pre_get()

    @pytest.mark.asyncio
    async def test_filter_refused_without_public_columns(self):
        handler = _handler()
        with pytest.raises(web.HTTPBadRequest):
            await handler._filtering({"_filter": "first_name=a"})

    @pytest.mark.asyncio
    async def test_head_gated_for_ownerless(self):
        handler = _handler(host=OwnerlessHost)
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await handler.head()


class TestIsolation:
    """Regression guards for inheritance and configuration."""

    def test_feat105_handlers_do_not_inherit_hooks(self):
        assert not issubclass(UserAccountHandler, GuardedModelViewHooks)
        assert not issubclass(UserIdentityHandler, GuardedModelViewHooks)
        assert not issubclass(PartnerKeyHandler, GuardedModelViewHooks)

    def test_missing_action_object_is_501(self):
        class MissingAction(GuardedModelViewHooks):
            pass

        with pytest.raises(web.HTTPNotImplemented):
            MissingAction()._action("read")
