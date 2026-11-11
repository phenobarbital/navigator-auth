"""PermissionHandler on the LOCAL handlers/model.py base (FEAT-107, TASK-155).

The local base has no _pre_* hooks, so these tests drive the VERBS — the same
approach as test_partner_key_handler_access.py.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from datamodel.parsers.json import JSONContent
from navigator.views.model import ModelView

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.model import ModelHandler as LocalBase
from navigator_auth.handlers.permissions import PermissionHandler

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

VERBS = ["get", "head", "put", "patch", "post", "delete"]
POLICY = "permissions_admin_access"
ALL_ACTIONS = ["permission:read", "permission:create", "permission:update", "permission:delete"]


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


def _session(user_id=7, groups=("users",)):
    return FakeSession({"session": {"user_id": user_id, "username": "u", "groups": list(groups)}})


def _su():
    return _session(groups=["superuser"])


class _Patches:
    def __init__(self, session):
        self.ps = [
            patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)),
            patch("navigator_auth.handlers.guards.get_session", new=AsyncMock(return_value=session)),
            patch("navigator_auth.handlers.guards.AuditLog"),
        ]

    def __enter__(self):
        for p in self.ps:
            p.start()

    def __exit__(self, *a):
        for p in self.ps:
            p.stop()


class FakePDP:
    def __init__(self, policies):
        self._evaluator = None
        self._policies = policies
        self._auditlog = MagicMock(log=AsyncMock())

    @property
    def policies(self):
        return self._policies


def _pdp(actions=None):
    pol = Policy(
        POLICY,
        description="d",
        effect=PolicyEffect.ALLOW,
        actions=actions or ALL_ACTIONS,
        groups=["superuser"],
        priority=1,
    )
    return FakePDP([pol])


def _handler(pdp=None, meta=None, body=None):
    app = {"authdb": MagicMock()}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", "/api/v1/permissions/3", app=app)
    request["authenticated"] = True
    if meta:
        request.match_info.update({"meta": meta})
    h = PermissionHandler.__new__(PermissionHandler)
    h._request = request
    h._json = JSONContent()
    h.logger = MagicMock()
    h.json_data = AsyncMock(return_value=body)
    return h


def _ok():
    return web.Response(text="{}", content_type="application/json")


class TestBase:
    def test_permission_handler_uses_baseview_base(self):
        assert issubclass(PermissionHandler, LocalBase)
        assert not issubclass(PermissionHandler, ModelView)

    def test_config_matches_policy_pack(self):
        path = Path(__file__).resolve().parents[3] / "navigator_auth/abac/default_policies/auth_crud_admin_access.yaml"
        pack = yaml.safe_load(path.read_text())
        pol = next(p for p in pack["policies"] if p["name"] == PermissionHandler.policy_name)
        assert set(pol["actions"]) == set(PermissionHandler.superuser_actions)
        assert PermissionHandler.owner_column is None


class TestGates:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("verb", VERBS)
    async def test_every_verb_requires_superuser(self, verb):
        h = _handler(_pdp(), body={"description": "x"})
        with _Patches(_session()), patch.object(LocalBase, verb, new=AsyncMock()) as base:
            with pytest.raises(web.HTTPException) as exc:
                await getattr(h, verb)()
        assert exc.value.status in (403, 404)
        base.assert_not_awaited()
        h.request.app["authdb"].acquire.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("col", ["permission_id", "created_at"])
    async def test_put_refuses_privileged_column(self, col):
        h = _handler(_pdp(), body={"permission": "p", col: 1})
        with _Patches(_su()), patch.object(LocalBase, "put", new=AsyncMock()) as base:
            with pytest.raises(web.HTTPForbidden):
                await h.put()
        base.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_put_allows_permission_and_description(self):
        h = _handler(_pdp(), body={"permission": "p", "description": "d"})
        with _Patches(_su()), patch.object(LocalBase, "put", new=AsyncMock(return_value=_ok())) as base:
            await h.put()
        base.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("verb", ["put", "patch", "post"])
    async def test_unknown_column_refused(self, verb):
        h = _handler(_pdp(), body={"updated_at": "now"})
        with _Patches(_su()), patch.object(LocalBase, verb, new=AsyncMock()) as base:
            with pytest.raises(web.HTTPForbidden):
                await getattr(h, verb)()
        base.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("verb", ["put", "patch", "post"])
    async def test_non_object_body_is_400(self, verb):
        h = _handler(_pdp(), body=["a"])
        with _Patches(_su()), pytest.raises(web.HTTPBadRequest):
            await getattr(h, verb)()

    @pytest.mark.asyncio
    async def test_patch_meta_is_read_gated(self):
        h = _handler(_pdp(["permission:read"]), meta=":meta", body=None)
        with _Patches(_su()), patch.object(LocalBase, "patch", new=AsyncMock(return_value=_ok())) as base:
            await h.patch()
        base.assert_awaited_once()
        h2 = _handler(_pdp(["permission:read"]), meta=":meta")
        with _Patches(_session()), pytest.raises(web.HTTPForbidden):
            await h2.patch()

    @pytest.mark.asyncio
    async def test_patch_update_allowed(self):
        h = _handler(_pdp(), body={"description": "d"})
        with _Patches(_su()), patch.object(LocalBase, "patch", new=AsyncMock(return_value=_ok())) as base:
            await h.patch()
        base.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_post_requires_create_and_update(self):
        h = _handler(_pdp(["permission:create"]), body={"description": "d"})
        with _Patches(_su()), patch.object(LocalBase, "post", new=AsyncMock()) as base:
            with pytest.raises(web.HTTPForbidden):
                await h.post()
        base.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_denied_is_404(self):
        h = _handler(_pdp())
        with _Patches(_session()), pytest.raises(web.HTTPNotFound):
            await h.delete()

    @pytest.mark.asyncio
    async def test_delete_superuser_delegates(self):
        h = _handler(_pdp())
        with _Patches(_su()), patch.object(LocalBase, "delete", new=AsyncMock(return_value=_ok())) as base:
            await h.delete()
        base.assert_awaited_once()
