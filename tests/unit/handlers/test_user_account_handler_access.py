"""Access control and redaction on UserAccountHandler (FEAT-105, TASK-126).

`_set_address`'s parameterization is TASK-121's (test_user_account_set_address.py).
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from datamodel.parsers.json import JSONContent

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.userattrs import UserAccountHandler
from navigator_auth.models import UserAccount

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

OWNER_ID = 42
OTHER_ID = 99
POLICY = "user_accounts_admin_access"
PUBLIC = frozenset(
    {
        "account_id",
        "user_id",
        "provider",
        "uid",
        "address",
        "account",
        "created_at",
    }
)


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


def _session(user_id=OWNER_ID, groups=("users",)):
    return FakeSession({"session": {"user_id": user_id, "username": "u", "groups": list(groups)}})


class _Patches:
    def __init__(self, session):
        self.ps = [
            patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)),
            patch("navigator_auth.handlers.guards.get_session", new=AsyncMock(return_value=session)),
        ]

    def __enter__(self):
        for p in self.ps:
            p.start()

    def __exit__(self, *a):
        for p in self.ps:
            p.stop()


def _patch_sessions(session):
    return _Patches(session)


class FakePDP:
    def __init__(self, policies, auditlog=None):
        self._evaluator = None
        self._policies = policies
        self._auditlog = auditlog

    @property
    def policies(self):
        return self._policies


def _pdp():
    audit = MagicMock()
    audit.log = AsyncMock()
    pol = Policy(
        POLICY,
        description="d",
        effect=PolicyEffect.ALLOW,
        actions=["account:read", "account:delete"],
        groups=["superuser"],
        priority=1,
    )
    return FakePDP([pol], audit), audit


class FakeModel:
    columns = {"account_id": None, "user_id": None, "provider": None}

    class Meta:
        connection = None
        name = "user_accounts"
        schema = "auth"

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []
        self.calls = []

    def get_columns(self):
        return self.columns

    async def get(self, **kw):
        self.calls.append(("get", kw))
        if not self.rows:
            from asyncdb.exceptions import NoDataFound

            raise NoDataFound("none")
        return self.rows[0]

    async def filter(self, **kw):
        self.calls.append(("filter", kw))
        return [MagicMock(to_dict=MagicMock(return_value=r)) for r in self.rows]


class _Row:
    def __init__(self, owner=OWNER_ID):
        self.user_id = owner
        self.account_id = "abc"


class FakeConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _handler(path="/api/v1/user_accounts/abc", query="", model=None, pdp=None, body=None):
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", path + query, app=app)
    request["authenticated"] = True
    h = UserAccountHandler.__new__(UserAccountHandler)
    h._request = request
    h._json = JSONContent()
    h.model = model or FakeModel()
    h.get_model = h.model
    h.handler = AsyncMock(return_value=FakeConn())
    h.json_data = AsyncMock(return_value=body)
    h._session = _session()
    return h


class TestConfiguration:
    def test_guard_precedes_the_base_in_the_mro(self):
        from navigator.views import ModelView
        from navigator_auth.handlers.guards import OwnerOrSuperuserGuard

        mro = UserAccountHandler.__mro__
        assert mro.index(OwnerOrSuperuserGuard) < mro.index(ModelView)

    def test_credential_columns_is_empty(self):
        assert UserAccountHandler.credential_columns == frozenset()

    def test_public_columns_covers_every_model_column(self):
        assert set(UserAccount.get_columns()) == PUBLIC
        assert UserAccountHandler.public_columns == PUBLIC

    def test_policy_name_and_actions_match_the_pack(self):
        assert UserAccountHandler.policy_name == POLICY
        assert UserAccountHandler.superuser_actions == frozenset({"account:read", "account:delete"})

    def test_hidden_lists_are_per_subclass(self):
        from navigator.views import ModelView

        assert UserAccountHandler._hidden is not ModelView._hidden


class TestReadPath:
    @pytest.mark.asyncio
    async def test_unauthenticated_read_is_401(self):
        with _patch_sessions(None), pytest.raises(web.HTTPUnauthorized):
            await _handler()._pre_get()

    @pytest.mark.asyncio
    async def test_get_forces_owner_filter(self):
        model = FakeModel([{"user_id": OWNER_ID}])
        h = _handler(path="/api/v1/user_accounts", model=model)
        with _patch_sessions(_session()):
            await h._get_data({}, {})
        assert model.calls == [("filter", {"user_id": OWNER_ID})]

    @pytest.mark.asyncio
    async def test_get_foreign_row_returns_404_identical_to_missing(self):
        out = []
        for _ in range(2):
            h = _handler(model=FakeModel([]))
            with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound) as ei:
                await h._get_data({}, {"account_id": "abc"})
            out.append((ei.value.status, ei.value.text))
        assert out[0] == out[1]

    @pytest.mark.asyncio
    async def test_get_foreign_user_id_param_refused(self):
        h = _handler(query=f"?user_id={OTHER_ID}")
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._pre_get()

    @pytest.mark.asyncio
    async def test_superuser_may_read_a_foreign_row_and_is_audited(self):
        pdp, audit = _pdp()
        model = FakeModel([{"user_id": OTHER_ID}])
        h = _handler(model=model, pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            await h._get_data({}, {"account_id": "abc"})
        assert "user_id" not in model.calls[0][1]
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_superuser_denied_without_policy_but_owner_is_not(self):
        with _patch_sessions(_session(groups=["superuser"])):
            h = _handler(path="/api/v1/user_accounts", model=FakeModel([{"user_id": 1}]))
            with pytest.raises(web.HTTPForbidden):
                await h._get_data({"user_id": str(OTHER_ID)}, {})
            h = _handler(path="/api/v1/user_accounts", model=FakeModel([{"user_id": OWNER_ID}]))
            await h._get_data({}, {})

    @pytest.mark.asyncio
    async def test_model_without_owner_column_fails_closed(self):
        model = FakeModel()
        model.columns = {"account_id": None}
        with _patch_sessions(_session()), pytest.raises(web.HTTPNotImplemented):
            await _handler(model=model)._pre_get()


class TestWritePath:
    @pytest.mark.asyncio
    async def test_put_forces_owner(self):
        h = _handler()
        with (
            _patch_sessions(_session()),
            patch(
                "navigator.views.ModelView._post_data",
                new=AsyncMock(return_value={"provider": "x"}),
            ),
        ):
            data = await h._post_data()
        assert data["user_id"] == OWNER_ID

    @pytest.mark.asyncio
    async def test_put_with_foreign_owner_refused(self):
        h = _handler(body={"user_id": OTHER_ID})
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._pre_put()

    @pytest.mark.asyncio
    async def test_post_data_delegates_to_super(self):
        h = _handler()
        sup = AsyncMock(return_value={"provider": "x", "user_id": OWNER_ID})
        with _patch_sessions(_session()), patch("navigator.views.ModelView._post_data", new=sup):
            await h._post_data()
        sup.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_user_id_and_set_address_still_defined(self):
        assert "_set_user_id" in UserAccountHandler.__dict__
        assert "_set_address" in UserAccountHandler.__dict__

    @pytest.mark.asyncio
    async def test_cross_user_patch_refused(self):
        h = _handler()
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(OTHER_ID), {"provider": "x"})

    @pytest.mark.asyncio
    async def test_superuser_cross_user_patch_refused(self):
        pdp, audit = _pdp()
        h = _handler(pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(OTHER_ID), {"provider": "x"})
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_owner_patch_needs_no_policy(self):
        h = _handler()
        with _patch_sessions(_session()), patch("navigator.views.ModelView._set_update", new=AsyncMock()) as up:
            await h._set_update(_Row(), {"provider": "x"})
        up.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_owner_cannot_reassign_row(self):
        h = _handler()
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(), {"user_id": OTHER_ID})

    @pytest.mark.asyncio
    async def test_owner_may_delete_own_row(self):
        h = _handler(model=FakeModel([_Row()]))
        with _patch_sessions(_session()):
            assert await h._del_primary_data({"id": "abc"}) == "abc"

    @pytest.mark.asyncio
    async def test_foreign_delete_returns_404(self):
        h = _handler(model=FakeModel([_Row(OTHER_ID)]))
        with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound):
            await h._del_primary_data({"id": "abc"})

    @pytest.mark.asyncio
    async def test_delete_without_id_is_refused(self):
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await _handler()._del_primary_data({})

    @pytest.mark.asyncio
    async def test_superuser_delete_allowed_and_audited(self):
        pdp, audit = _pdp()
        h = _handler(model=FakeModel([_Row(OTHER_ID)]), pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            assert await h._del_primary_data({"id": "abc"}) == "abc"
        audit.log.assert_awaited_once()


class _Capture:
    def __init__(self):
        self.payload = None

    async def __call__(self, response, fields=None, headers=None, status=200):
        self.payload = response
        return web.Response(text="ok")


class _FConn(FakeConn):
    def __init__(self):
        self.calls = []

    async def fetch_all(self, sql, *args):
        self.calls.append((sql, args))
        return [{"provider": "git"}]


class TestProjectionAndFilter:
    @pytest.mark.asyncio
    async def test_response_is_restricted_to_public_columns(self):
        h = _handler()
        cap = _Capture()
        row = {"account_id": "a", "user_id": 1, "provider": "x", "secret_extra": "S"}
        with patch("navigator.views.ModelView._model_response", new=cap):
            await h._model_response(row)
        assert "secret_extra" not in cap.payload

    @pytest.mark.asyncio
    async def test_fields_param_is_intersected(self):
        h = _handler()
        cap = _Capture()
        with patch("navigator.views.ModelView._model_response", new=cap):
            await h._model_response({"provider": "x", "secret_extra": "S"}, ["provider", "secret_extra"])
        assert cap.payload == {"provider": "x"}

    @pytest.mark.asyncio
    async def test_meta_is_bounded_and_does_not_mutate(self):
        h = _handler()
        h.get_model = UserAccount
        resp = await h._get_meta_info(":meta", None)
        assert set(json.loads(resp.text)["properties"]) == PUBLIC
        assert "provider" in UserAccount.schema(as_dict=True)["properties"]

    @pytest.mark.asyncio
    async def test_head_x_columns_is_bounded(self):
        h = _handler()
        h.get_model = UserAccount
        with patch(
            "navigator.views.ModelView.head",
            new=AsyncMock(return_value=web.Response(headers={"X-Columns": "all"})),
        ):
            resp = await h.head()
        assert "provider" in resp.headers["X-Columns"]

    @pytest.mark.asyncio
    async def test_filter_on_unknown_column_is_400(self):
        conn = _FConn()
        h = _handler()
        h.handler = AsyncMock(return_value=conn)
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await h._filtering({"_filter": "nonsense=x"})
        assert conn.calls == []

    @pytest.mark.asyncio
    async def test_filter_is_parameterized_and_ands_owner(self):
        conn = _FConn()
        h = _handler()
        h.handler = AsyncMock(return_value=conn)
        with _patch_sessions(_session()):
            await h._filtering({"_filter": "provider=git"})
        sql, args = conn.calls[0]
        assert "$1" in sql and '"user_id" = $2' in sql and OWNER_ID in args

    @pytest.mark.asyncio
    async def test_filtering_returns_none_without_the_parameter(self):
        assert await _handler()._filtering({}) is None

    @pytest.mark.asyncio
    async def test_upstream_filtering_is_unreachable(self):
        conn = _FConn()
        h = _handler()
        h.handler = AsyncMock(return_value=conn)
        boom = MagicMock(side_effect=AssertionError("upstream called"))
        with _patch_sessions(_session()), patch("navigator.views.ModelView._filtering", new=boom):
            await h._filtering({"_filter": "provider=git"})
        boom.assert_not_called()
