"""Read-path access control on UserIdentityHandler (FEAT-105, TASK-123).

Response CONTENTS (redaction, :meta, _filter) are TASK-125's tests.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from datamodel.parsers.json import JSONContent
from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.userattrs import UserIdentityHandler

pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)

OWNER_ID = 42
OTHER_ID = 99
POLICY = "user_identities_admin_access"


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


def _session(user_id=OWNER_ID, groups=("users",)):
    return FakeSession({"session": {
        "user_id": user_id, "username": "u", "groups": list(groups)}})


class _Patches:
    def __init__(self, session):
        self.ps = [
            patch("navigator_auth.decorators.get_session",
                  new=AsyncMock(return_value=session)),
            patch("navigator_auth.handlers.guards.get_session",
                  new=AsyncMock(return_value=session)),
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


def _allow_policy():
    return Policy(
        POLICY, description="d", effect=PolicyEffect.ALLOW,
        actions=["identity:read"], groups=["superuser"], priority=1,
    )


class FakeModel:
    """Records every query the upstream _get_data issues."""

    columns = {"identity_id": None, "user_id": None, "email": None}

    class Meta:
        connection = None
        name = "user_identities"
        schema = "auth"

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []
        self.calls = []

    def get_columns(self):
        return self.columns

    async def get(self, **kw):
        self.calls.append(("get", kw))
        if not self.rows:
            return None
        return self.rows[0]

    async def filter(self, **kw):
        self.calls.append(("filter", kw))
        return [MagicMock(to_dict=MagicMock(return_value=r)) for r in self.rows]

    async def all(self):
        self.calls.append(("all", {}))
        return []


class FakeConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _handler(path="/api/v1/user_identity/abc", query="", model=None,
             pdp=None, match_info=None):
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", path + query, app=app)
    request["authenticated"] = True
    if match_info:
        request.match_info.update(match_info)
    h = UserIdentityHandler.__new__(UserIdentityHandler)
    h._request = request
    h._json = JSONContent()
    h.model = model or FakeModel()
    h.get_model = h.model
    h.handler = AsyncMock(return_value=FakeConn())
    return h


def _row(owner=OWNER_ID):
    return {"identity_id": "abc", "user_id": owner, "email": "e"}


class TestOwnerColumnGate:
    @pytest.mark.asyncio
    async def test_model_without_owner_column_fails_closed(self):
        model = FakeModel()
        model.columns = {"identity_id": None}
        h = _handler(model=model)
        with _patch_sessions(_session()), pytest.raises(web.HTTPNotImplemented):
            await h._pre_get()


class TestReadPathOwnership:
    @pytest.mark.asyncio
    async def test_get_forces_owner_filter(self):
        model = FakeModel([_row()])
        h = _handler(path="/api/v1/user_identity", model=model)
        with _patch_sessions(_session()):
            await h._get_data({}, {})
        assert model.calls == [("filter", {"user_id": OWNER_ID})]

    @pytest.mark.asyncio
    async def test_get_forces_owner_filter_on_pk(self):
        model = FakeModel([_row()])
        h = _handler(model=model)
        with _patch_sessions(_session()):
            await h._get_data({}, {"identity_id": "abc"})
        assert model.calls[0][1]["user_id"] == OWNER_ID
        assert model.calls[0][1]["identity_id"] == "abc"

    @pytest.mark.asyncio
    async def test_get_foreign_row_returns_404(self):
        h = _handler(model=FakeModel([]))
        with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound) as ei:
            await h._get_data({}, {"identity_id": "abc"})
        assert str(OTHER_ID) not in ei.value.text
        assert "email" not in ei.value.text

    @pytest.mark.asyncio
    async def test_missing_row_and_foreign_row_are_indistinguishable(self):
        texts = []
        for rows in ([], []):
            h = _handler(model=FakeModel(rows))
            with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound) as ei:
                await h._get_data({}, {"identity_id": "abc"})
            texts.append((ei.value.status, ei.value.text))
        assert texts[0] == texts[1]

    @pytest.mark.asyncio
    async def test_get_foreign_user_id_param_refused(self):
        model = FakeModel([_row()])
        h = _handler(query=f"?user_id={OTHER_ID}", model=model)
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._pre_get()
        assert model.calls == []

    @pytest.mark.asyncio
    async def test_own_user_id_param_is_accepted(self):
        model = FakeModel([_row()])
        h = _handler(path="/api/v1/user_identity", model=model)
        with _patch_sessions(_session()):
            await h._get_data({"user_id": str(OWNER_ID)}, {})
        assert model.calls == [("filter", {"user_id": OWNER_ID})]

    @pytest.mark.asyncio
    async def test_superuser_may_read_a_foreign_row(self):
        audit = MagicMock()
        audit.log = AsyncMock()
        pdp = FakePDP([_allow_policy()], audit)
        model = FakeModel([_row(OTHER_ID)])
        h = _handler(model=model, pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            res = await h._get_data({}, {"identity_id": "abc"})
        assert res["user_id"] == OTHER_ID
        assert "user_id" not in model.calls[0][1]

    @pytest.mark.asyncio
    async def test_superuser_cross_user_list_read_is_audited(self):
        audit = MagicMock()
        audit.log = AsyncMock()
        pdp = FakePDP([_allow_policy()], audit)
        model = FakeModel([_row(OTHER_ID)])
        h = _handler(path="/api/v1/user_identity", model=model, pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            await h._get_data({"user_id": str(OTHER_ID)}, {})
        assert model.calls == [("filter", {"user_id": str(OTHER_ID)})]
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_superuser_cross_user_pk_read_is_audited_once(self):
        audit = MagicMock()
        audit.log = AsyncMock()
        pdp = FakePDP([_allow_policy()], audit)
        h = _handler(model=FakeModel([_row(OTHER_ID)]), pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            await h._get_data({}, {"identity_id": "abc"})
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_superuser_without_policy_is_denied_but_owner_is_not(self):
        with _patch_sessions(_session(groups=["superuser"])):
            h = _handler(model=FakeModel([_row(OTHER_ID)]))
            with pytest.raises(web.HTTPNotFound):
                await h._get_data({}, {"identity_id": "abc"})
            h = _handler(path="/api/v1/user_identity", model=FakeModel([_row(OTHER_ID)]))
            with pytest.raises(web.HTTPForbidden):
                await h._get_data({"user_id": str(OTHER_ID)}, {})
            h = _handler(model=FakeModel([_row()]))
            assert (await h._get_data({}, {"identity_id": "abc"}))["user_id"] == OWNER_ID

    @pytest.mark.asyncio
    async def test_unauthenticated_read_is_401(self):
        h = _handler()
        with _patch_sessions(None), pytest.raises(web.HTTPUnauthorized):
            await h._pre_get()


class TestMetadataLists:
    def test_hidden_lists_are_per_subclass(self):
        from navigator.views import ModelView
        assert UserIdentityHandler._hidden is not ModelView._hidden
        assert UserIdentityHandler._required is not ModelView._required
        assert UserIdentityHandler._primaries is not ModelView._primaries

    @pytest.mark.asyncio
    async def test_set_user_id_unchanged(self):
        h = _handler()
        h._session = _session()
        assert await h._set_user_id(None, None, {}) == OWNER_ID
