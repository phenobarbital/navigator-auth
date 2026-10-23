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

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

OWNER_ID = 42
OTHER_ID = 99
POLICY = "user_identities_admin_access"


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


def _allow_policy():
    return Policy(
        POLICY,
        description="d",
        effect=PolicyEffect.ALLOW,
        actions=["identity:read"],
        groups=["superuser"],
        priority=1,
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


def _handler(path="/api/v1/user_identity/abc", query="", model=None, pdp=None, match_info=None):
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


# ---------------------------------------------------------------------------
# Write path (TASK-124)
# ---------------------------------------------------------------------------
class _Row:
    """A fetched row double for _set_update."""

    def __init__(self, owner=OWNER_ID):
        self.user_id = owner
        self.identity_id = "abc"


def _audit_pdp():
    audit = MagicMock()
    audit.log = AsyncMock()
    return FakePDP([_allow_policy_all()], audit), audit


def _allow_policy_all():
    return Policy(
        POLICY,
        description="d",
        effect=PolicyEffect.ALLOW,
        actions=["identity:read", "identity:revoke", "identity:delete"],
        groups=["superuser"],
        priority=1,
    )


def _wh(body=None, model=None, pdp=None, path="/api/v1/user_identity/abc"):
    h = _handler(path=path, model=model, pdp=pdp)
    h.json_data = AsyncMock(return_value=body)
    h._session = _session()
    return h


class TestReadonlyColumns:
    @pytest.mark.asyncio
    async def test_owner_write_to_readonly_column_refused(self):
        h = _wh()
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest) as ei:
            await h._set_update(_Row(), {"access_token": "x"})
        assert "access_token" in ei.value.text

    @pytest.mark.asyncio
    async def test_every_readonly_column_is_refused(self):
        h = _wh()
        with _patch_sessions(_session()):
            for col in UserIdentityHandler.readonly_columns:
                with pytest.raises(web.HTTPBadRequest):
                    await h._set_update(_Row(), {col: "x"})

    @pytest.mark.asyncio
    async def test_readonly_refused_in_a_batched_payload(self):
        h = _wh()
        with pytest.raises(web.HTTPBadRequest):
            h._reject_readonly([{"email": "a@b"}, {"access_token": "x"}])

    @pytest.mark.asyncio
    async def test_refusal_does_not_echo_the_value(self):
        h = _wh()
        with pytest.raises(web.HTTPBadRequest) as ei:
            h._reject_readonly({"access_token": "SENTINEL-TOKEN"})
        assert "SENTINEL-TOKEN" not in ei.value.text

    @pytest.mark.asyncio
    async def test_writable_column_still_accepted(self):
        h = _wh()
        h._reject_readonly({"display_name": "n"})
        with _patch_sessions(_session()), patch("navigator.views.ModelView._set_update", new=AsyncMock()) as up:
            await h._set_update(_Row(), {"display_name": "n"})
        up.assert_awaited_once()


class TestWriteOwnership:
    @pytest.mark.asyncio
    async def test_put_forces_owner(self):
        h = _wh(body={"email": "a@b"})
        with (
            _patch_sessions(_session()),
            patch(
                "navigator.views.ModelView._post_data",
                new=AsyncMock(return_value={"email": "a@b"}),
            ),
        ):
            data = await h._post_data()
        assert data["user_id"] == OWNER_ID

    @pytest.mark.asyncio
    async def test_put_with_foreign_owner_refused(self):
        h = _wh(body={"user_id": OTHER_ID})
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._pre_put()

    @pytest.mark.asyncio
    async def test_superuser_put_for_another_user_refused(self):
        pdp, _ = _audit_pdp()
        h = _wh(body={"user_id": OTHER_ID}, pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            with pytest.raises(web.HTTPForbidden):
                await h._pre_put()

    @pytest.mark.asyncio
    async def test_cross_user_patch_refused_for_non_superuser(self):
        h = _wh()
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(OTHER_ID), {"display_name": "x"})

    @pytest.mark.asyncio
    async def test_owner_patch_needs_no_policy(self):
        h = _wh()
        with _patch_sessions(_session()), patch("navigator.views.ModelView._set_update", new=AsyncMock()):
            await h._set_update(_Row(), {"display_name": "x"})

    @pytest.mark.asyncio
    async def test_owner_cannot_reassign_row(self):
        h = _wh()
        with _patch_sessions(_session()), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(), {"user_id": OTHER_ID})

    @pytest.mark.asyncio
    async def test_patch_null_owner_is_dropped(self):
        h = _wh()
        data = {"display_name": "x", "user_id": None}
        with _patch_sessions(_session()), patch("navigator.views.ModelView._set_update", new=AsyncMock()):
            await h._set_update(_Row(), data)
        assert "user_id" not in data


class TestSuperuserWriteEnvelope:
    @pytest.mark.asyncio
    async def test_superuser_may_revoke_a_foreign_row(self):
        pdp, audit = _audit_pdp()
        h = _wh(pdp=pdp)
        with (
            _patch_sessions(_session(groups=["superuser"])),
            patch("navigator.views.ModelView._set_update", new=AsyncMock()) as up,
        ):
            await h._set_update(_Row(OTHER_ID), {"enabled": False})
        up.assert_awaited_once()
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_superuser_cannot_edit_another_column(self):
        pdp, _ = _audit_pdp()
        h = _wh(pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(OTHER_ID), {"display_name": "x"})

    @pytest.mark.asyncio
    async def test_superuser_cannot_smuggle_a_column_alongside_the_revoke(self):
        pdp, _ = _audit_pdp()
        h = _wh(pdp=pdp)
        with (
            _patch_sessions(_session(groups=["superuser"])),
            patch("navigator.views.ModelView._set_update", new=AsyncMock()) as up,
        ):
            with pytest.raises(web.HTTPForbidden):
                await h._set_update(_Row(OTHER_ID), {"enabled": False, "email": "a@x"})
        up.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_superuser_enable_true_is_not_a_revoke(self):
        pdp, _ = _audit_pdp()
        h = _wh(pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(OTHER_ID), {"enabled": True})

    @pytest.mark.asyncio
    async def test_superuser_revoke_denied_without_policy(self):
        h = _wh()
        with _patch_sessions(_session(groups=["superuser"])), pytest.raises(web.HTTPForbidden):
            await h._set_update(_Row(OTHER_ID), {"enabled": False})


class _DelModel(FakeModel):
    async def get(self, **kw):
        self.calls.append(("get", kw))
        if not self.rows:
            from asyncdb.exceptions import NoDataFound

            raise NoDataFound("none")
        return _Row(self.rows[0]["user_id"])


class TestDeletePath:
    @pytest.mark.asyncio
    async def test_owner_may_delete_own_row(self):
        h = _wh(model=_DelModel([_row()]))
        with _patch_sessions(_session()):
            assert await h._del_primary_data({"id": "abc"}) == "abc"

    @pytest.mark.asyncio
    async def test_foreign_delete_returns_404(self):
        h = _wh(model=_DelModel([_row(OTHER_ID)]))
        with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound):
            await h._del_primary_data({"id": "abc"})

    @pytest.mark.asyncio
    async def test_foreign_and_missing_delete_are_indistinguishable(self):
        out = []
        for rows in ([_row(OTHER_ID)], []):
            h = _wh(model=_DelModel(rows))
            with _patch_sessions(_session()), pytest.raises(web.HTTPNotFound) as ei:
                await h._del_primary_data({"id": "abc"})
            out.append((ei.value.status, ei.value.text))
        assert out[0] == out[1]

    @pytest.mark.asyncio
    async def test_delete_without_id_is_refused(self):
        h = _wh(model=_DelModel([_row()]))
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await h._del_primary_data({})

    @pytest.mark.asyncio
    async def test_superuser_delete_is_allowed_and_audited(self):
        pdp, audit = _audit_pdp()
        h = _wh(model=_DelModel([_row(OTHER_ID)]), pdp=pdp)
        with _patch_sessions(_session(groups=["superuser"])):
            assert await h._del_primary_data({"id": "abc"}) == "abc"
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unauthenticated_write_is_401(self):
        h = _wh()
        with _patch_sessions(None), pytest.raises(web.HTTPUnauthorized):
            await h._pre_delete()


# ---------------------------------------------------------------------------
# Response redaction (TASK-125)
# ---------------------------------------------------------------------------
import json  # noqa: E402

CREDENTIALS = ("access_token", "refresh_token", "id_token", "key_version")
SENTINEL = b"SENTINEL-TOKEN-BYTES"


def _full_row(owner=OWNER_ID):
    return {
        "identity_id": "abc",
        "user_id": owner,
        "email": "e@x",
        "auth_provider": "git",
        "auth_data": {"n": 1},
        "scopes": ["s"],
        "access_token": SENTINEL,
        "refresh_token": b"rt",
        "id_token": b"it",
        "key_version": 3,
        "enabled": True,
    }


class _Capture:
    """Capture what reaches upstream's _model_response."""

    def __init__(self):
        self.payload = None

    async def __call__(self, response, fields=None, headers=None, status=200):
        self.payload = response
        return web.Response(text="ok")


def _body(payload):
    return json.dumps(payload, default=lambda o: repr(o))


class TestResponseRedaction:
    async def _run(self, response, fields=None):
        h = _handler()
        cap = _Capture()
        with patch("navigator.views.ModelView._model_response", new=cap):
            await h._model_response(response, fields=fields)
        return cap.payload

    @pytest.mark.asyncio
    async def test_no_credential_key_in_any_response(self):
        out = await self._run(_full_row())
        assert not (set(out) & set(CREDENTIALS))
        assert out["has_refresh_token"] is True and out["profile"] == {"n": 1}

    @pytest.mark.asyncio
    async def test_fields_param_cannot_project_credentials(self):
        out = await self._run(_full_row(), ["access_token", "refresh_token", "email"])
        assert out == {"email": "e@x"}

    @pytest.mark.asyncio
    async def test_fields_naming_only_credentials_returns_no_data(self):
        out = await self._run(_full_row(), ["access_token"])
        assert out == {}

    @pytest.mark.asyncio
    async def test_superuser_response_is_redacted_too(self):
        out = await self._run(_full_row(OTHER_ID))
        assert not (set(out) & set(CREDENTIALS))

    @pytest.mark.asyncio
    async def test_list_and_scalar_shapes_preserved(self):
        assert isinstance(await self._run([_full_row()]), list)
        assert isinstance(await self._run(_full_row()), dict)

    @pytest.mark.asyncio
    async def test_no_token_bytes_anywhere_in_the_payload(self):
        out = await self._run([_full_row()])
        assert "SENTINEL" not in _body(out)

    @pytest.mark.asyncio
    async def test_write_responses_are_scrubbed(self):
        h = _handler()
        scrubbed = h._scrub(_full_row())
        assert not (set(scrubbed) & set(CREDENTIALS))
        assert h._scrub({"message": "gone"}) == {"message": "gone"}
        assert h._scrub([_full_row()])[0].get("access_token") is None


class TestMetaRedaction:
    @pytest.mark.asyncio
    async def test_meta_strips_credential_columns(self):
        from navigator_auth.models import UserIdentity

        h = _handler()
        h.get_model = UserIdentity
        resp = await h._get_meta_info(":meta", None)
        body = json.loads(resp.text)
        assert not (set(body["properties"]) & set(CREDENTIALS))
        assert "email" in body["properties"]

    @pytest.mark.asyncio
    async def test_sample_strips_credential_columns(self):
        h = _handler()
        h.get_model = MagicMock()
        h.get_model.sample.return_value = {"email": "a", "access_token": "x"}
        resp = await h._get_meta_info(":sample", None)
        assert json.loads(resp.text) == {"email": "a"}

    @pytest.mark.asyncio
    async def test_meta_does_not_mutate_the_cached_schema(self):
        from navigator_auth.models import UserIdentity

        h = _handler()
        h.get_model = UserIdentity
        await h._get_meta_info(":meta", None)
        assert "access_token" in UserIdentity.schema(as_dict=True)["properties"]

    @pytest.mark.asyncio
    async def test_meta_returns_none_for_a_non_meta_request(self):
        assert await _handler()._get_meta_info(None, None) is None

    @pytest.mark.asyncio
    async def test_head_x_columns_has_no_credentials(self):
        from navigator_auth.models import UserIdentity

        h = _handler()
        h.get_model = UserIdentity
        with patch(
            "navigator.views.ModelView.head",
            new=AsyncMock(return_value=web.Response(headers={"X-Columns": "all"})),
        ):
            resp = await h.head()
        assert not any(c in resp.headers["X-Columns"] for c in CREDENTIALS)
        assert "email" in resp.headers["X-Columns"]


class _FilterModel(FakeModel):
    columns = {
        "identity_id": None,
        "user_id": None,
        "email": None,
        "auth_provider": None,
        "access_token": None,
    }


class _FConn:
    def __init__(self):
        self.calls = []

    async def fetch_all(self, sql, *args):
        self.calls.append((sql, args))
        return [{"email": "a@b", "auth_provider": "git"}]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _fh(conn):
    h = _handler(model=_FilterModel())
    h.handler = AsyncMock(return_value=conn)
    return h


class TestSafeFilterWiring:
    @pytest.mark.asyncio
    async def test_filter_on_credential_column_is_400(self):
        conn = _FConn()
        h = _fh(conn)
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await h._filtering({"_filter": "access_token=x"})
        assert conn.calls == []

    @pytest.mark.asyncio
    async def test_filter_on_public_column_is_parameterized(self):
        conn = _FConn()
        h = _fh(conn)
        with _patch_sessions(_session()):
            resp = await h._filtering({"_filter": "auth_provider=git"})
        assert resp is not None
        sql, args = conn.calls[0]
        assert "$1" in sql and "git" in args[0]

    @pytest.mark.asyncio
    async def test_filter_result_is_redacted(self):
        conn = _FConn()
        h = _fh(conn)
        cap = _Capture()
        with _patch_sessions(_session()), patch("navigator.views.ModelView._model_response", new=cap):
            await h._filtering({"_filter": "auth_provider=git"})
        assert not (set(cap.payload[0]) & set(CREDENTIALS))

    @pytest.mark.asyncio
    async def test_filtering_returns_none_without_the_parameter(self):
        assert await _handler()._filtering({}) is None

    @pytest.mark.asyncio
    async def test_upstream_filtering_is_unreachable(self):
        conn = _FConn()
        h = _fh(conn)
        boom = MagicMock(side_effect=AssertionError("upstream _filtering called"))
        with _patch_sessions(_session()), patch("navigator.views.ModelView._filtering", new=boom):
            await h._filtering({"_filter": "auth_provider=git"})
        boom.assert_not_called()


class TestReviewRegressions:
    @pytest.mark.asyncio
    async def test_single_attribute_patch_form_refused(self):
        """A non-JSON PATCH body bypasses _set_update upstream => 400."""
        h = _wh()
        with (
            _patch_sessions(_session()),
            patch(
                "navigator.views.ModelView._patch_data",
                new=AsyncMock(return_value="evil"),
            ),
            pytest.raises(web.HTTPBadRequest),
        ):
            await h._patch_data()

    @pytest.mark.asyncio
    async def test_put_vault_column_in_query_string_refused(self):
        h = _wh(path="/api/v1/user_identity")
        h._request = make_mocked_request(
            "PUT",
            "/api/v1/user_identity?access_token=x",
            app={"auth": MagicMock()},
        )
        with _patch_sessions(_session()), pytest.raises(web.HTTPBadRequest):
            await h._pre_put()

    @pytest.mark.asyncio
    async def test_patch_meta_has_no_credentials(self):
        from navigator_auth.models import UserIdentity

        h = _wh()
        h.model = UserIdentity
        h._request.match_info.update({"meta": ":meta"})
        with _patch_sessions(_session()):
            resp = await h.patch()
        names = json.loads(resp.text)
        assert "email" in names and not (set(names) & set(CREDENTIALS))


class TestCodexReviewRegressions:
    @pytest.mark.asyncio
    async def test_patch_meta_requires_authentication(self):
        h = _wh()
        h._request.match_info.update({"meta": ":meta"})
        with _patch_sessions(None), pytest.raises(web.HTTPUnauthorized):
            await h.patch()

    @pytest.mark.asyncio
    async def test_superuser_revoke_post_for_unknown_pk_refused(self):
        pdp, _ = _audit_pdp()
        h = _wh(pdp=pdp, model=FakeModel([]))  # get() -> None: row missing
        body = {"identity_id": "new", "user_id": OTHER_ID, "enabled": False}
        with (
            _patch_sessions(_session(groups=["superuser"])),
            patch(
                "navigator.views.ModelView._post_data",
                new=AsyncMock(return_value=dict(body)),
            ),
            pytest.raises(web.HTTPForbidden),
        ):
            await h._post_data()

    @pytest.mark.asyncio
    async def test_superuser_revoke_post_for_existing_pk_allowed(self):
        pdp, _ = _audit_pdp()
        h = _wh(pdp=pdp, model=_DelModel([_row(OTHER_ID)]))
        body = {"identity_id": "abc", "user_id": OTHER_ID, "enabled": False}
        with (
            _patch_sessions(_session(groups=["superuser"])),
            patch(
                "navigator.views.ModelView._post_data",
                new=AsyncMock(return_value=dict(body)),
            ),
        ):
            assert (await h._post_data())["user_id"] == OTHER_ID
