"""Cross-surface ownership and redaction, end to end (FEAT-105, TASK-128).

The unit suites in tests/unit/handlers/ prove each method; these scenarios
prove the SEQUENCES the acceptance criteria are written about — e.g. "the
token is returned exactly once" is a property of a create-then-read pair.

In-process and connection-mocked, like the rest of this suite: no database.
The ABAC pack is the SHIPPED auth_model_admin_access.yaml, parsed with
YAMLStorage and turned into real ResourcePolicy objects, so the policy names,
actions and resource patterns are exercised against the guard for real.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from datamodel.parsers.json import JSONContent

from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.handlers.model import ModelHandler as LocalBase
from navigator_auth.handlers.partners import PartnerKeyHandler
from navigator_auth.handlers.userattrs import UserAccountHandler, UserIdentityHandler
from navigator_auth.identity.store import IdentityStore

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

OWNER_ID = 42
SUPERUSER_ID = 7
OTHER_ID = 99

SENTINEL_ACCESS = b"SENTINEL-ACCESS-TOKEN-BYTES"
SENTINEL_REFRESH = b"SENTINEL-REFRESH-TOKEN-BYTES"
SENTINEL_JWT = "eyJhbGciOiJIUzI1NiJ9.SENTINEL-PARTNER.signature"
SENTINELS = ("SENTINEL-ACCESS", "SENTINEL-REFRESH", "SENTINEL-PARTNER")

PACK = (
    Path(__file__).resolve().parents[2]
    / "navigator_auth"
    / "abac"
    / "default_policies"
    / "auth_model_admin_access.yaml"
)


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


class FakePDP:
    """Minimal PDP stub exposing ``policies`` and an audit sink."""

    def __init__(self, policies, auditlog):
        self._evaluator = None
        self._policies = policies
        self._auditlog = auditlog

    @property
    def policies(self):
        return self._policies


class FakeModel:
    """Row store double for the upstream ModelView data path."""

    def __init__(self, columns, rows):
        self._columns = columns
        self.rows = rows
        self.calls = []

    class Meta:
        connection = None
        name = "t"
        schema = "auth"

    def get_columns(self):
        return self._columns

    async def get(self, **kw):
        self.calls.append(("get", kw))
        want = {k: v for k, v in kw.items()}
        for r in self.rows:
            if all(r.get(k) == v for k, v in want.items()):
                return _Obj(r)
        from asyncdb.exceptions import NoDataFound

        raise NoDataFound("none")

    async def filter(self, **kw):
        self.calls.append(("filter", kw))
        return [
            MagicMock(to_dict=MagicMock(return_value=r)) for r in self.rows if all(r.get(k) == v for k, v in kw.items())
        ]


class _Obj:
    def __init__(self, d):
        self.__dict__.update(d)

    def to_dict(self):
        return dict(self.__dict__)


class FakeConn:
    def __init__(self):
        self.calls = []

    async def fetch_all(self, sql, *args):
        self.calls.append((sql, args))
        return []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


@pytest.fixture
def owner_session():
    return FakeSession({"session": {"user_id": OWNER_ID, "username": "owner", "groups": ["users"]}})


@pytest.fixture
def superuser_session():
    return FakeSession({"session": {"user_id": SUPERUSER_ID, "username": "root", "groups": ["superuser"]}})


@pytest.fixture
def identity_row():
    """UserIdentity row dict: ciphered token columns, PII, foreign owner."""
    return {
        "identity_id": "11111111-1111-1111-1111-111111111111",
        "user_id": OTHER_ID,
        "display_name": "D",
        "title": None,
        "nickname": None,
        "email": "o@x",
        "phone": None,
        "short_bio": None,
        "avatar": None,
        "auth_provider": "git",
        "provider_user_id": "p1",
        "scopes": ["repo"],
        "token_type": "Bearer",
        "expires_at": None,
        "refreshed_at": None,
        "created_at": None,
        "enabled": True,
        "auth_data": {"login": "octo"},
        "attributes": {},
        "access_token": SENTINEL_ACCESS,
        "refresh_token": SENTINEL_REFRESH,
        "id_token": None,
        "key_version": 1,
    }


@pytest.fixture
def account_row():
    return {
        "account_id": "a1",
        "user_id": OWNER_ID,
        "provider": "git",
        "uid": "octo",
        "address": "https://x/octo",
        "account": {},
        "created_at": None,
    }


@pytest.fixture
def partner_row():
    return {
        "partner_id": "p1",
        "name": "n",
        "partner": "x",
        "issuer": "navigator",
        "token": SENTINEL_JWT,
        "created_at": None,
        "revoked": False,
        "enabled": True,
        "grants": {},
        "programs": [],
    }


@pytest.fixture
def recording_conn():
    return FakeConn()


@pytest.fixture
def audit():
    log = MagicMock()
    log.log = AsyncMock()
    return log


@pytest.fixture
def pdp_with_pack(audit):
    """A PDP carrying the three FEAT-105 policies from the shipped pack."""
    assert PACK.exists(), f"policy pack missing: {PACK}"
    policies = []
    for d in YAMLStorage._parse_file(PACK):
        policies.append(
            ResourcePolicy(
                name=d["name"],
                effect=PolicyEffect.ALLOW,
                description=d.get("description"),
                resources=d["resources"],
                actions=d["actions"],
                subjects=d["subjects"],
                priority=d["priority"],
                enforcing=d["enforcing"],
            )
        )
    return FakePDP(policies, audit)


class _Sessions:
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
    return _Sessions(session)


def _request(path, pdp=None, query="", meta=None):
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", path + query, app=app)
    request["authenticated"] = True
    if meta:
        request.match_info.update({"meta": meta})
    return request


def _crud(cls, path, model, pdp=None, query="", meta=None, body=None):
    h = cls.__new__(cls)
    h._request = _request(path, pdp, query, meta)
    h._json = JSONContent()
    h.logger = MagicMock()
    h.model = model
    h.get_model = model
    h.handler = AsyncMock(return_value=FakeConn())
    h.json_data = AsyncMock(return_value=body)
    h._session = FakeSession({"session": {"user_id": OWNER_ID}})
    return h


IDENTITY_COLUMNS = {
    c: None
    for c in (
        "identity_id",
        "user_id",
        "display_name",
        "title",
        "nickname",
        "email",
        "phone",
        "short_bio",
        "avatar",
        "auth_provider",
        "provider_user_id",
        "scopes",
        "token_type",
        "expires_at",
        "refreshed_at",
        "created_at",
        "enabled",
        "auth_data",
        "attributes",
        "access_token",
        "refresh_token",
        "id_token",
        "key_version",
    )
}
IDENTITY_PATH = "/api/v1/user_identity/11111111-1111-1111-1111-111111111111"


def _body(response) -> str:
    """Body text of a response or of a raised HTTP exception."""
    if isinstance(response, web.HTTPException):
        return response.text or ""
    text = getattr(response, "text", None)
    if text is not None:
        return text
    body = getattr(response, "body", b"")
    return body.decode() if isinstance(body, bytes) else str(body)


async def _serialize(h, data, fields=None):
    """Run data through the handler's real response path, return body text."""
    captured = {}

    async def _cap(self, response, fields=None, headers=None, status=200):
        captured["r"] = response
        return web.Response(text=json.dumps(response, default=repr))

    with patch("navigator.views.ModelView._model_response", new=_cap):
        resp = await h._model_response(data, fields=fields)
    return resp.text, captured["r"]


class TestIdentitySurfaceOwner:
    @pytest.mark.asyncio
    async def test_identity_surface_end_to_end_owner(self, owner_session, identity_row, pdp_with_pack):
        """Owner reads own identity: metadata present, zero token bytes."""
        identity_row["user_id"] = OWNER_ID
        model = FakeModel(IDENTITY_COLUMNS, [identity_row])
        h = _crud(UserIdentityHandler, IDENTITY_PATH, model, pdp_with_pack)
        with _patch_sessions(owner_session):
            await h._pre_get()
            data = await h._get_data({}, {"identity_id": identity_row["identity_id"]})
        text, payload = await _serialize(h, data.to_dict())
        for s in SENTINELS:
            assert s not in text
        assert payload["auth_provider"] == "git" and payload["enabled"] is True
        # vault surface (store.masked) and CRUD surface agree on the
        # credential-related keys.
        vault = IdentityStore.masked(None, _Obj(identity_row))
        for key in ("has_refresh_token", "has_id_token", "expired", "profile", "scopes", "token_type"):
            assert payload[key] == vault[key], key

    @pytest.mark.asyncio
    async def test_owner_cannot_reach_a_foreign_identity_by_any_route(self, owner_session, identity_row, pdp_with_pack):
        """PK, list, ?user_id=, ?_filter= and :meta refuse or exclude."""
        model = FakeModel(IDENTITY_COLUMNS, [identity_row])  # owned by OTHER
        with _patch_sessions(owner_session):
            # PK
            h = _crud(UserIdentityHandler, IDENTITY_PATH, model, pdp_with_pack)
            with pytest.raises(web.HTTPNotFound):
                await h._get_data({}, {"identity_id": identity_row["identity_id"]})
            # list: only own rows (none exist)
            h = _crud(UserIdentityHandler, "/api/v1/user_identity", model, pdp_with_pack)
            from asyncdb.exceptions import NoDataFound

            with pytest.raises(NoDataFound):
                await h._get_data({}, {})
            assert model.calls[-1] == ("filter", {"user_id": OWNER_ID})
            # ?user_id=
            h = _crud(UserIdentityHandler, "/api/v1/user_identity", model, pdp_with_pack, query=f"?user_id={OTHER_ID}")
            with pytest.raises(web.HTTPForbidden):
                await h._pre_get()
            # ?_filter= on a credential
            conn = FakeConn()
            h = _crud(UserIdentityHandler, "/api/v1/user_identity", model, pdp_with_pack)
            h.handler = AsyncMock(return_value=conn)
            with pytest.raises(web.HTTPBadRequest):
                await h._filtering({"_filter": "access_token=x"})
            assert conn.calls == []
            # :meta
            from navigator_auth.models import UserIdentity

            h.get_model = UserIdentity
            meta = json.loads((await h._get_meta_info(":meta", None)).text)
            assert "access_token" not in meta["properties"]


class TestIdentitySurfaceSuperuser:
    @pytest.mark.asyncio
    async def test_identity_surface_end_to_end_superuser(self, superuser_session, identity_row, pdp_with_pack, audit):
        """Read, revoke, delete a foreign identity; PUT refresh is refused."""
        pk = identity_row["identity_id"]
        model = FakeModel(IDENTITY_COLUMNS, [identity_row])
        with _patch_sessions(superuser_session):
            h = _crud(UserIdentityHandler, IDENTITY_PATH, model, pdp_with_pack)
            # 1. GET foreign -> redacted, audited
            data = await h._get_data({}, {"identity_id": pk})
            text, payload = await _serialize(h, data.to_dict())
            assert payload["user_id"] == OTHER_ID
            assert not any(s in text for s in SENTINELS)
            assert audit.log.await_count == 1
            # 2. PATCH {"enabled": false} -> allowed + audited
            with patch("navigator.views.ModelView._set_update", new=AsyncMock()):
                await h._set_update(_Obj(identity_row), {"enabled": False})
            assert audit.log.await_count == 2
            # 3. PUT (refresh path) naming the foreign owner -> 403
            h_put = _crud(
                UserIdentityHandler,
                IDENTITY_PATH,
                model,
                pdp_with_pack,
                body={"user_id": OTHER_ID, "access_token": "x"},
            )
            with pytest.raises(web.HTTPForbidden):
                await h_put._pre_put()
            # 4. PATCH other column -> 403
            with pytest.raises(web.HTTPForbidden):
                await h._set_update(_Obj(identity_row), {"display_name": "x"})
            # 5. vault columns are refused for everyone
            with pytest.raises(web.HTTPBadRequest):
                await h._set_update(_Obj(identity_row), {"access_token": "x"})
            # 6. DELETE -> allowed + audited
            before = audit.log.await_count
            assert await h._del_primary_data({"id": pk}) == pk
            assert audit.log.await_count == before + 1
        for call in audit.log.await_args_list:
            answer = call.args[0]
            assert answer.response and answer.rule == "user_identities_admin_access"

    @pytest.mark.asyncio
    async def test_superuser_is_fully_denied_without_the_pack(self, superuser_session, owner_session, identity_row):
        """No PDP => the admin path is closed; the owner path still open."""
        pk = identity_row["identity_id"]
        model = FakeModel(IDENTITY_COLUMNS, [identity_row])
        with _patch_sessions(superuser_session), patch("navigator_auth.handlers.guards.AuditLog"):
            h = _crud(UserIdentityHandler, IDENTITY_PATH, model)
            with pytest.raises(web.HTTPNotFound):
                await h._get_data({}, {"identity_id": pk})
            with pytest.raises(web.HTTPForbidden):
                await h._set_update(_Obj(identity_row), {"enabled": False})
            with pytest.raises(web.HTTPNotFound):
                await h._del_primary_data({"id": pk})
        identity_row["user_id"] = OWNER_ID
        with _patch_sessions(owner_session):
            h = _crud(UserIdentityHandler, IDENTITY_PATH, model)
            row = await h._get_data({}, {"identity_id": pk})
            assert row.user_id == OWNER_ID


class TestAccountSurface:
    @pytest.mark.asyncio
    async def test_account_owner_and_superuser(
        self, owner_session, superuser_session, account_row, pdp_with_pack, audit
    ):
        cols = {c: None for c in account_row}
        model = FakeModel(cols, [account_row])
        path = "/api/v1/user_accounts/a1"
        with _patch_sessions(owner_session):
            h = _crud(UserAccountHandler, path, model, pdp_with_pack)
            row = await h._get_data({}, {"account_id": "a1"})
            assert row.user_id == OWNER_ID
        account_row["user_id"] = OTHER_ID
        with _patch_sessions(owner_session):
            h = _crud(UserAccountHandler, path, model, pdp_with_pack)
            with pytest.raises(web.HTTPNotFound):
                await h._get_data({}, {"account_id": "a1"})
        with _patch_sessions(superuser_session):
            h = _crud(UserAccountHandler, path, model, pdp_with_pack)
            row = await h._get_data({}, {"account_id": "a1"})
            assert row.user_id == OTHER_ID
            assert audit.log.await_count == 1
            with pytest.raises(web.HTTPForbidden):
                await h._set_update(_Obj(account_row), {"provider": "x"})


def _json_resp(payload, status=200):
    return web.Response(text=json.dumps(payload), status=status, content_type="application/json")


def _partner(pdp=None, meta=None):
    h = PartnerKeyHandler.__new__(PartnerKeyHandler)
    h._request = _request("/api/v1/partner/tokens/p1", pdp, meta=meta)
    h._json = JSONContent()
    h.logger = MagicMock()
    return h


class TestPartnerKeyLifecycle:
    @pytest.mark.asyncio
    async def test_partner_key_lifecycle_superuser_only(self, superuser_session, partner_row, pdp_with_pack, audit):
        """Create (token once), list (no token), revoke, delete."""
        with _patch_sessions(superuser_session):
            with patch.object(LocalBase, "put", new=AsyncMock(return_value=_json_resp(partner_row, 201))):
                created = await _partner(pdp_with_pack).put()
            assert created.status == 201 and SENTINEL_JWT in created.text
            h = _partner(pdp_with_pack)
            single = await h._post_get(dict(partner_row))
            listing = await h._post_get([dict(partner_row)])
            assert SENTINEL_JWT not in single.text + listing.text
            assert "token" not in json.loads(single.text)
            meta_get = await _partner(pdp_with_pack, meta=":meta").get()
            meta_patch = await _partner(pdp_with_pack, meta=":meta").patch()
            assert "token" not in json.loads(meta_get.text)["properties"]
            assert "token" not in json.loads(meta_patch.text)
            with patch.object(LocalBase, "patch", new=AsyncMock(return_value=_json_resp(partner_row, 202))):
                revoked = await _partner(pdp_with_pack).patch()
            assert revoked.status == 202 and SENTINEL_JWT not in revoked.text
            with patch.object(LocalBase, "delete", new=AsyncMock(return_value=_json_resp(partner_row, 202))):
                deleted = await _partner(pdp_with_pack).delete()
            assert SENTINEL_JWT not in deleted.text
        # put, get(:meta), patch(:meta), patch, delete => 5 audited verbs
        assert audit.log.await_count == 5

    @pytest.mark.asyncio
    async def test_regular_user_is_refused_at_every_step(self, owner_session, partner_row, pdp_with_pack):
        with _patch_sessions(owner_session), patch("navigator_auth.handlers.guards.AuditLog"):
            for verb in ("get", "put", "patch", "post", "delete", "head"):
                with pytest.raises(web.HTTPForbidden):
                    await getattr(_partner(pdp_with_pack), verb)()


class TestRoutesStillExist:
    def test_all_six_routes_are_registered(self):
        """Spec G4: the paths and verbs are unchanged by this feature."""
        import inspect
        import navigator_auth.handlers as handlers

        src = inspect.getsource(handlers)
        for name in (
            "api_auth_useridentity_id",
            "api_auth_useridentity",
            "api_auth_useraccount_id",
            "api_auth_useraccount",
            "api_auth_partnerkey_id",
            "api_auth_partnerkey",
        ):
            assert f'name="{name}"' in src
        for path in (
            "/api/v1/user_identity/{id:.*}",
            "/api/v1/user_accounts/{id:.*}",
            "/api/v1/partner/tokens/{id:.*}",
        ):
            assert path in src
