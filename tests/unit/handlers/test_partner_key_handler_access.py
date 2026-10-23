"""PartnerKeyHandler is superuser-only and returns `token` once (FEAT-105).

This handler sits on the LOCAL handlers/model.py base, which has no _pre_*
hooks — so these tests drive the VERBS.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from datamodel.parsers.json import JSONContent

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.model import ModelHandler as LocalBase
from navigator_auth.handlers.partners import PartnerKey, PartnerKeyHandler

pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)

SENTINEL_JWT = "eyJhbGciOiJIUzI1NiJ9.SENTINEL.signature"
POLICY = "partner_keys_admin_access"
PUBLIC = frozenset({
    "partner_id", "name", "partner", "issuer", "created_at", "revoked",
    "enabled", "grants", "programs",
})
VERBS = ["get", "put", "patch", "post", "delete", "head"]


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


def _session(user_id=7, groups=("users",)):
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


class ExplodingPolicy:
    name = POLICY

    def evaluate(self, ctx, env):
        raise RuntimeError("boom")

    def is_allowed(self, ctx, env, **kw):
        raise RuntimeError("boom")


def _permissive_pdp():
    audit = MagicMock()
    audit.log = AsyncMock()
    pol = Policy(
        POLICY, description="d", effect=PolicyEffect.ALLOW,
        actions=["partner:read", "partner:create", "partner:revoke", "partner:delete"],
        groups=["superuser"], priority=1,
    )
    return FakePDP([pol], audit), audit


def _handler(pdp=None, meta=None):
    app = {}
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", "/api/v1/partner/tokens/abc", app=app)
    request["authenticated"] = True
    if meta:
        request.match_info.update({"meta": meta})
    h = PartnerKeyHandler.__new__(PartnerKeyHandler)
    h._request = request
    h._json = JSONContent()
    h.logger = MagicMock()
    return h


def _partner_row(token=SENTINEL_JWT):
    return {
        "partner_id": "p1", "name": "n", "partner": "x", "issuer": "navigator",
        "token": token, "created_at": None, "revoked": False, "enabled": True,
        "grants": {}, "programs": [],
    }


def _su():
    return _session(groups=["superuser"])


def _json_resp(payload, status=200):
    return web.Response(
        text=json.dumps(payload), status=status, content_type="application/json"
    )


class TestConfiguration:
    def test_guard_precedes_the_base_in_the_mro(self):
        from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
        mro = PartnerKeyHandler.__mro__
        assert mro.index(OwnerOrSuperuserGuard) < mro.index(LocalBase)

    def test_owner_column_is_none(self):
        assert PartnerKeyHandler.owner_column is None

    def test_public_columns_is_every_column_but_token(self):
        assert set(PartnerKey.get_columns()) - PUBLIC == {"token"}
        assert PartnerKeyHandler.public_columns == PUBLIC

    def test_policy_name_and_four_actions_match_the_pack(self):
        assert PartnerKeyHandler.policy_name == POLICY
        assert PartnerKeyHandler.superuser_actions == frozenset(
            {"partner:read", "partner:create", "partner:revoke", "partner:delete"})

    def test_partner_pk_is_list(self):
        assert PartnerKeyHandler.pk == ["partner_id"]

    def test_token_column_flags_unchanged(self):
        meta = PartnerKey.get_columns()["token"].metadata
        assert not meta.get("secret")


class TestSuperuserOnly:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("verb", VERBS)
    async def test_every_verb_refuses_a_non_superuser(self, verb):
        pdp, _ = _permissive_pdp()
        h = _handler(pdp)
        with _patch_sessions(_session()), patch("navigator_auth.handlers.guards.AuditLog"):
            with pytest.raises(web.HTTPForbidden):
                await getattr(h, verb)()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("verb", VERBS)
    async def test_unauthenticated_is_401(self, verb):
        with _patch_sessions(None), pytest.raises(web.HTTPUnauthorized):
            await getattr(_handler(), verb)()

    @pytest.mark.asyncio
    async def test_superuser_denied_without_pdp(self):
        with _patch_sessions(_su()), patch("navigator_auth.handlers.guards.AuditLog"):
            with pytest.raises(web.HTTPForbidden):
                await _handler().get()

    @pytest.mark.asyncio
    async def test_superuser_denied_when_policy_raises(self):
        h = _handler(FakePDP([ExplodingPolicy()], MagicMock(log=AsyncMock())))
        with _patch_sessions(_su()), pytest.raises(web.HTTPForbidden):
            await h.get()

    @pytest.mark.asyncio
    async def test_each_verb_is_audited(self):
        for verb, status in [("get", 200), ("delete", 202), ("patch", 202)]:
            pdp, audit = _permissive_pdp()
            h = _handler(pdp)
            with _patch_sessions(_su()), patch.object(
                LocalBase, verb, new=AsyncMock(return_value=_json_resp({}, status))
            ):
                await getattr(h, verb)()
            audit.log.assert_awaited_once()


class TestTokenRedaction:
    @pytest.mark.asyncio
    async def test_get_single_row_has_no_token(self):
        h = _handler()
        resp = await h._post_get(_partner_row())
        assert "token" not in json.loads(resp.text)
        assert SENTINEL_JWT not in resp.text

    @pytest.mark.asyncio
    async def test_get_list_has_no_token(self):
        resp = await _handler()._post_get([_partner_row(), _partner_row()])
        assert SENTINEL_JWT not in resp.text

    @pytest.mark.asyncio
    async def test_fields_param_cannot_project_the_token(self):
        resp = await _handler()._post_get(_partner_row(), ["token", "name"])
        assert json.loads(resp.text) == {"name": "n"}

    @pytest.mark.asyncio
    async def test_get_meta_has_no_token(self):
        pdp, _ = _permissive_pdp()
        h = _handler(pdp, meta=":meta")
        with _patch_sessions(_su()):
            resp = await h.get()
        assert "token" not in json.loads(resp.text)["properties"]

    @pytest.mark.asyncio
    async def test_patch_meta_has_no_token(self):
        pdp, _ = _permissive_pdp()
        h = _handler(pdp, meta=":meta")
        with _patch_sessions(_su()):
            resp = await h.patch()
        assert "token" not in json.loads(resp.text)
        assert "name" in json.loads(resp.text)

    @pytest.mark.asyncio
    async def test_meta_does_not_mutate_the_cached_schema(self):
        pdp, _ = _permissive_pdp()
        h = _handler(pdp, meta=":meta")
        with _patch_sessions(_su()):
            await h.get()
        assert "token" in PartnerKey.schema(as_dict=True)["properties"]

    @pytest.mark.asyncio
    async def test_head_x_columns_has_no_token(self):
        pdp, _ = _permissive_pdp()
        with _patch_sessions(_su()), patch.object(
            LocalBase, "head",
            new=AsyncMock(return_value=web.Response(headers={"X-Columns": "all"})),
        ):
            resp = await _handler(pdp).head()
        assert "token" not in resp.headers["X-Columns"]
        assert "name" in resp.headers["X-Columns"]

    @pytest.mark.asyncio
    async def test_delete_response_has_no_token(self):
        pdp, _ = _permissive_pdp()
        with _patch_sessions(_su()), patch.object(
            LocalBase, "delete",
            new=AsyncMock(return_value=_json_resp(_partner_row(), 202)),
        ):
            resp = await _handler(pdp).delete()
        assert resp.status == 202 and SENTINEL_JWT not in resp.text

    @pytest.mark.asyncio
    async def test_sentinel_appears_nowhere_in_any_read_body(self):
        pdp, _ = _permissive_pdp()
        row = _partner_row()
        row["grants"] = {"note": "ok"}
        bodies = [
            (await _handler()._post_get(row)).text,
            (await _handler()._post_get([row])).text,
        ]
        with _patch_sessions(_su()):
            bodies.append((await _handler(pdp, meta=":meta").get()).text)
            bodies.append((await _handler(pdp, meta=":meta").patch()).text)
        assert all(SENTINEL_JWT not in b for b in bodies)


class TestReturnOnceToken:
    @pytest.mark.asyncio
    async def test_put_create_returns_the_token(self):
        pdp, _ = _permissive_pdp()
        with _patch_sessions(_su()), patch.object(
            LocalBase, "put",
            new=AsyncMock(return_value=_json_resp(_partner_row(), 201)),
        ):
            resp = await _handler(pdp).put()
        assert resp.status == 201 and SENTINEL_JWT in resp.text

    @pytest.mark.asyncio
    async def test_post_that_creates_returns_the_token(self):
        pdp, _ = _permissive_pdp()
        with _patch_sessions(_su()), patch.object(
            LocalBase, "post",
            new=AsyncMock(return_value=_json_resp(_partner_row(), 201)),
        ):
            resp = await _handler(pdp).post()
        assert SENTINEL_JWT in resp.text

    @pytest.mark.asyncio
    async def test_post_that_updates_does_not_echo_the_token(self):
        pdp, _ = _permissive_pdp()
        with _patch_sessions(_su()), patch.object(
            LocalBase, "post",
            new=AsyncMock(return_value=_json_resp(_partner_row(), 202)),
        ):
            resp = await _handler(pdp).post()
        assert resp.status == 202 and SENTINEL_JWT not in resp.text

    @pytest.mark.asyncio
    async def test_post_requires_create_and_revoke(self):
        audit = MagicMock(log=AsyncMock())
        pol = Policy(
            POLICY, description="d", effect=PolicyEffect.ALLOW,
            actions=["partner:create"], groups=["superuser"], priority=1,
        )
        h = _handler(FakePDP([pol], audit))
        with _patch_sessions(_su()), patch.object(
            LocalBase, "post", new=AsyncMock(return_value=_json_resp({}, 201))
        ) as sup:
            with pytest.raises(web.HTTPForbidden):
                await h.post()
        sup.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_patch_does_not_echo_the_token(self):
        pdp, _ = _permissive_pdp()
        with _patch_sessions(_su()), patch.object(
            LocalBase, "patch",
            new=AsyncMock(return_value=_json_resp(_partner_row(), 202)),
        ):
            resp = await _handler(pdp).patch()
        assert SENTINEL_JWT not in resp.text

    @pytest.mark.asyncio
    async def test_created_token_is_not_readable_afterwards(self):
        pdp, _ = _permissive_pdp()
        h = _handler(pdp)
        with _patch_sessions(_su()), patch.object(
            LocalBase, "put",
            new=AsyncMock(return_value=_json_resp(_partner_row(), 201)),
        ):
            created = await h.put()
        assert SENTINEL_JWT in created.text
        later = await h._post_get(_partner_row())
        assert SENTINEL_JWT not in later.text
