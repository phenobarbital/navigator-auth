"""Unit tests for OwnerOrSuperuserGuard (FEAT-105, TASK-122).

The mixin is driven through a synthetic host so no handler is involved.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

PUBLIC = frozenset({"identity_id", "user_id", "email", "auth_provider"})
CREDENTIALS = frozenset({"access_token", "refresh_token", "id_token", "key_version"})
POLICY = "user_identities_admin_access"
ACTIONS = frozenset({"identity:read", "identity:revoke", "identity:delete"})


class FakeModel:
    class Meta:
        name = "user_identities"
        schema = "auth"

    @classmethod
    def get_columns(cls):
        return {c: None for c in PUBLIC | CREDENTIALS}


class RecordingConn:
    def __init__(self):
        self.calls = []

    async def fetch_all(self, sql, *args):
        self.calls.append((sql, args))
        return [{"email": "a@b"}]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class Host(OwnerOrSuperuserGuard):
    owner_column = "user_id"
    credential_columns = CREDENTIALS
    public_columns = PUBLIC
    policy_name = POLICY
    superuser_actions = ACTIONS

    def __init__(self, request):
        self.request = request
        self.get_model = FakeModel
        self.conn = RecordingConn()

    async def handler(self, request=None):
        return self.conn

    def error(self, response=None, status=400, **kwargs):
        """Mirror BaseHandler.error(): RAISE, never return."""
        cls = {
            400: web.HTTPBadRequest,
            401: web.HTTPUnauthorized,
            403: web.HTTPForbidden,
            404: web.HTTPNotFound,
        }.get(status, web.HTTPBadRequest)
        import json

        raise cls(text=json.dumps(response or {}), content_type="application/json")


class OwnerlessHost(Host):
    owner_column = None


class NoPolicyHost(Host):
    policy_name = None


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

    def is_allowed(self, ctx, env, **kwargs):
        raise RuntimeError("boom")


def _policy(actions=("identity:read", "identity:revoke", "identity:delete", "identity:refresh")):
    return Policy(
        POLICY,
        description="d",
        effect=PolicyEffect.ALLOW,
        actions=list(actions),
        groups=["superuser"],
        priority=1,
    )


def _audit():
    log = MagicMock()
    log.log = AsyncMock()
    return log


def _request(pdp=None, path="/api/v1/user_identity/abc"):
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
    return patch(
        "navigator_auth.handlers.guards.get_session",
        new=AsyncMock(return_value=session),
    ), patch(
        "navigator_auth.decorators.get_session",
        new=AsyncMock(return_value=session),
    )


class _Sess:
    """Context manager patching get_session in guards and decorators."""

    def __init__(self, session):
        self.ps = _patch_session(session)

    def __enter__(self):
        for p in self.ps:
            p.start()

    def __exit__(self, *a):
        for p in self.ps:
            p.stop()


def S(session):
    return _Sess(session)


class TestActingUser:
    @pytest.mark.asyncio
    async def test_requires_session(self):
        with S(None), pytest.raises(web.HTTPUnauthorized):
            await Host(_request()).acting_user()

    @pytest.mark.asyncio
    async def test_requires_user_id(self):
        sess = _session()
        data = {"session": {"username": "u"}}
        sess.__getitem__ = lambda s, k: data[k]
        with S(sess), pytest.raises(web.HTTPUnauthorized):
            await Host(_request()).acting_user()

    @pytest.mark.asyncio
    async def test_superuser_via_group_only(self):
        with S(_session(groups=["superuser"])):
            assert await Host(_request()).acting_user() == (42, True)
        with S(_session(groups="ex_superuser_revoked")):
            assert await Host(_request()).acting_user() == (42, False)

    @pytest.mark.asyncio
    async def test_superuser_via_attribute(self):
        with S(_session(superuser=True)):
            assert (await Host(_request()).acting_user())[1] is True


class TestAuthorizeRow:
    @pytest.mark.asyncio
    async def test_owner_needs_no_policy(self):
        with S(_session()):
            assert await Host(_request()).authorize_row("identity:read", 42) is True

    @pytest.mark.asyncio
    async def test_owner_writes_no_audit_record(self):
        with (
            S(_session()),
            patch("navigator_auth.handlers.guards.AuditLog") as AL,
            patch("navigator_auth.handlers.guards.policy_allows") as pa,
        ):
            await Host(_request()).authorize_row("identity:read", 42)
        AL.assert_not_called()
        pa.assert_not_called()

    @pytest.mark.asyncio
    async def test_owner_id_type_mismatch_still_matches(self):
        with S(_session(user_id=42)):
            assert await Host(_request()).authorize_row("identity:read", "42") is True

    @pytest.mark.asyncio
    async def test_foreign_row_refused_403(self):
        with S(_session()), patch("navigator_auth.handlers.guards.AuditLog"):
            with pytest.raises(web.HTTPForbidden):
                await Host(_request()).authorize_row("identity:read", 7)

    @pytest.mark.asyncio
    async def test_foreign_row_refused_404_when_asked(self):
        with S(_session()), patch("navigator_auth.handlers.guards.AuditLog"):
            with pytest.raises(web.HTTPNotFound):
                await Host(_request()).authorize_row("identity:read", 7, not_found_on_deny=True)

    @pytest.mark.asyncio
    async def test_deny_body_leaks_no_row_data(self):
        with S(_session()), patch("navigator_auth.handlers.guards.AuditLog"):
            with pytest.raises(web.HTTPForbidden) as ei:
                await Host(_request()).authorize_row("identity:read", 98765)
        text = ei.value.text
        assert "98765" not in text and "user_id" not in text and "email" not in text

    @pytest.mark.asyncio
    async def test_ownerless_requires_superuser(self):
        with S(_session()), patch("navigator_auth.handlers.guards.AuditLog"):
            for action in ACTIONS:
                with pytest.raises(web.HTTPForbidden):
                    await OwnerlessHost(_request()).authorize_row(action, 42)

    @pytest.mark.asyncio
    async def test_action_outside_superuser_actions_refused(self):
        pdp = FakePDP([_policy()], _audit())
        with S(_session(groups=["superuser"])):
            with pytest.raises(web.HTTPForbidden):
                await Host(_request(pdp)).authorize_row("identity:refresh", 7)

    @pytest.mark.asyncio
    async def test_missing_policy_name_refuses_without_valueerror(self):
        pdp = FakePDP([_policy()], _audit())
        with S(_session(groups=["superuser"])):
            with pytest.raises(web.HTTPForbidden):
                await NoPolicyHost(_request(pdp)).authorize_row("identity:read", 7)

    @pytest.mark.asyncio
    async def test_fails_closed_without_pdp(self):
        req = _request()
        with S(_session(groups=["superuser"])), patch("navigator_auth.handlers.guards.AuditLog"):
            with pytest.raises(web.HTTPForbidden):
                await Host(req).authorize_row("identity:read", 7)
            assert await Host(req).authorize_row("identity:read", 42) is True

    @pytest.mark.asyncio
    async def test_fails_closed_policy_undeclared_or_raising(self):
        for pdp in (FakePDP([], _audit()), FakePDP([ExplodingPolicy()], _audit())):
            with S(_session(groups=["superuser"])):
                with pytest.raises(web.HTTPForbidden):
                    await Host(_request(pdp)).authorize_row("identity:read", 7)

    @pytest.mark.asyncio
    async def test_superuser_with_policy_allowed(self):
        pdp = FakePDP([_policy()], _audit())
        with S(_session(groups=["superuser"])):
            assert await Host(_request(pdp)).authorize_row("identity:read", 7) is True

    @pytest.mark.asyncio
    async def test_cross_user_allow_is_audited(self):
        audit = _audit()
        pdp = FakePDP([_policy()], audit)
        with S(_session(groups=["superuser"])):
            await Host(_request(pdp)).authorize_row("identity:read", 7)
        audit.log.assert_awaited_once()
        answer, status = audit.log.await_args.args[:2]
        assert answer.response and answer.rule == POLICY and status == "ALLOW"

    @pytest.mark.asyncio
    async def test_cross_user_deny_is_audited(self):
        audit = _audit()
        pdp = FakePDP([], audit)
        with S(_session(groups=["superuser"])):
            with pytest.raises(web.HTTPForbidden):
                await Host(_request(pdp)).authorize_row("identity:read", 7)
        audit.log.assert_awaited_once()
        assert audit.log.await_args.args[1] == "DENY"

    @pytest.mark.asyncio
    async def test_audit_backend_failure_does_not_break_the_request(self):
        audit = _audit()
        audit.log = AsyncMock(side_effect=RuntimeError("down"))
        pdp = FakePDP([_policy()], audit)
        with S(_session(groups=["superuser"])):
            assert await Host(_request(pdp)).authorize_row("identity:read", 7) is True


class TestSanitizeQuery:
    @pytest.mark.asyncio
    async def test_fields_intersected_with_allowlist(self):
        with S(_session()):
            _, fields = await Host(_request()).sanitize_query({}, ["access_token", "email"])
        assert fields == ["email"]

    @pytest.mark.asyncio
    async def test_foreign_owner_param_refused(self):
        with S(_session()), pytest.raises(web.HTTPForbidden):
            await Host(_request()).sanitize_query({"user_id": "7"}, None)

    @pytest.mark.asyncio
    async def test_own_owner_param_is_dropped_not_merged(self):
        with S(_session()):
            qp, _ = await Host(_request()).sanitize_query({"user_id": "42"}, None)
        assert "user_id" not in qp

    @pytest.mark.asyncio
    async def test_superuser_may_name_a_foreign_owner(self):
        with S(_session(groups=["superuser"])):
            qp, _ = await Host(_request()).sanitize_query({"user_id": "7"}, None)
        assert qp == {"user_id": "7"}

    @pytest.mark.asyncio
    async def test_credential_qp_key_dropped_for_everyone(self):
        for groups in (["users"], ["superuser"]):
            with S(_session(groups=groups)):
                qp, _ = await Host(_request()).sanitize_query({"access_token": "x", "email": "e"}, None)
            assert qp == {"email": "e"}


class TestSafeFilter:
    @pytest.mark.asyncio
    async def test_rejects_non_allowlisted_field(self):
        host = Host(_request())
        with S(_session()), pytest.raises(web.HTTPBadRequest):
            await host.safe_filter("access_token=x")
        assert host.conn.calls == []

    @pytest.mark.asyncio
    async def test_rejects_unknown_field_identically(self):
        msgs = []
        for expr in ("access_token=x", "nonsense=x"):
            with S(_session()), pytest.raises(web.HTTPBadRequest) as ei:
                await Host(_request()).safe_filter(expr)
            msgs.append(ei.value.text)
        assert msgs[0] == msgs[1]

    @pytest.mark.asyncio
    async def test_rejects_malformed_expression(self):
        with S(_session()), pytest.raises(web.HTTPBadRequest):
            await Host(_request()).safe_filter("justafield")

    @pytest.mark.asyncio
    async def test_binds_value_as_parameter(self):
        host = Host(_request())
        payload = "' OR 1=1 --"
        with S(_session()):
            await host.safe_filter(f"email={payload}")
        sql, args = host.conn.calls[0]
        assert "$1" in sql and payload not in sql
        assert any(payload in str(a) for a in args)
        assert "access_token" not in sql

    @pytest.mark.asyncio
    async def test_ands_owner_predicate_for_non_superuser(self):
        host = Host(_request())
        with S(_session(user_id=42)):
            await host.safe_filter("email=a")
        sql, args = host.conn.calls[0]
        assert '"user_id" = $2' in sql and 42 in args

    @pytest.mark.asyncio
    async def test_superuser_filter_has_no_owner_predicate_and_is_audited(self):
        audit = _audit()
        host = Host(_request(FakePDP([_policy()], audit)))
        with S(_session(groups=["superuser"])):
            await host.safe_filter("email=a")
        sql, args = host.conn.calls[0]
        assert "$2" not in sql and len(args) == 1
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_superuser_filter_without_policy_stays_owner_bound(self):
        """No PDP / undeclared policy => the superuser is NOT widened."""
        for pdp in (None, FakePDP([], _audit())):
            host = Host(_request(pdp))
            with S(_session(groups=["superuser"])), patch("navigator_auth.handlers.guards.AuditLog"):
                await host.safe_filter("email=a")
            sql, args = host.conn.calls[0]
            assert '"user_id" = $2' in sql and 42 in args
