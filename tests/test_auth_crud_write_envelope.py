"""FEAT-107 end to end: the auth CRUD write envelope, over the real router.

In-process and connection-mocked: no database. Routes come from the real
setup_handlers(); policies are the SHIPPED auth_crud_admin_access.yaml, parsed
with YAMLStorage into real ResourcePolicy objects — the approach of
tests/integration/test_auth_model_ownership.py (FEAT-105).

Every scenario resolves the request through ``app.router.resolve`` and runs the
real verb (``patch`` / ``put`` / ``post`` / ``delete``) of the resolved handler
class. Database access is replaced at the model boundary (``Model.get`` /
``insert`` / ``update`` / ``updating`` / ``create`` / ``delete``), recording
every write so refusal scenarios can assert "no write reached the database".

Creation is ``PUT /api/v1/users`` (POST needs a primary key on this base,
TASK-153); membership rows are created with PUT and removed with DELETE
(TASK-154).
"""

from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from asyncdb.exceptions import NoDataFound
from datamodel.parsers.json import JSONContent
from navigator_session import AUTH_SESSION_OBJECT, SESSION_KEY

from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.handlers import setup_handlers
from navigator_auth.handlers.groups import GroupManager, GroupPermissionManager, UserGroupManager
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.permissions import PermissionHandler
from navigator_auth.handlers.users.passwd import check_password
from navigator_auth.handlers.users.role import UserRoleHandler
from navigator_auth.handlers.users.session import UserSession
from navigator_auth.handlers.users.user import UserManager
from navigator_auth.models import Group, GroupPermission, Permission, User, UserGroup

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

PACK = (
    Path(__file__).resolve().parents[1] / "navigator_auth" / "abac" / "default_policies" / "auth_crud_admin_access.yaml"
)

OWNER_ID, ADMIN_ID, GRANTOR_ID, SECADMIN_ID, VICTIM_ID = 42, 7, 8, 9, 99
SUPERUSER_GROUP_ID, SECADMIN_GROUP_ID, ORDINARY_GROUP_ID = 1, 2, 3

WRITE_OPS = ("insert", "update", "updating", "create", "delete")
MODELS = (User, Group, UserGroup, GroupPermission, Permission)


class FakeSession(dict):
    """Session double exposing ``decode`` like the real one."""

    def decode(self, key):
        return self.get(key)


def _session(user_id, groups, username="u", superuser=None):
    info = {"user_id": user_id, "username": username, "groups": list(groups)}
    if superuser is not None:
        info["superuser"] = superuser
    return FakeSession({AUTH_SESSION_OBJECT: info})


@pytest.fixture
def escalation_payload():
    """Spec §4, verbatim — the §1 payload."""
    return {
        "is_superuser": True,
        "is_staff": True,
        "user_role": 10,
        "email": "attacker@evil.test",
        "password": "hunter2",
    }


@pytest.fixture
def ordinary_session():
    return _session(OWNER_ID, ["users"], "owner")


@pytest.fixture
def admin_session():
    return _session(ADMIN_ID, ["superuser"], "root", superuser=True)


@pytest.fixture
def grantor_session():
    return _session(GRANTOR_ID, ["superuser", "security_admin"], "grantor", superuser=True)


@pytest.fixture
def security_admin_only_session():
    return _session(SECADMIN_ID, ["security_admin"], "secadmin")


@pytest.fixture
def app():
    """A bare Application with the real FEAT-107 routes."""
    application = web.Application()
    setup_handlers(application, application.router)
    return application


@pytest.fixture
def pdp_with_pack():
    """A PDP carrying the six policies of the SHIPPED auth_crud_admin_access.yaml."""
    assert PACK.exists(), f"policy pack missing: {PACK}"
    policies = [
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
        for d in YAMLStorage._parse_file(PACK)
    ]
    pdp = MagicMock()
    pdp._evaluator = None
    pdp._policies = policies
    pdp.policies = policies
    pdp._auditlog = MagicMock(log=AsyncMock())
    return pdp


class FakeConn:
    """Async-context connection double."""

    def __init__(self):
        self.calls = []

    async def fetch_one(self, sql, *args):
        self.calls.append(("fetch_one", sql, args))
        return None

    async def fetch_all(self, sql, *args):
        self.calls.append(("fetch_all", sql, args))
        return []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeTransitionConn:
    """The connection ``security_transition`` yields to the two password paths.

    Since the FEAT-106 review fixes, password writes are SQL on the transition
    connection: a ``SELECT … FOR UPDATE`` re-read of the captured hash, then one
    ``UPDATE … RETURNING``. ``stored`` is what the re-read returns (the handler
    coalesces a never-set password to ``''``).
    """

    def __init__(self, stored):
        self.stored = stored
        self.updates = []

    async def fetchval(self, sql, *args):
        statement = sql.lstrip()
        if statement.startswith("SELECT"):
            return self.stored
        if statement.startswith("UPDATE"):
            self.updates.append((sql, args))
            return args[0]
        raise AssertionError(f"unexpected statement on the transition connection: {sql}")


def _password_transition(conn, revoker=None):
    """Patches running the password paths on ``conn`` with no MFA services or session store."""

    @asynccontextmanager
    async def _transition(app, user_id, event, **kwargs):
        yield conn

    patches = [
        patch("navigator_auth.handlers.users.session.security_transition", new=_transition),
        patch("navigator_auth.handlers.users.session.increment_generation", new=AsyncMock()),
    ]
    if revoker is not None:
        patches.append(
            patch(
                "navigator_auth.handlers.users.session.PasswordRecoveryHandler.session_revoker",
                new=MagicMock(return_value=revoker),
            )
        )
    return _Ctx(patches)


class FakeDB:
    """Row tables behind the model boundary, plus a record of every write."""

    def __init__(self):
        self.tables = {
            User: [
                {
                    "user_id": OWNER_ID,
                    "first_name": "Olive",
                    "last_name": "Owner",
                    "display_name": "Olive Owner",
                    "username": "owner",
                    "email": "owner@example.test",
                    "is_superuser": False,
                    "is_staff": False,
                    "user_role": 1,
                    "password": None,
                },
                {
                    "user_id": VICTIM_ID,
                    "first_name": "Vic",
                    "last_name": "Tim",
                    "display_name": "Vic Tim",
                    "username": "victim",
                    "email": "victim@example.test",
                    "is_superuser": False,
                    "is_staff": False,
                    "user_role": 1,
                    "password": None,
                },
            ],
            Group: [
                {"group_id": SUPERUSER_GROUP_ID, "group_name": "superuser"},
                {"group_id": SECADMIN_GROUP_ID, "group_name": "security_admin"},
                {"group_id": ORDINARY_GROUP_ID, "group_name": "editors"},
            ],
            UserGroup: [{"user_id": VICTIM_ID, "group_id": ORDINARY_GROUP_ID}],
            GroupPermission: [{"group_id": ORDINARY_GROUP_ID, "permission_id": 5}],
            Permission: [{"permission_id": 5, "permission": "x:y", "description": "d"}],
        }
        self.writes = []
        self.conn = FakeConn()

    def user_row(self, user_id):
        return next(r for r in self.tables[User] if r["user_id"] == user_id)

    def writes_to(self, model=None):
        return [w for w in self.writes if model is None or w[0] is model]

    def _make_get(self, model):
        async def _get(*args, **kw):
            for row in self.tables[model]:
                if all(str(row.get(k)) == str(v) for k, v in kw.items()):
                    return model(**row)
            raise NoDataFound("none")

        return _get

    def _make_write(self, model, op):
        async def _write(*args, **kw):
            self.writes.append((model, op, kw))
            return {}

        return _write

    def patches(self):
        out = []
        for model in MODELS:
            out.append(patch.object(model, "get", new=self._make_get(model)))
            for op in WRITE_OPS:
                out.append(patch.object(model, op, new=self._make_write(model, op), create=True))
        return out


@pytest.fixture
def db():
    return FakeDB()


class _Ctx:
    """Start/stop a list of patches as one context manager."""

    def __init__(self, patches):
        self.patches = patches

    def __enter__(self):
        for p in self.patches:
            p.start()

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


def _sessions(session):
    return [
        patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)),
        patch("navigator_auth.handlers.guards.get_session", new=AsyncMock(return_value=session)),
        patch("navigator.views.abstract.get_session", new=AsyncMock(return_value=session)),
    ]


async def _ok_response(self, result=None, status=200, fields=None, **kw):
    """Stand-in for the success-body step, which is not under test."""
    return web.json_response({}, status=status)


async def _drive(app, method, path, body=None, *, session, pdp=None, db=None):
    """Resolve ``path`` on the real router and run the resolved handler's verb.

    Returns the response, or the raised ``web.HTTPException`` (so a refusal
    and a success are inspected the same way).
    """
    probe = make_mocked_request(method, path)
    match = await app.router.resolve(probe)
    assert (
        not isinstance(match, web.UrlMappingMatchInfo) or match.http_exception is None
    ), f"{method} {path} did not resolve: {match.http_exception!r}"
    cls = match.handler
    holder = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if pdp is not None:
        holder["abac"] = pdp
    request = make_mocked_request(method, path, app=holder, match_info=match)
    request["authenticated"] = True
    handler = cls.__new__(cls)
    handler.__name__ = cls.__name__
    handler._request = request
    handler._json = JSONContent()
    handler.logger = MagicMock()
    handler.json_data = AsyncMock(return_value=body)
    handler._session = session
    db = db or FakeDB()
    handler.handler = AsyncMock(return_value=db.conn)
    patches = _sessions(session) + db.patches()
    # Success bodies are not under test: keep the response step trivial.
    for name in ("_patch_response", "_put_response", "_post_response", "_delete_response"):
        patches.append(
            patch.object(
                cls,
                name,
                new=_ok_response,
                create=True,
            )
        )
    with _Ctx(patches):
        try:
            return await getattr(handler, method.lower())()
        except web.HTTPException as exc:
            return exc


def _status(response) -> int:
    return response.status


def _refused(response) -> bool:
    return isinstance(response, web.HTTPException) and response.status in (403, 404)


def _assert_pristine(db, user_id=VICTIM_ID):
    row = db.user_row(user_id)
    assert row["is_superuser"] is False
    assert row["is_staff"] is False
    assert row["user_role"] == 1
    assert row["password"] is None
    assert row["email"].endswith("@example.test")


class TestRoutes:
    """Reachability: the route resolves to the right, guarded class."""

    def test_role_route_resolves_before_user_crud(self, app):
        import asyncio

        match = asyncio.new_event_loop().run_until_complete(
            app.router.resolve(make_mocked_request("POST", "/api/v1/users/5/role"))
        )
        assert match.handler is UserRoleHandler
        match = asyncio.new_event_loop().run_until_complete(
            app.router.resolve(make_mocked_request("PATCH", "/api/v1/users/5"))
        )
        assert match.handler is UserManager

    def test_every_surface_resolves_to_a_guarded_handler(self, app):
        import asyncio

        loop = asyncio.new_event_loop()
        expected = {
            "/api/v1/users/5": UserManager,
            "/api/v1/user_groups": UserGroupManager,
            "/api/v1/usergroups": UserGroupManager,
            "/api/v1/group_permissions": GroupPermissionManager,
            "/api/v1/groups": GroupManager,
            "/api/v1/permissions/5": PermissionHandler,
            "/api/v1/users/5/role": UserRoleHandler,
        }
        for path, cls in expected.items():
            verb = "POST" if path.endswith("/role") else "GET"
            match = loop.run_until_complete(app.router.resolve(make_mocked_request(verb, path)))
            assert match.handler is cls, path
            assert issubclass(match.handler, OwnerOrSuperuserGuard), path


class TestInvertedProbe:
    """The §1 probe, inverted: the payload that used to land is now refused."""

    @pytest.mark.asyncio
    async def test_section1_payload_refused_for_owner(self, app, ordinary_session, escalation_payload, db):
        db.tables[User][0]["is_superuser"] = False
        response = await _drive(
            app, "PATCH", f"/api/v1/users/{OWNER_ID}", escalation_payload, session=ordinary_session, db=db
        )
        assert _status(response) == 403
        assert db.writes == []
        owner = db.user_row(OWNER_ID)
        assert owner["is_superuser"] is False and owner["is_staff"] is False
        assert owner["user_role"] == 1 and owner["password"] is None
        assert owner["email"] == "owner@example.test"

    @pytest.mark.asyncio
    async def test_section1_payload_refused_for_admin(self, app, admin_session, escalation_payload, db, pdp_with_pack):
        response = await _drive(
            app,
            "PATCH",
            f"/api/v1/users/{VICTIM_ID}",
            escalation_payload,
            session=admin_session,
            pdp=pdp_with_pack,
            db=db,
        )
        assert _status(response) == 403
        assert db.writes == []
        _assert_pristine(db)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path", [("PUT", "/api/v1/users"), ("POST", f"/api/v1/users/{VICTIM_ID}")])
    async def test_section1_payload_refused_on_put_and_post(
        self, app, admin_session, ordinary_session, escalation_payload, db, pdp_with_pack, method, path
    ):
        for session in (admin_session, ordinary_session):
            response = await _drive(
                app, method, path, dict(escalation_payload), session=session, pdp=pdp_with_pack, db=db
            )
            assert _refused(response), (method, session)
            assert db.writes == []
            _assert_pristine(db)


class TestEscalationRoutesClosed:
    """Spec R6: the reachability claim, established by a request."""

    @pytest.mark.asyncio
    async def test_authenticated_user_cannot_escalate_via_users_crud(self, app, ordinary_session, db, pdp_with_pack):
        for method, path, body in (
            ("PATCH", f"/api/v1/users/{OWNER_ID}", {"is_superuser": True}),
            ("PATCH", f"/api/v1/users/{VICTIM_ID}", {"first_name": "pwned"}),
            ("PUT", "/api/v1/users", {"first_name": "a", "last_name": "b", "username": "c", "email": "c@d.ef"}),
            ("POST", f"/api/v1/users/{VICTIM_ID}", {"first_name": "pwned"}),
            ("DELETE", f"/api/v1/users/{VICTIM_ID}", None),
        ):
            response = await _drive(app, method, path, body, session=ordinary_session, pdp=pdp_with_pack, db=db)
            assert _refused(response), (method, path, getattr(response, "status", response))
        assert db.writes == []
        _assert_pristine(db)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("route", ["/api/v1/user_groups", "/api/v1/usergroups"])
    async def test_authenticated_user_cannot_escalate_via_user_groups(
        self, app, ordinary_session, db, pdp_with_pack, route
    ):
        for method, body in (
            ("PUT", {"user_id": OWNER_ID, "group_id": SUPERUSER_GROUP_ID}),
            ("PUT", {"user_id": OWNER_ID, "group_id": SECADMIN_GROUP_ID}),
            ("PUT", {"user_id": OWNER_ID, "group_id": ORDINARY_GROUP_ID}),
            ("POST", {"user_id": OWNER_ID, "group_id": SUPERUSER_GROUP_ID}),
            # PATCH targets the one existing membership and tries to move it.
            ("PATCH", {"user_id": VICTIM_ID, "group_id": ORDINARY_GROUP_ID, "created_by": OWNER_ID}),
        ):
            response = await _drive(app, method, route, body, session=ordinary_session, pdp=pdp_with_pack, db=db)
            assert isinstance(response, web.HTTPException) and response.status >= 400, (method, route)
            assert response.status != 500, (method, route)
        assert db.writes == []

    @pytest.mark.asyncio
    async def test_authenticated_user_cannot_escalate_via_group_permissions(
        self, app, ordinary_session, db, pdp_with_pack
    ):
        for method, body in (
            ("PUT", {"group_id": ORDINARY_GROUP_ID, "permission_id": 5}),
            ("POST", {"group_id": ORDINARY_GROUP_ID, "permission_id": 5}),
            ("PATCH", {"group_id": ORDINARY_GROUP_ID, "permission_id": 5, "updated_at": "2020-01-01"}),
        ):
            response = await _drive(
                app, method, "/api/v1/group_permissions", body, session=ordinary_session, pdp=pdp_with_pack, db=db
            )
            assert isinstance(response, web.HTTPException) and response.status >= 400, method
            assert response.status != 500
        assert db.writes == []

    @pytest.mark.asyncio
    async def test_superuser_cannot_escalate_via_security_admin_membership(self, app, admin_session, db, pdp_with_pack):
        """A plain superuser lacks users:grant_role: no self-add, no rename, no delete."""
        add_self = await _drive(
            app,
            "PUT",
            "/api/v1/user_groups",
            {"user_id": ADMIN_ID, "group_id": SECADMIN_GROUP_ID},
            session=admin_session,
            pdp=pdp_with_pack,
            db=db,
        )
        assert _status(add_self) == 403
        add_victim = await _drive(
            app,
            "PUT",
            "/api/v1/usergroups",
            {"user_id": VICTIM_ID, "group_id": SUPERUSER_GROUP_ID},
            session=admin_session,
            pdp=pdp_with_pack,
            db=db,
        )
        assert _status(add_victim) == 403
        rename = await _drive(
            app,
            "PATCH",
            f"/api/v1/groups/{SECADMIN_GROUP_ID}",
            {"group_name": "renamed"},
            session=admin_session,
            pdp=pdp_with_pack,
            db=db,
        )
        assert _status(rename) == 403
        assert db.writes == []


class TestLegitimateAdministration:
    """Hardening must not break the intended paths (spec AC10, AC19)."""

    @pytest.mark.asyncio
    async def test_admin_can_still_administer_users(self, app, admin_session, db, pdp_with_pack):
        response = await _drive(
            app,
            "PATCH",
            f"/api/v1/users/{VICTIM_ID}",
            {"email": "new@example.test"},
            session=admin_session,
            pdp=pdp_with_pack,
            db=db,
        )
        assert not isinstance(response, web.HTTPException), getattr(response, "text", response)
        assert [w[1] for w in db.writes_to(User)] == ["update"]

    @pytest.mark.asyncio
    async def test_user_can_still_edit_own_profile(self, app, ordinary_session, db, pdp_with_pack):
        response = await _drive(
            app,
            "PATCH",
            f"/api/v1/users/{OWNER_ID}",
            {"first_name": "Renamed", "timezone": "UTC"},
            session=ordinary_session,
            pdp=pdp_with_pack,
            db=db,
        )
        assert not isinstance(response, web.HTTPException), getattr(response, "text", response)
        assert [w[1] for w in db.writes_to(User)] == ["update"]

    @pytest.mark.asyncio
    async def test_admin_can_create_user_then_reset_password(self, app, admin_session, db, pdp_with_pack):
        """AC19: creation is PUT; the new user has no password until password_reset."""
        body = {"first_name": "New", "last_name": "User", "username": "newuser", "email": "new@example.test"}
        created = await _drive(app, "PUT", "/api/v1/users", body, session=admin_session, pdp=pdp_with_pack, db=db)
        assert not isinstance(created, web.HTTPException), getattr(created, "text", created)
        inserts = [w for w in db.writes_to(User) if w[1] == "insert"]
        assert len(inserts) == 1
        assert "password" not in body

        # password_reset: the only password path, driven directly.
        target = User(user_id=123, first_name="New", last_name="User", username="newuser", email="new@example.test")
        session = _session(ADMIN_ID, ["superuser"], "root", superuser=True)
        session[SESSION_KEY] = "sid"
        handler = UserSession()
        request = make_mocked_request(
            "POST",
            "/api/v2/user/password_reset/123",
            match_info={"userid": "123"},
            app={"authdb": MagicMock(acquire=AsyncMock(return_value=db.conn))},
        )
        handler.json_data = AsyncMock(return_value={"password": "S3cret!pass"})
        conn = FakeTransitionConn(stored="")  # created without a password
        revoker = MagicMock(revoke_user=AsyncMock(return_value=0))
        with (
            patch("navigator_auth.handlers.users.session.get_session", new=AsyncMock(return_value=session)),
            patch.object(User, "get", new=AsyncMock(return_value=target)),
            _password_transition(conn, revoker),
        ):
            response = await handler.password_reset(request)
        assert response.status == 202
        [(sql, (user_id, new_hash))] = conn.updates
        assert user_id == 123
        assert "is_new = true" in sql
        assert check_password(new_hash, "S3cret!pass")

    @pytest.mark.asyncio
    async def test_role_grant_end_to_end(self, app, grantor_session, admin_session, db, pdp_with_pack):
        """AC11: security_admin + superuser grants (and is audited); plain superuser is refused."""
        statement_rows = {
            GRANTOR_ID: {"user_id": GRANTOR_ID, "is_superuser": True, "is_staff": True, "user_role": 10},
            VICTIM_ID: {"user_id": VICTIM_ID, "is_superuser": False, "is_staff": False, "user_role": 0},
            ADMIN_ID: {"user_id": ADMIN_ID, "is_superuser": True, "is_staff": True, "user_role": 10},
        }

        class RoleConn(FakeConn):
            async def transaction(self):
                self.calls.append(("transaction", "", ()))
                return self

            async def commit(self):
                self.calls.append(("commit", "", ()))

            async def rollback(self):
                self.calls.append(("rollback", "", ()))

            async def fetch_one(self, sql, *args):
                self.calls.append(("fetch_one", sql, args))
                if sql.lstrip().startswith("UPDATE"):
                    row = dict(statement_rows[args[0]])
                    row["is_staff"] = True
                    return row
                return statement_rows.get(args[0])

        conn = RoleConn()

        async def _role_call(session):
            probe = make_mocked_request("POST", f"/api/v1/users/{VICTIM_ID}/role")
            match = await app.router.resolve(probe)
            assert match.handler is UserRoleHandler
            holder = {"authdb": MagicMock(acquire=AsyncMock(return_value=conn)), "abac": pdp_with_pack}
            request = make_mocked_request("POST", f"/api/v1/users/{VICTIM_ID}/role", app=holder, match_info=match)
            request["authenticated"] = True
            handler = UserRoleHandler.__new__(UserRoleHandler)
            handler._request = request
            handler._json = JSONContent()
            handler.logger = MagicMock()
            handler.json_data = AsyncMock(return_value={"is_staff": True})
            with _Ctx(_sessions(session)):
                try:
                    return await handler.post()
                except web.HTTPException as exc:
                    return exc

        refused = await _role_call(admin_session)
        assert _status(refused) == 403
        assert not [c for c in conn.calls if c[1].lstrip().startswith("UPDATE")]

        pdp_with_pack._auditlog.log.reset_mock()
        allowed = await _role_call(grantor_session)
        assert not isinstance(allowed, web.HTTPException), getattr(allowed, "text", allowed)
        assert allowed.status == 200
        assert [c for c in conn.calls if c[1].lstrip().startswith("UPDATE")]
        assert pdp_with_pack._auditlog.log.await_count >= 1
        # Selects lock the rows and the write commits (issue:952f6c12269b).
        assert all("FOR UPDATE" in c[1] for c in conn.calls if c[0] == "fetch_one" and c[1].startswith("SELECT"))
        assert [c[0] for c in conn.calls if c[0] in ("commit", "rollback")] == ["commit"]


class TestPasswordPathsUnchanged:
    """AC9: pin the CURRENT behaviour of the two password paths, quirks included."""

    @staticmethod
    def _request(path, match, db):
        return make_mocked_request(
            "POST",
            path,
            match_info=match,
            app={"authdb": MagicMock(acquire=AsyncMock(return_value=db.conn))},
        )

    @pytest.mark.asyncio
    async def test_password_change_still_works(self, db):
        from navigator_auth.handlers.users.passwd import check_password, set_basic_password

        old_hash = set_basic_password("oldpass-123")
        user = User(user_id=OWNER_ID, first_name="O", last_name="W", username="owner", email="o@example.test")
        user.password = old_hash
        session = _session(OWNER_ID, ["users"])
        session[SESSION_KEY] = "sid"
        handler = UserSession()
        handler.get_json = AsyncMock(return_value={"password": "newpass-456", "old_password": "oldpass-123"})
        request = self._request("/api/v2/user/set_password", {}, db)
        conn = FakeTransitionConn(stored=old_hash)
        with (
            patch("navigator_auth.handlers.users.session.get_session", new=AsyncMock(return_value=session)),
            patch.object(User, "get", new=AsyncMock(return_value=user)),
            patch.object(User, "update", new=AsyncMock(return_value=user)) as update,
            _password_transition(conn),
        ):
            response = await handler.password_change(request)
        assert response.status == 202
        # The write is one UPDATE on the transition connection, not Model.update.
        update.assert_not_awaited()
        [(_sql, (user_id, new_hash))] = conn.updates
        assert user_id == OWNER_ID
        assert check_password(new_hash, "newpass-456")

    @pytest.mark.asyncio
    async def test_password_change_wrong_old_password_refused(self, db):
        from navigator_auth.handlers.users.passwd import set_basic_password

        user = User(user_id=OWNER_ID, first_name="O", last_name="W", username="owner", email="o@example.test")
        user.password = set_basic_password("oldpass-123")
        session = _session(OWNER_ID, ["users"])
        session[SESSION_KEY] = "sid"
        handler = UserSession()
        handler.get_json = AsyncMock(return_value={"password": "newpass-456", "old_password": "WRONG"})
        request = self._request("/api/v2/user/set_password", {}, db)
        with (
            patch("navigator_auth.handlers.users.session.get_session", new=AsyncMock(return_value=session)),
            patch.object(User, "get", new=AsyncMock(return_value=user)),
            patch.object(User, "update", new=AsyncMock(return_value=user)) as update,
            pytest.raises(web.HTTPException) as caught,
        ):
            await handler.password_change(request)
        # A wrong current password is a 403 (issue:f6cd44f3f6d2), not a 500.
        assert caught.value.status == 403
        update.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_password_reset_still_works(self, db):
        user = User(user_id=VICTIM_ID, first_name="V", last_name="T", username="victim", email="v@example.test")
        session = _session(ADMIN_ID, ["superuser"], "root", superuser=True)
        session[SESSION_KEY] = "sid"
        handler = UserSession()
        handler.json_data = AsyncMock(return_value={"password": "reset-789"})
        request = self._request(f"/api/v2/user/password_reset/{VICTIM_ID}", {"userid": str(VICTIM_ID)}, db)
        conn = FakeTransitionConn(stored="")
        revoker = MagicMock(revoke_user=AsyncMock(return_value=1))
        with (
            patch("navigator_auth.handlers.users.session.get_session", new=AsyncMock(return_value=session)),
            patch.object(User, "get", new=AsyncMock(return_value=user)),
            patch.object(User, "update", new=AsyncMock(return_value=user)) as update,
            _password_transition(conn, revoker),
        ):
            response = await handler.password_reset(request)
        assert response.status == 202
        update.assert_not_awaited()
        [(sql, (user_id, new_hash))] = conn.updates
        assert user_id == VICTIM_ID
        assert "is_new = true" in sql
        assert check_password(new_hash, "reset-789")
        # A reset revokes the target's sessions, strictly.
        revoker.revoke_user.assert_awaited_once()
        assert revoker.revoke_user.await_args.kwargs == {"strict": True}

    @pytest.mark.asyncio
    async def test_password_reset_refused_for_non_superuser(self, db):
        session = _session(OWNER_ID, ["users"], "owner", superuser=False)
        session[SESSION_KEY] = "sid"
        handler = UserSession()
        handler.json_data = AsyncMock(return_value={"password": "reset-789"})
        request = self._request(f"/api/v2/user/password_reset/{VICTIM_ID}", {"userid": str(VICTIM_ID)}, db)
        with (
            patch("navigator_auth.handlers.users.session.get_session", new=AsyncMock(return_value=session)),
            patch.object(User, "update", new=AsyncMock()) as update,
            pytest.raises(web.HTTPException) as caught,
        ):
            await handler.password_reset(request)
        assert caught.value.status == 406
        update.assert_not_awaited()
