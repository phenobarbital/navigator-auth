"""FEAT-106 review fixes — lock core (M2): bounded user_lock and LOCK_CONNECTION (AC10, AC11)."""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from navigator_session import AUTH_SESSION_OBJECT

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from navigator_auth.handlers.recovery.revoke import RevocationError
from navigator_auth.handlers.users.passwd import check_password, set_basic_password
from navigator_auth.handlers.users.session import UserSession
from navigator_auth.mfa.events import TransitionAborted, security_transition
from navigator_auth.mfa.exceptions import MfaStorageError, MfaUnavailable
from navigator_auth.mfa.security import LOCK_CONNECTION, MfaSecurity, advisory_user_lock
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.security_state import current_generation, ensure_security_state_tables
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory, single_connection_authdb  # noqa: F401


@pytest.mark.asyncio
async def test_user_lock_timeout(mfa_db, mfa_user_factory, mfa_secret, monkeypatch):
    """A held advisory lock makes a second user lock time out within the configured bound."""
    monkeypatch.setattr("navigator_auth.mfa.security.AUTH_MFA_LOCK_TIMEOUT", 0.3)
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold_lock() -> None:
        async with security.user_lock(user["user_id"]):
            entered.set()
            await release.wait()

    holder = asyncio.create_task(hold_lock())
    await entered.wait()
    started = asyncio.get_running_loop().time()
    with pytest.raises(MfaStorageError):
        async with security.user_lock(user["user_id"]):
            pass
    assert asyncio.get_running_loop().time() - started < 2
    release.set()
    await holder


@pytest.mark.asyncio
async def test_user_lock_acquire_timeout(single_connection_authdb, mfa_user_factory):
    """With the only pool connection held, acquisition itself is bounded."""
    first_user, second_user = await mfa_user_factory(), await mfa_user_factory()
    async with advisory_user_lock(single_connection_authdb, first_user["user_id"]):
        with pytest.raises(MfaStorageError):
            async with advisory_user_lock(single_connection_authdb, second_user["user_id"], timeout=0.2):
                pass


@pytest.mark.asyncio
async def test_lock_connection_published(mfa_db, mfa_user_factory, mfa_secret):
    """The lock context holds the connection only for successful and failing bodies."""
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    assert LOCK_CONNECTION.get() is None
    async with security.user_lock(user["user_id"]) as conn:
        assert LOCK_CONNECTION.get() is conn
    assert LOCK_CONNECTION.get() is None
    with pytest.raises(RuntimeError, match="body failed"):
        async with security.user_lock(user["user_id"]) as conn:
            assert LOCK_CONNECTION.get() is conn
            raise RuntimeError("body failed")
    assert LOCK_CONNECTION.get() is None


@pytest.mark.asyncio
async def test_no_acquire_inside_lock_guard(single_connection_authdb, mfa_user_factory):
    """The fixture records and refuses an acquisition attempted inside a lock scope."""
    user = await mfa_user_factory()
    single_connection_authdb.strict = True
    async with advisory_user_lock(single_connection_authdb, user["user_id"]):
        with pytest.raises(AssertionError, match="inside a user_lock scope"):
            single_connection_authdb.acquire()
    assert len(single_connection_authdb.acquires_inside_lock) == 1
    assert LOCK_CONNECTION.get() is None
    async with await single_connection_authdb.acquire():
        pass
    assert single_connection_authdb.acquires == [False, True, False]


@pytest.mark.asyncio
async def test_advisory_user_lock_serializes_without_mfa_security(mfa_db, mfa_user_factory):
    """The standalone advisory lock serializes a user without an MFA secret or service."""
    user = await mfa_user_factory()
    entered = asyncio.Event()
    release = asyncio.Event()
    timestamps = {}
    loop = asyncio.get_running_loop()

    async def first() -> None:
        async with advisory_user_lock(mfa_db, user["user_id"]):
            timestamps["first_enter"] = loop.time()
            entered.set()
            await release.wait()
            timestamps["first_exit"] = loop.time()

    async def second() -> None:
        await entered.wait()
        async with advisory_user_lock(mfa_db, user["user_id"]):
            timestamps["second_enter"] = loop.time()

    first_task = asyncio.create_task(first())
    await entered.wait()
    second_task = asyncio.create_task(second())
    await asyncio.sleep(0.05)
    assert "second_enter" not in timestamps
    release.set()
    await asyncio.gather(first_task, second_task)
    assert timestamps["second_enter"] >= timestamps["first_exit"]


def _app_with_services(pool, secret: bytes) -> dict:
    """Return an app mapping with live MFA bookkeeping services on ``pool``."""
    services = MfaServices(
        backend=None,
        available=True,
        db_pool=pool,
        secret=secret,
        security=MfaSecurity(pool, secret),
        trusted_devices=TrustedDeviceStore(pool),
    )
    return {"authdb": pool, MFA_APP_KEY: MfaServicesSlot(services)}


@pytest.mark.asyncio
async def test_transition_unavailable_fails_closed():
    """Configured but unavailable MFA raises before the transition body executes."""
    app = {MFA_APP_KEY: MfaServicesSlot(MfaServices(backend=None, available=False))}
    ran = []

    with pytest.raises(MfaUnavailable):
        async with security_transition(app, 42, "password_change"):
            ran.append(True)

    assert ran == []


@pytest.mark.asyncio
async def test_transition_not_configured_yields_tx(mfa_db, mfa_user_factory):
    """No service slot yields an advisory-locked transaction that rolls body writes back."""
    user = await mfa_user_factory()
    app = {"authdb": mfa_db}

    with pytest.raises(RuntimeError, match="rollback"):
        async with security_transition(app, user["user_id"], "password_change") as conn:
            assert LOCK_CONNECTION.get() is conn
            changed = await conn.fetchval(
                f"UPDATE {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} SET first_name = $1 " "WHERE user_id = $2 RETURNING 1",
                "changed",
                user["user_id"],
            )
            assert changed == 1
            raise RuntimeError("rollback")

    async with await mfa_db.acquire() as conn:
        first_name = await conn.fetchval(
            f"SELECT first_name FROM {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} WHERE user_id = $1", user["user_id"]
        )
    assert first_name == ""


@pytest.mark.asyncio
async def test_transition_aborted_rolls_back(mfa_db, mfa_user_factory, mfa_secret):
    """TransitionAborted rolls back the body write, version increment, and audit row."""
    user = await mfa_user_factory()
    app = _app_with_services(mfa_db, mfa_secret)

    with pytest.raises(TransitionAborted, match="credentials_changed"):
        async with security_transition(app, user["user_id"], "password_change") as conn:
            changed = await conn.fetchval(
                f"UPDATE {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} SET first_name = $1 " "WHERE user_id = $2 RETURNING 1",
                "changed",
                user["user_id"],
            )
            assert changed == 1
            raise TransitionAborted("credentials_changed")

    security = MfaSecurity(mfa_db, mfa_secret)
    async with await mfa_db.acquire() as conn:
        first_name = await conn.fetchval(
            f"SELECT first_name FROM {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} WHERE user_id = $1", user["user_id"]
        )
        version = await security.current_version(conn, user["user_id"])
        audit_count = await conn.fetchval(
            f"SELECT count(*) FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE target_user_id = $1", user["user_id"]
        )
    assert first_name == ""
    assert version == 0
    assert audit_count == 0


@pytest.mark.asyncio
async def test_transition_commits_write_with_bookkeeping(
    single_connection_authdb, mfa_db, mfa_user_factory, mfa_secret
):
    """One connection commits the body write, version, and audit without a nested acquire."""
    user = await mfa_user_factory()
    app = _app_with_services(single_connection_authdb, mfa_secret)

    async def _transition() -> None:
        async with security_transition(app, user["user_id"], "password_change") as conn:
            assert LOCK_CONNECTION.get() is conn
            changed = await conn.fetchval(
                f"UPDATE {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} SET first_name = $1 " "WHERE user_id = $2 RETURNING 1",
                "committed",
                user["user_id"],
            )
            assert changed == 1

    await asyncio.wait_for(_transition(), timeout=10)

    security = MfaSecurity(mfa_db, mfa_secret)
    async with await mfa_db.acquire() as conn:
        first_name = await conn.fetchval(
            f"SELECT first_name FROM {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} WHERE user_id = $1", user["user_id"]
        )
        version = await security.current_version(conn, user["user_id"])
        audit_count = await conn.fetchval(
            f"SELECT count(*) FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE target_user_id = $1", user["user_id"]
        )
    assert first_name == "committed"
    assert version == 1
    assert audit_count == 1
    assert single_connection_authdb.acquires_inside_lock == []


class _Revoker:
    """Record strict password-reset revocation requests without external session state."""

    def __init__(self, error: Exception | None = None) -> None:
        """Initialize an optional failure raised by strict revocation."""
        self.error = error
        self.calls: list[tuple[object, bool]] = []

    async def revoke_user(self, request, user, *, strict: bool = False) -> int:
        """Record the request and either succeed or raise the configured error."""
        self.calls.append((user, strict))
        if self.error is not None:
            raise self.error
        return 1


def _response_body(response) -> dict:
    """Decode an aiohttp response body returned by a direct handler invocation."""
    return json.loads(response.body)


async def _password_change(pool, user: dict, app: dict, password: str = "ChangedPw1!"):
    """Invoke ``password_change`` with its authenticated session and JSON payload stubbed."""
    handler = UserSession()

    async def session(_request):
        return {AUTH_SESSION_OBJECT: {"user_id": user["user_id"], "superuser": user["is_superuser"]}}

    async def get_json(_request):
        return {"password": password, "old_password": user["password_plain"]}

    handler.session = session
    handler.get_json = get_json
    handler.match_parameters = lambda _request: {}
    return await handler.password_change(SimpleNamespace(app=app))


async def _password_reset(pool, actor: dict, user: dict, app: dict, password: str = "ResetPw1!"):
    """Invoke ``password_reset`` as an authenticated superuser with a JSON payload stubbed."""
    handler = UserSession()

    async def session(_request):
        return {AUTH_SESSION_OBJECT: {"user_id": actor["user_id"], "superuser": True}}

    async def json_data(_request):
        return {"password": password}

    handler.session = session
    handler.json_data = json_data
    handler.match_parameters = lambda _request: {"userid": user["user_id"]}
    return await handler.password_reset(SimpleNamespace(app=app))


async def _stored_password(pool, user_id: int) -> str:
    """Return the persisted password hash for a fixture user."""
    async with await pool.acquire() as conn:
        return await conn.fetchval(f"SELECT password FROM {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} WHERE user_id = $1", user_id)


@pytest.mark.asyncio
async def test_password_change_two_phase_success(mfa_db, mfa_user_factory, mfa_secret):
    """password_change updates its hash with the MFA audit and version in one transition."""
    user = await mfa_user_factory()
    response = await _password_change(mfa_db, user, _app_with_services(mfa_db, mfa_secret))

    assert response.status == 202
    assert check_password(await _stored_password(mfa_db, user["user_id"]), "ChangedPw1!")
    security = MfaSecurity(mfa_db, mfa_secret)
    async with await mfa_db.acquire() as conn:
        assert await security.current_version(conn, user["user_id"]) == 1
        assert await conn.fetchval(
            f"SELECT count(*) FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE target_user_id = $1", user["user_id"]
        ) == 1


@pytest.mark.asyncio
async def test_password_change_hash_drift_409(mfa_db, mfa_user_factory, monkeypatch):
    """A separately committed hash change between phases is rejected without another write."""
    user = await mfa_user_factory()
    changed_hash = set_basic_password("InterveningPw1!")
    original_transition = security_transition

    @asynccontextmanager
    async def drift_transition(app, user_id, event, **kwargs):
        async with original_transition(app, user_id, event, **kwargs) as conn:
            async with await mfa_db.acquire() as drift_conn:
                await drift_conn.fetchval(
                    f"UPDATE {AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE} SET password = $2 WHERE user_id = $1 RETURNING user_id",
                    user_id,
                    changed_hash,
                )
            yield conn

    monkeypatch.setattr("navigator_auth.handlers.users.session.security_transition", drift_transition)
    response = await _password_change(mfa_db, user, {"authdb": mfa_db})

    assert response.status == 409
    assert _response_body(response) == {"error": "credentials_changed"}
    assert await _stored_password(mfa_db, user["user_id"]) == changed_hash


@pytest.mark.asyncio
async def test_transition_atomic_on_audit_failure_password_flows(mfa_db, mfa_user_factory, mfa_secret, monkeypatch):
    """An audit failure rolls back password writes for both password flows."""
    change_user = await mfa_user_factory()
    actor = await mfa_user_factory(superuser=True)
    reset_user = await mfa_user_factory()
    app = _app_with_services(mfa_db, mfa_secret)
    change_before = await _stored_password(mfa_db, change_user["user_id"])
    reset_before = await _stored_password(mfa_db, reset_user["user_id"])

    async def fail_audit(self, conn, entry):
        raise MfaStorageError("injected")

    monkeypatch.setattr(MfaSecurity, "write_audit", fail_audit)
    monkeypatch.setattr(
        "navigator_auth.handlers.users.session.PasswordRecoveryHandler.session_revoker",
        classmethod(lambda cls: _Revoker()),
    )
    change_response = await _password_change(mfa_db, change_user, app)
    reset_response = await _password_reset(mfa_db, actor, reset_user, app)

    assert change_response.status == reset_response.status == 503
    assert await _stored_password(mfa_db, change_user["user_id"]) == change_before
    assert await _stored_password(mfa_db, reset_user["user_id"]) == reset_before


@pytest.mark.asyncio
async def test_password_flows_mfa_unavailable_503(mfa_db, mfa_user_factory, monkeypatch):
    """Configured but unavailable MFA fails both password flows before credential writes."""
    change_user = await mfa_user_factory()
    actor = await mfa_user_factory(superuser=True)
    reset_user = await mfa_user_factory()
    unavailable = {MFA_APP_KEY: MfaServicesSlot(MfaServices(backend=None, available=False)), "authdb": mfa_db}
    change_before = await _stored_password(mfa_db, change_user["user_id"])
    reset_before = await _stored_password(mfa_db, reset_user["user_id"])
    monkeypatch.setattr(
        "navigator_auth.handlers.users.session.PasswordRecoveryHandler.session_revoker",
        classmethod(lambda cls: _Revoker()),
    )

    change_response = await _password_change(mfa_db, change_user, unavailable)
    reset_response = await _password_reset(mfa_db, actor, reset_user, unavailable)

    assert change_response.status == reset_response.status == 503
    assert _response_body(change_response) == _response_body(reset_response) == {"error": "mfa_unavailable"}
    assert await _stored_password(mfa_db, change_user["user_id"]) == change_before
    assert await _stored_password(mfa_db, reset_user["user_id"]) == reset_before


@pytest.mark.asyncio
async def test_password_reset_revokes_sessions(mfa_db, mfa_user_factory, monkeypatch):
    """Reset increments generation and rolls both writes back when strict revocation fails."""
    await ensure_security_state_tables(mfa_db)
    actor = await mfa_user_factory(superuser=True)
    user = await mfa_user_factory()
    revoker = _Revoker()
    monkeypatch.setattr(
        "navigator_auth.handlers.users.session.PasswordRecoveryHandler.session_revoker", classmethod(lambda cls: revoker)
    )
    response = await _password_reset(mfa_db, actor, user, {"authdb": mfa_db})
    assert response.status == 202
    assert len(revoker.calls) == 1
    assert revoker.calls[0][0].user_id == user["user_id"]
    assert revoker.calls[0][1] is True
    async with await mfa_db.acquire() as conn:
        assert await current_generation(conn, user["user_id"]) == 1
    before = await _stored_password(mfa_db, user["user_id"])
    monkeypatch.setattr(
        "navigator_auth.handlers.users.session.PasswordRecoveryHandler.session_revoker",
        classmethod(lambda cls: _Revoker(RevocationError("injected"))),
    )
    failed = await _password_reset(mfa_db, actor, user, {"authdb": mfa_db}, password="AnotherPw1!")
    assert failed.status == 503
    assert _response_body(failed) == {"error": "temporarily_unavailable"}
    assert await _stored_password(mfa_db, user["user_id"]) == before
    async with await mfa_db.acquire() as conn:
        assert await current_generation(conn, user["user_id"]) == 1


@pytest.mark.asyncio
async def test_password_flows_single_connection(single_connection_authdb, mfa_user_factory, monkeypatch):
    """Both flows finish using a one-connection authdb without acquiring inside a lock."""
    await ensure_security_state_tables(single_connection_authdb)
    user = await mfa_user_factory()
    actor = await mfa_user_factory(superuser=True)
    monkeypatch.setattr(
        "navigator_auth.handlers.users.session.PasswordRecoveryHandler.session_revoker",
        classmethod(lambda cls: _Revoker()),
    )
    app = {"authdb": single_connection_authdb}
    await asyncio.wait_for(_password_change(single_connection_authdb, user, app), timeout=10)
    await asyncio.wait_for(_password_reset(single_connection_authdb, actor, user, app), timeout=10)
    assert single_connection_authdb.acquires_inside_lock == []
