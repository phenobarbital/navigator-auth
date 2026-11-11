"""Second-factor HTTP surface (FEAT-106, spec §3 Module 10).

Only ``verify()`` turns a factor into a session. Every verification and resend
runs under the per-user PostgreSQL advisory lock (MfaSecurity.user_lock), held
through session creation, so it serializes with every MFA security transition.
Codes, challenge tokens and device tokens are never logged (AC14).
"""

import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from aiohttp import web

from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY, AUTH_OTP_CHALLENGE_TTL
from navigator_auth.decorators import policy_allows
from navigator_auth.exceptions import FailedAuth, InvalidAuth, MfaSignal, UserNotFound
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.services import MfaServices, get_mfa_services
from navigator_auth.mfa.notify import notify_security_event
from navigator_auth.mfa.state import usable_email
from navigator_auth.mfa.store import ENROLLMENT_TTL
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device
from navigator_auth.mfa.types import (
    AMR_BY_PROVIDER,
    AMR_PASSWORD,
    MFA_DEVICE_TOKEN_KEY,
    EnrollmentAuthorization,
    MfaAuditEntry,
    MfaMode,
    MfaSecurityNotice,
    MfaState,
    PROVIDER_EMAIL,
    PROVIDER_TOTP,
    MfaChallenge,
    MfaEvaluation,
)
from navigator_auth.responses import JSONResponse
from navigator_session import AUTH_SESSION_OBJECT, get_session

logger = logging.getLogger("navigator.auth.mfa")

MFA_PREFIX = "/auth/mfa"
NO_STORE = {"Cache-Control": "no-store"}


def _error(code: str, status: int, **extra: Any) -> web.Response:
    """Return a uniform JSON error without sensitive values."""
    return JSONResponse({"error": code, **extra}, status=status, headers=NO_STORE)


async def _json_body(request: web.Request) -> dict:
    """Return the JSON object body, or an empty dict for anything else."""
    try:
        body = await request.json()
    except Exception:  # pylint: disable=W0718 -- malformed JSON is an invalid request.
        return {}
    return body if isinstance(body, dict) else {}


def _remote(request: web.Request) -> str:
    """Return the request's remote address with a safe fallback."""
    return request.remote or "unknown"


def setup_mfa_routes(app: web.Application, router: Any) -> None:
    """Register the sessionless MFA challenge and verification routes."""
    handler = MfaHandler()
    router.add_post(f"{MFA_PREFIX}/challenge", handler.challenge, name="mfa_challenge")
    router.add_post(f"{MFA_PREFIX}/verify", handler.verify, name="mfa_verify")
    excluded = app[AUTH_EXCLUDE_LIST_KEY]
    for path in (f"{MFA_PREFIX}/challenge", f"{MFA_PREFIX}/verify"):
        if path not in excluded:
            excluded.append(path)
    router.add_post(f"{MFA_PREFIX}/totp/enroll", handler.enroll_totp, name="mfa_totp_enroll")
    router.add_post(f"{MFA_PREFIX}/totp/confirm", handler.confirm_totp, name="mfa_totp_confirm")
    router.add_delete(f"{MFA_PREFIX}/totp", handler.disenroll_totp, name="mfa_totp_disenroll")
    router.add_post(f"{MFA_PREFIX}/backup-codes", handler.backup_codes, name="mfa_backup_codes")
    # Registered AFTER the literal /totp DELETE; NOT in AUTH_EXCLUDE_LIST_KEY.
    router.add_delete(rf"{MFA_PREFIX}/{{user_id:\d+}}", handler.admin_disenroll, name="mfa_admin_disenroll")


class MfaHandler:
    """Challenge resend and verification (management routes added by TASK-141/142)."""

    async def verify(self, request: web.Request) -> web.Response:
        """POST /auth/mfa/verify for a signed challenge and an OTP code."""
        services = get_mfa_services(request.app)
        if services is None or not services.available:
            return _error("mfa_unavailable", 503)
        body = await _json_body(request)
        token, provider, code = body.get("challenge"), body.get("provider"), body.get("code")
        if not all(isinstance(value, str) and value for value in (token, provider, code)):
            return _error("invalid_request", 400)
        try:
            preview = await services.store.peek(token)
            if preview is None:
                return _error("invalid_challenge", 401)
            async with services.security.user_lock(preview.user_id) as conn:
                return await self._verify_locked(request, services, conn, token, provider, code, body)
        except web.HTTPException:
            raise
        except Exception as err:  # pylint: disable=W0718 -- security dependencies fail closed.
            logger.error("MFA verify: refused, dependency failure: %s", type(err).__name__)
            return _error("mfa_unavailable", 503)

    async def _session_user(self, request: web.Request) -> tuple[Any, Any, Any]:
        """Return MFA services, the live session, and its fresh user record."""
        services = get_mfa_services(request.app)
        if services is None or not services.available:
            raise web.HTTPServiceUnavailable(text='{"error": "mfa_unavailable"}', content_type="application/json")
        if not request.get("authenticated", False):
            raise web.HTTPUnauthorized(text='{"error": "session_required"}', content_type="application/json")
        session = await get_session(request, new=False)
        if session is None:
            raise web.HTTPUnauthorized(text='{"error": "session_required"}', content_type="application/json")
        session_data = session.get(AUTH_SESSION_OBJECT, {}) if hasattr(session, "get") else {}
        user_id = getattr(getattr(request, "user", None), "user_id", None) or session_data.get("user_id")
        if user_id is None:
            raise web.HTTPUnauthorized(text='{"error": "session_required"}', content_type="application/json")
        try:
            record = await services.backend._idp.user_from_id(int(user_id))
        except UserNotFound:
            raise web.HTTPUnauthorized(text='{"error": "session_required"}', content_type="application/json")
        return services, session, record

    @staticmethod
    def _fresh_password_ok(services: Any, record: Any, password: Optional[str]) -> bool:
        """Check the password supplied in this request against the stored hash."""
        if not password:
            return False
        try:
            stored = record["password"] if isinstance(record, dict) else getattr(record, "password", None)
            username = record.get("username") if isinstance(record, dict) else getattr(record, "username", None)
            return services.backend._idp.check_password(stored, password, login=username)
        except (InvalidAuth, ValueError, TypeError, AttributeError):
            return False

    async def _strong_factor_proof(
        self, request: web.Request, services: Any, session: Any, record: Any, body: dict
    ) -> bool:
        """Accept current TOTP, an unused backup code, or a fresh passkey session."""
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        code = body.get("code")
        if code and await services.providers[PROVIDER_TOTP].verify(request, record, code):
            return True
        backup_code = body.get("backup_code")
        if backup_code and await services.backup_codes.consume(uid, backup_code):
            return True
        session_data = session.get(AUTH_SESSION_OBJECT, {}) if hasattr(session, "get") else {}
        created = getattr(session, "created", 0)
        return (
            session_data.get("auth_method") == "passkey" and int(time.time()) - int(created) <= AUTH_OTP_CHALLENGE_TTL
        )

    async def _security_context(self, services: Any, record: Any, conn: Any) -> tuple[Any, MfaState, bool, str]:
        """Return policy, state, strong-factor status, and the current context digest."""
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        memberships = await services.resolver.memberships(uid, conn=conn)
        policy = await services.resolver.effective(record, conn=conn, memberships=memberships)
        totp = await services.state.totp_confirmed(uid, conn=conn)
        strong = await services.state.has_strong_factor(record, conn=conn)
        state = MfaState.TOTP if totp else (MfaState.EMAIL if policy.mode == MfaMode.ENFORCED else MfaState.NONE)
        digest = services.security.context_digest(
            user=record, memberships=memberships, policy=policy, state=state, has_strong_factor=strong
        )
        return policy, state, strong, digest

    async def _verify_locked(
        self,
        request: web.Request,
        services: MfaServices,
        conn: Any,
        token: str,
        provider: str,
        code: str,
        body: dict,
    ) -> web.Response:
        """Verify inside one advisory-lock transaction through session creation."""
        record = await services.store.peek(token)
        if record is None:
            return _error("invalid_challenge", 401)
        revalidated = await self._revalidate(request, services, conn, token, record)
        if isinstance(revalidated, web.Response):
            return revalidated
        user, evaluation = revalidated
        if not await services.user_limiter.check(str(record.user_id)) or not await services.ip_limiter.check(
            _remote(request)
        ):
            return _error("rate_limited", 429)
        if (
            provider not in record.providers
            or provider not in evaluation.providers
            or provider not in services.providers
        ):
            return await self._failed(services, token)
        if not await services.providers[provider].verify(request, user, code, challenge=record):
            return await self._failed(services, token)
        consumed = await services.store.consume(token)
        if consumed is None or consumed != record:
            return _error("invalid_challenge", 401)
        extra = {"auth_method": "basic", "mfa": True, "amr": [AMR_PASSWORD, AMR_BY_PROVIDER[provider]]}
        try:
            result = await services.backend.open_session(request, user, extra=extra)
        except FailedAuth as err:
            return _error("account_disabled", err.status)
        device = await self._maybe_trust_device(services, conn, evaluation, body)
        if device is not None:
            result[MFA_DEVICE_TOKEN_KEY] = device
        return await request.app["auth"].finalize_login(request, result)

    async def _revalidate(
        self, request: web.Request, services: MfaServices, conn: Any, token: str, record: MfaChallenge
    ) -> tuple[Any, MfaEvaluation] | web.Response:
        """Return fresh user/evaluation, discarding challenges on any context drift."""
        try:
            user = await services.backend._idp.user_from_id(record.user_id)
        except UserNotFound:
            await services.store.discard(token)
            return _error("invalid_challenge", 401)
        try:
            evaluation = await services.evaluate(user, conn=conn)
        except MfaSignal as err:
            await services.store.discard(token)
            return JSONResponse(err.payload(), status=err.status, headers=NO_STORE)
        if evaluation.security_version != record.security_version or not secrets.compare_digest(
            evaluation.context_digest, record.context_digest
        ):
            await services.store.discard(token)
            return _error("stale_challenge", 401)
        return user, evaluation

    async def _failed(self, services: MfaServices, token: str) -> web.Response:
        """Count an invalid OTP attempt while preserving the first four attempts."""
        remaining = await services.store.register_failure(token)
        if remaining < 0:
            return _error("invalid_challenge", 401)
        return _error("invalid_code", 401, attempts_remaining=remaining)

    async def _maybe_trust_device(
        self, services: MfaServices, conn: Any, evaluation: MfaEvaluation, body: dict
    ) -> Optional[dict]:
        """Issue a trusted device only when requested and policy permits it."""
        if not body.get("remember_device"):
            return None
        if not may_offer_trusted_device(
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        label = str(body.get("device_label") or "")[:128]
        raw = await services.trusted_devices.issue(
            evaluation.user_id, evaluation.policy.remember_days, label, conn=conn
        )
        return {"token": raw, "max_age": evaluation.policy.remember_days * 86400}

    async def challenge(self, request: web.Request) -> web.Response:
        """POST /auth/mfa/challenge resends an email OTP without resetting expiry or attempts."""
        services = get_mfa_services(request.app)
        if services is None or not services.available:
            return _error("mfa_unavailable", 503)
        token = (await _json_body(request)).get("challenge")
        if not isinstance(token, str) or not token:
            return _error("invalid_request", 400)
        try:
            preview = await services.store.peek(token)
            if preview is None:
                return _error("invalid_challenge", 401)
            async with services.security.user_lock(preview.user_id) as conn:
                record = await services.store.peek(token)
                if record is None:
                    return _error("invalid_challenge", 401)
                revalidated = await self._revalidate(request, services, conn, token, record)
                if isinstance(revalidated, web.Response):
                    return revalidated
                user, evaluation = revalidated
                if not await services.user_limiter.check(str(record.user_id)) or not await services.ip_limiter.check(
                    _remote(request)
                ):
                    return _error("rate_limited", 429)
                if PROVIDER_EMAIL in record.providers and PROVIDER_EMAIL in evaluation.providers:
                    issued = await services.providers[PROVIDER_EMAIL].challenge(request, user)
                    if await services.store.replace_email_code(token, issued["code_hash"]) is None:
                        return _error("invalid_challenge", 401)
                expires_in = await services.store.remaining_ttl(token)
        except web.HTTPException:
            raise
        except Exception as err:  # pylint: disable=W0718 -- security dependencies fail closed.
            logger.error("MFA challenge resend: refused, dependency failure: %s", type(err).__name__)
            return _error("mfa_unavailable", 503)
        return JSONResponse({"status": "accepted", "expires_in": expires_in}, status=202, headers=NO_STORE)

    async def enroll_totp(self, request: web.Request) -> web.Response:
        """Start a pending, session-bound TOTP enrolment."""
        services, session, record = await self._session_user(request)
        body = await _json_body(request)
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        if not self._fresh_password_ok(services, record, body.get("password")):
            return _error("invalid_credentials", 403)
        try:
            if await services.state.has_strong_factor(record) and not await self._strong_factor_proof(
                request, services, session, record, body
            ):
                return _error("strong_factor_proof_required", 403)
            async with services.security.user_lock(uid) as conn:
                policy, state, _, digest = await self._security_context(services, record, conn)
                version = await services.security.current_version(conn, uid)
                authorization = EnrollmentAuthorization(
                    user_id=uid,
                    session_id=session.session_id,
                    security_version=version,
                    context_digest=digest,
                    expires_at=datetime.now(timezone.utc) + timedelta(seconds=ENROLLMENT_TTL),
                )
                payload = await services.providers[PROVIDER_TOTP].start_enrollment(record, authorization)
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=uid,
                        target_user_id=uid,
                        org_id=policy.org_id or None,
                        action="totp_enroll_start",
                        old_state=state.value,
                        new_state=state.value,
                        method="totp",
                        outcome="pending",
                    ),
                )
            return JSONResponse(payload, status=201, headers=NO_STORE)
        except MfaStorageError:
            return _error("mfa_unavailable", 503)

    async def confirm_totp(self, request: web.Request) -> web.Response:
        """Confirm a pending TOTP seed and atomically install it."""
        services, session, record = await self._session_user(request)
        body = await _json_body(request)
        token, code = body.get("enrollment_token"), body.get("code")
        if not isinstance(token, str) or not token or not isinstance(code, str) or not code:
            return _error("invalid_body", 400)
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        if not await services.user_limiter.check(f"enroll:{uid}") or not await services.ip_limiter.check(
            _remote(request)
        ):
            return _error("rate_limited", 429)
        try:
            async with services.security.user_lock(uid) as conn:
                policy, old_state, _, _ = await self._security_context(services, record, conn)
                ok = await services.providers[PROVIDER_TOTP].confirm_enrollment(
                    record, code, token, session.session_id, conn=conn
                )
                if not ok:
                    pending = await services.store.peek_enrollment(token)
                    remaining = 0 if pending is not None else -1
                    raise _EnrollmentFailed(remaining)
                await services.security.bump_version(conn, uid)
                await services.trusted_devices.revoke_all(uid, "totp_enrolled", conn=conn)
                codes = None
                if await services.backup_codes.remaining(uid, conn=conn) == 0:
                    codes = await services.backup_codes.generate(uid, conn=conn)
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=uid,
                        target_user_id=uid,
                        org_id=policy.org_id or None,
                        action="totp_confirm",
                        old_state=old_state.value,
                        new_state="totp",
                        method="totp",
                        outcome="success",
                    ),
                )
            payload = {"status": "confirmed"}
            if codes:
                payload["backup_codes"] = codes
            return JSONResponse(payload, status=200, headers=NO_STORE)
        except _EnrollmentFailed as err:
            if err.remaining < 0:
                return _error("invalid_enrollment", 400)
            return _error("invalid_code", 400, attempts_remaining=max(err.remaining, 0))
        except MfaStorageError:
            return _error("mfa_unavailable", 503)

    async def disenroll_totp(self, request: web.Request) -> web.Response:
        """Disenrol TOTP after fresh password and strong-factor proof."""
        services, session, record = await self._session_user(request)
        body = await _json_body(request)
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        if not self._fresh_password_ok(services, record, body.get("password")):
            return _error("invalid_credentials", 403)
        if not await services.providers[PROVIDER_TOTP].is_enrolled(record):
            return _error("not_enrolled", 404)
        policy = await services.resolver.effective(record)
        if await services.state.requires_strong_factor(record, policy) and await services.state.passkey_count(uid) == 0:
            return _error("strong_factor_required", 409)
        proof = body.get("code")
        valid = bool(proof and await services.providers[PROVIDER_TOTP].verify(request, record, proof))
        if not valid and body.get("backup_code"):
            valid = await services.backup_codes.consume(uid, body["backup_code"])
        if not valid:
            return _error("strong_factor_proof_required", 403)
        try:
            async with services.security.user_lock(uid) as conn:
                policy, old_state, _, _ = await self._security_context(services, record, conn)
                await services.providers[PROVIDER_TOTP].disenroll(record, conn=conn)
                await services.security.bump_version(conn, uid)
                await services.trusted_devices.revoke_all(uid, "totp_disenrolled", conn=conn)
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=uid,
                        target_user_id=uid,
                        org_id=policy.org_id or None,
                        action="totp_disenroll",
                        old_state=old_state.value,
                        new_state="none",
                        method="totp",
                        outcome="success",
                    ),
                )
            await notify_security_event(
                MfaSecurityNotice(
                    email=usable_email(record),
                    display_name=str(getattr(record, "display_name", "") or ""),
                    username=str(getattr(record, "username", uid)),
                    event="totp_disenrolled",
                    occurred_at=datetime.now(timezone.utc),
                    actor=None,
                )
            )
            return JSONResponse({"status": "disenrolled"}, status=200, headers=NO_STORE)
        except MfaStorageError:
            return _error("mfa_unavailable", 503)

    async def backup_codes(self, request: web.Request) -> web.Response:
        """Generate and return a replacement backup-code set once."""
        services, _, record = await self._session_user(request)
        body = await _json_body(request)
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        if not self._fresh_password_ok(services, record, body.get("password")):
            return _error("invalid_credentials", 403)
        if not await services.state.has_strong_factor(record):
            return _error("strong_factor_required", 403)
        try:
            async with services.security.user_lock(uid) as conn:
                policy, state, _, _ = await self._security_context(services, record, conn)
                codes = await services.backup_codes.generate(uid, conn=conn)
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=uid,
                        target_user_id=uid,
                        org_id=policy.org_id or None,
                        action="backup_codes_regenerate",
                        old_state=state.value,
                        new_state=state.value,
                        method="backup",
                        outcome="success",
                    ),
                )
            return JSONResponse({"backup_codes": codes, "count": len(codes)}, status=201, headers=NO_STORE)
        except MfaStorageError:
            return _error("mfa_unavailable", 503)


    async def _audit_denied(self, services: Any, actor_id: int, target_id: int, reason: str) -> None:
        """Durable record of a refused admin disenrolment. Best effort: never changes the response."""
        try:
            async with services.security.user_lock(target_id) as conn:
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=actor_id,
                        target_user_id=target_id,
                        org_id=None,
                        action="admin_disenroll",
                        method="admin",
                        outcome="denied",
                        detail={"reason": reason},
                    ),
                )
        except Exception as err:  # pylint: disable=W0718 -- a denial stays a 403.
            logger.warning("MFA admin disenroll: denial audit not written: %s", type(err).__name__)

    async def admin_disenroll(self, request: web.Request) -> web.Response:
        """DELETE /auth/mfa/{user_id} -- switch a user's OTP off and nothing else (AC16, AC26).

        Gated by ABAC ``mfa:disenroll`` (policy ``mfa_admin_access``) AND tenant
        ownership. Disables TOTP, invalidates backup codes (D21), bumps the security
        version, revokes trusted devices, audits, then notifies the target.
        """
        services, _, actor = await self._session_user(request)
        actor_id = int(actor["user_id"] if isinstance(actor, dict) else getattr(actor, "user_id"))
        target_id = int(request.match_info["user_id"])
        if target_id == actor_id:
            await self._audit_denied(services, actor_id, target_id, "self_target")
            return _error("self_disenroll_forbidden", 403)
        allowed, reason, _ = await policy_allows(
            "mfa_admin_access", request, action="mfa:disenroll", resource=request.path
        )
        if not allowed:
            await self._audit_denied(services, actor_id, target_id, f"abac: {reason}")
            return _error("forbidden", 403)
        try:
            actor_orgs = set(await services.resolver.memberships(actor_id))
            target_orgs = set(await services.resolver.memberships(target_id))
        except MfaStorageError:
            return _error("mfa_unavailable", 503)
        if not target_orgs or not target_orgs <= actor_orgs:
            await self._audit_denied(services, actor_id, target_id, "foreign_tenant")
            return _error("forbidden", 403)
        try:
            record = await services.backend._idp.user_from_id(target_id)
        except UserNotFound:
            return _error("not_found", 404)
        try:
            async with services.security.user_lock(target_id) as conn:
                old = "totp" if await services.state.totp_confirmed(target_id, conn=conn) else "none"
                await services.providers[PROVIDER_TOTP].disenroll(record, conn=conn)
                dropped = await services.backup_codes.invalidate_all(target_id, conn=conn)
                await services.security.bump_version(conn, target_id)
                revoked = await services.trusted_devices.revoke_all(target_id, "admin_disenroll", conn=conn)
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=actor_id,
                        target_user_id=target_id,
                        org_id=min(target_orgs),
                        action="admin_disenroll",
                        old_state=old,
                        new_state="none",
                        method="admin",
                        outcome="success",
                        detail={
                            "orgs": sorted(target_orgs),
                            "backup_codes_invalidated": dropped,
                            "devices_revoked": revoked,
                        },
                    ),
                )
        except MfaStorageError:
            return _error("mfa_unavailable", 503)
        await notify_security_event(
            MfaSecurityNotice(
                email=usable_email(record),
                display_name=str(getattr(record, "display_name", "") or ""),
                username=str(getattr(record, "username", target_id)),
                event="admin_disenrolled",
                occurred_at=datetime.now(timezone.utc),
                actor=str(getattr(actor, "username", actor_id)),
            )
        )
        return JSONResponse({"status": "disenrolled", "user_id": target_id}, status=200, headers=NO_STORE)


class _EnrollmentFailed(Exception):
    """Internal rollback sentinel for failed enrollment confirmation."""

    def __init__(self, remaining: int) -> None:
        self.remaining = remaining
