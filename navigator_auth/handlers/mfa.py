"""Second-factor HTTP surface (FEAT-106, spec §3 Module 10).

Only ``verify()`` turns a factor into a session. Every verification and resend
runs under the per-user PostgreSQL advisory lock (MfaSecurity.user_lock), held
through session creation, so it serializes with every MFA security transition.
Codes, challenge tokens and device tokens are never logged (AC14).
"""

import logging
import secrets
from typing import Any, Optional

from aiohttp import web

from navigator_auth import conf as auth_conf
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.exceptions import FailedAuth, MfaSignal, UserNotFound
from navigator_auth.mfa.services import MfaServices, get_mfa_services
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device
from navigator_auth.mfa.types import (
    AMR_BY_PROVIDER,
    AMR_PASSWORD,
    MFA_DEVICE_TOKEN_KEY,
    PROVIDER_EMAIL,
    MfaChallenge,
    MfaEvaluation,
)
from navigator_auth.responses import JSONResponse

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
    # TASK-141 / TASK-142 register their (non-excluded) routes below this line.


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
        if not await services.user_limiter.check(str(record.user_id)) or not await services.ip_limiter.check(_remote(request)):
            return _error("rate_limited", 429)
        if provider not in record.providers or provider not in evaluation.providers or provider not in services.providers:
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
