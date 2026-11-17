"""Shared second-factor gate for every password login path (FEAT-106 review fixes, spec §3 M5).

The gate decides, verifies and issues a second-factor login under the per-user advisory lock, so
session issuance is serialized with every security transition (G1, G6). It never builds a session:
callers pass a ``SessionIssuer`` that the gate invokes inside the lock. Codes, challenge tokens and
device tokens are never logged.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Generic, NoReturn, Optional, TypeVar

from aiohttp import web

from navigator_auth import conf as auth_conf
from navigator_auth.authorizations._client_ip import limiter_client_ip, parse_proxies
from navigator_auth.exceptions import FailedAuth, InvalidAuth, MFARefused, MfaSignal, UserNotFound
from navigator_auth.mfa.services import MfaServices
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device
from navigator_auth.mfa.types import (
    AMR_BY_PROVIDER,
    AMR_PASSWORD,
    AMR_TRUSTED_DEVICE,
    PROVIDER_BACKUP,
    PROVIDER_EMAIL,
    PROVIDER_TOTP,
    TRUSTED_COOKIE,
    MfaChallenge,
    MfaEvaluation,
    MfaState,
)

logger = logging.getLogger("navigator.auth.mfa")

T = TypeVar("T")
SessionIssuer = Callable[[Any, dict], Awaitable[T]]


@dataclass(frozen=True)
class LoginChallenge:
    """A challenge a login adapter presents to a user for second-factor verification."""

    token: str
    providers: tuple[str, ...]
    preferred: Optional[str]
    expires_in: int


@dataclass(frozen=True)
class GateResult(Generic[T]):
    """The session or challenge result of a second-factor gate operation."""

    session: Optional[T] = None
    challenge: Optional[LoginChallenge] = None
    device: Optional[dict] = None


class VerifyRefused(Exception):
    """A verification refusal preserving the adapter's client-facing response envelope."""

    def __init__(self, code: str, status: int, **extra: Any) -> None:
        """Store the client-facing code, HTTP status, and extra envelope fields."""
        super().__init__(code)
        self.code = code
        self.status = status
        self.extra = dict(extra)


def _field(user: Any, name: str, default: Any = None) -> Any:
    """Read a field from a mapping or attribute-based user record."""
    try:
        value = user[name]
    except (KeyError, TypeError, AttributeError):
        value = getattr(user, name, default)
    return default if value is None else value


_TRUSTED_PROXIES = parse_proxies(auth_conf.ALLOWED_IP_TRUSTED_PROXIES)


def _remote(request: web.Request) -> str:
    """Return the client IP the MFA limiter keys on, honouring trusted proxies."""
    return limiter_client_ip(request, _TRUSTED_PROXIES)


class SecondFactorGate:
    """Decide, verify and issue a second-factor login under one user lock (spec §3 M5)."""

    def __init__(
        self, services: MfaServices, *, userid_attribute: str = "user_id", password_attribute: str = "password"
    ) -> None:
        """Bind the gate to already-leased, available MFA services."""
        self._services = services
        self._uid_attr = userid_attribute
        self._pwd_attr = password_attribute

    async def decide(self, request: web.Request, user: Any, issue: SessionIssuer[T]) -> GateResult[T]:
        """Decide a password login after the caller has completed its password check.

        Raises:
            FailedAuth: If the fresh account is disabled or its password hash changed.
            MFARefused: If no factor is available or a dependency is unavailable.
        """
        services = self._services
        uid = int(_field(user, self._uid_attr))
        try:
            # A refusal raised inside the lock would roll the lock transaction back, and with it a
            # trusted-device family revocation done on replay. Capture it, leave the lock scope normally
            # (committing), then re-raise.
            deferred: Optional[Exception] = None
            async with services.security.user_lock(uid) as conn:
                try:
                    fresh = await services.backend._idp.user_from_id(uid, conn=conn)  # pylint: disable=W0212
                    if not _field(fresh, "is_active", True):
                        raise FailedAuth("User account is disabled", status=403)
                    if not secrets.compare_digest(
                        str(_field(fresh, self._pwd_attr, "")), str(_field(user, self._pwd_attr, ""))
                    ):
                        raise FailedAuth("credentials_changed", status=401)
                    evaluation = await services.evaluate(fresh, conn=conn)
                    if evaluation.state == MfaState.NONE:
                        await services.security.commit_before_session(conn)
                        return GateResult(session=await issue(fresh, {}))
                    device_token = await self._trusted_device(request, conn, evaluation)
                    if device_token is not None:
                        await services.security.commit_before_session(conn)
                        session = await issue(fresh, {"mfa": True, "amr": [AMR_PASSWORD, AMR_TRUSTED_DEVICE]})
                        device = {"token": device_token, "max_age": evaluation.policy.remember_days * 86400}
                        return GateResult(session=session, device=device)
                    if not evaluation.providers:
                        raise MFARefused(
                            "no_factor_available", "No second factor is available for this account", status=403
                        )
                    code_hash = None
                    if evaluation.preferred == PROVIDER_EMAIL:
                        issued = await services.providers[PROVIDER_EMAIL].challenge(request, fresh)
                        code_hash = issued.get("code_hash")
                    token, _record = await services.store.issue(
                        fresh,
                        list(evaluation.providers),
                        evaluation.preferred,
                        security_version=evaluation.security_version,
                        context_digest=evaluation.context_digest,
                        email_code_hash=code_hash,
                    )
                except Exception as err:  # pylint: disable=W0718 -- re-raised after the lock commits.
                    deferred = err
            if deferred is not None:
                raise deferred
        except (MfaSignal, FailedAuth, InvalidAuth):
            raise
        except Exception as err:  # pylint: disable=W0718 -- security dependencies fail closed.
            logger.error("MFA gate: decide refused, dependency failure: %s", type(err).__name__)
            raise MFARefused("mfa_unavailable", "Second factor is temporarily unavailable", status=503) from err
        return GateResult(
            challenge=LoginChallenge(
                token=token,
                providers=tuple(evaluation.providers),
                preferred=evaluation.preferred,
                expires_in=int(auth_conf.AUTH_OTP_CHALLENGE_TTL),
            )
        )

    async def verify(
        self,
        request: web.Request,
        token: str,
        provider: str,
        code: str,
        issue: SessionIssuer[T],
        *,
        remember_device: bool = False,
        device_label: str = "",
    ) -> GateResult[T]:
        """Verify a challenge and issue the session under the user lock.

        Raises:
            VerifyRefused: When validation, policy, or dependency processing refuses the request.
        """
        services = self._services
        if not all(isinstance(value, str) and value for value in (token, provider, code)):
            raise VerifyRefused("invalid_request", 400)
        try:
            preview = await services.store.peek(token)
            if preview is None:
                raise VerifyRefused("invalid_challenge", 401)
            if not await services.user_limiter.check(str(preview.user_id)) or not await services.ip_limiter.check(
                _remote(request)
            ):
                raise VerifyRefused("rate_limited", 429)
            if provider not in preview.providers or provider not in services.providers:
                await self._failed(token)
            # D16 (deliberate): a backup code is burned on the store's OWN connection, outside the lock, so no
            # later failure (stale challenge, issuer error, rollback) can ever restore a used code. A stale
            # challenge therefore costs the user one code; that is fail-safe, never a bypass.
            if provider == PROVIDER_BACKUP and not await services.backup_codes.consume(preview.user_id, code):
                await self._failed(token)
            async with services.security.user_lock(preview.user_id) as conn:
                record = await services.store.peek(token)
                if record is None:
                    raise VerifyRefused("invalid_challenge", 401)
                user, evaluation = await self._revalidate(conn, token, record)
                if provider not in evaluation.providers and provider != PROVIDER_BACKUP:
                    await self._failed(token)
                if provider == PROVIDER_TOTP:
                    ok = await services.providers[provider].verify(request, user, code, challenge=record, conn=conn)
                elif provider == PROVIDER_EMAIL:
                    ok = await services.providers[provider].verify(request, user, code, challenge=record)
                else:
                    ok = provider == PROVIDER_BACKUP
                if not ok:
                    await self._failed(token)
                consumed = await services.store.consume(token)
                if consumed is None or consumed != record:
                    raise VerifyRefused("invalid_challenge", 401)
                device = await self._maybe_trust_device(conn, evaluation, remember_device, device_label)
                await services.security.commit_before_session(conn)
                try:
                    session = await issue(user, {"mfa": True, "amr": [AMR_PASSWORD, AMR_BY_PROVIDER[provider]]})
                except FailedAuth as err:
                    raise VerifyRefused("account_disabled", err.status) from err
        except (VerifyRefused, web.HTTPException):
            raise
        except Exception as err:  # pylint: disable=W0718 -- security dependencies fail closed.
            logger.error("MFA gate: verify refused, dependency failure: %s", type(err).__name__)
            raise VerifyRefused("mfa_unavailable", 503) from err
        return GateResult(session=session, device=device)

    async def _revalidate(self, conn: Any, token: str, record: MfaChallenge) -> tuple[Any, MfaEvaluation]:
        """Read a fresh user and evaluation, discarding a challenge on any context drift."""
        try:
            user = await self._services.backend._idp.user_from_id(record.user_id, conn=conn)  # pylint: disable=W0212
        except UserNotFound:
            await self._services.store.discard(token)
            raise VerifyRefused("invalid_challenge", 401) from None
        try:
            evaluation = await self._services.evaluate(user, conn=conn)
        except MfaSignal as err:
            await self._services.store.discard(token)
            extra = {key: value for key, value in err.payload().items() if key != "error"}
            raise VerifyRefused(getattr(err, "code", "mfa_refused"), err.status, **extra) from err
        if evaluation.security_version != record.security_version or not secrets.compare_digest(
            evaluation.context_digest, record.context_digest
        ):
            await self._services.store.discard(token)
            raise VerifyRefused("stale_challenge", 401)
        return user, evaluation

    async def _failed(self, token: str) -> NoReturn:
        """Count an invalid attempt and refuse it."""
        remaining = await self._services.store.register_failure(token)
        if remaining < 0:
            raise VerifyRefused("invalid_challenge", 401)
        raise VerifyRefused("invalid_code", 401, attempts_remaining=remaining)

    async def _trusted_device(self, request: web.Request, conn: Any, evaluation: MfaEvaluation) -> Optional[str]:
        """Rotate a trusted-device cookie on the lock connection."""
        raw = request.cookies.get(TRUSTED_COOKIE)
        if not raw or not may_offer_trusted_device(
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        rotated = await self._services.trusted_devices.consume_and_rotate(raw, evaluation.user_id, conn=conn)
        if rotated is None or rotated[0] != evaluation.user_id:
            return None
        return rotated[1]

    async def _maybe_trust_device(
        self, conn: Any, evaluation: MfaEvaluation, remember_device: bool, device_label: str
    ) -> Optional[dict]:
        """Issue a trusted device only when requested and policy permits it."""
        if not remember_device or not may_offer_trusted_device(
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        days = evaluation.policy.remember_days
        raw = await self._services.trusted_devices.issue(
            evaluation.user_id, days, str(device_label or "")[:128], conn=conn
        )
        return {"token": raw, "max_age": days * 86400}
