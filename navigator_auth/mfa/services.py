"""MFA service container (FEAT-106, spec §3 Module 9, contract D12)."""

import logging
from collections.abc import Mapping
from typing import Any, Optional

import redis.asyncio as aioredis

from navigator_auth import conf as auth_conf
from navigator_auth.mfa.abstract import AbstractOTPProvider
from navigator_auth.mfa.backup_codes import BackupCodeProvider, BackupCodeStore
from navigator_auth.mfa.email_otp import EmailOTPProvider
from navigator_auth.mfa.limiter import StrictRateLimiter
from navigator_auth.mfa.migrations import setup_mfa_tables
from navigator_auth.mfa.policy import MfaPolicyResolver
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.state import MfaStateMachine, _user_id
from navigator_auth.mfa.store import MfaChallengeStore
from navigator_auth.mfa.totp import TOTPProvider
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.mfa.types import MfaEvaluation, PROVIDER_BACKUP, PROVIDER_EMAIL, PROVIDER_TOTP

logger = logging.getLogger("navigator.auth.mfa")

MFA_APP_KEY = "navigator_auth.mfa"


class MfaServices:
    """Every MFA component, built once per process."""

    def __init__(
        self,
        *,
        backend: Any,
        available: bool,
        redis_pool: Any = None,
        db_pool: Any = None,
        secret: bytes = b"",
        store: Optional[MfaChallengeStore] = None,
        user_limiter: Optional[StrictRateLimiter] = None,
        ip_limiter: Optional[StrictRateLimiter] = None,
        security: Optional[MfaSecurity] = None,
        trusted_devices: Optional[TrustedDeviceStore] = None,
        backup_codes: Optional[BackupCodeStore] = None,
        resolver: Optional[MfaPolicyResolver] = None,
        state: Optional[MfaStateMachine] = None,
        providers: Optional[dict[str, AbstractOTPProvider]] = None,
    ) -> None:
        self.backend = backend
        self.available = available
        self.redis_pool = redis_pool
        self.db_pool = db_pool
        self.secret = secret
        self.store = store
        self.user_limiter = user_limiter
        self.ip_limiter = ip_limiter
        self.security = security
        self.trusted_devices = trusted_devices
        self.backup_codes = backup_codes
        self.resolver = resolver
        self.state = state
        self.providers = providers or {}

    async def evaluate(self, user: Mapping, *, conn: Any = None) -> MfaEvaluation:
        """Return one consistent snapshot of policy, state, and security context."""
        if conn is None:
            async with await self.db_pool.acquire() as own:
                return await self._evaluate(user, own)
        return await self._evaluate(user, conn)

    async def _evaluate(self, user: Mapping, conn: Any) -> MfaEvaluation:
        user_id = int(_user_id(user))
        memberships = await self.resolver.memberships(user_id, conn=conn)
        policy = await self.resolver.effective(user, conn=conn, memberships=memberships)
        state = await self.state.state_of(user, policy, conn=conn)
        totp = await self.state.totp_confirmed(user_id, conn=conn)
        strong = await self.state.has_strong_factor(user, conn=conn)
        providers, preferred = await self.state.available_providers(user, policy, conn=conn)
        version = await self.security.current_version(conn, user_id)
        digest = self.security.context_digest(
            user=user,
            memberships=memberships,
            policy=policy,
            state=state,
            has_strong_factor=strong,
        )
        return MfaEvaluation(
            user_id=user_id,
            policy=policy,
            memberships=tuple(memberships),
            state=state,
            has_strong_factor=strong,
            totp_confirmed=totp,
            providers=tuple(providers),
            preferred=preferred,
            security_version=version,
            context_digest=digest,
        )

    async def close(self) -> None:
        """Disconnect the Redis pool."""
        if self.redis_pool is not None:
            await self.redis_pool.disconnect()


class MfaServicesSlot:
    """Mutable holder registered on the app before it is frozen."""

    def __init__(self, services: Optional[MfaServices] = None) -> None:
        self.services = services


def get_mfa_services(app: Any) -> Optional[MfaServices]:
    """Return the app's MFA services, if configured."""
    slot = app.get(MFA_APP_KEY) if app is not None else None
    return slot.services if isinstance(slot, MfaServicesSlot) else None


async def build_mfa_services(app: Any, backend: Any) -> MfaServices:
    """Build every MFA component without allowing startup to fail."""
    secret = auth_conf.AUTH_OTP_SECRET
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not secret:
        logger.critical("MFA: AUTH_BASIC_2FA_ENABLED but AUTH_OTP_SECRET is unset; BasicAuth logins will be refused")
        return MfaServices(backend=backend, available=False)
    db_pool = app.get("authdb")
    if db_pool is None:
        logger.critical("MFA: no 'authdb' pool; BasicAuth logins will be refused")
        return MfaServices(backend=backend, available=False)
    try:
        available = await setup_mfa_tables(db_pool)
        redis_pool = aioredis.ConnectionPool.from_url(auth_conf.REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
        store = MfaChallengeStore(redis_pool, secret)
        backup_codes = BackupCodeStore(db_pool, secret)
        user_limiter = StrictRateLimiter(redis_pool, auth_conf.AUTH_OTP_RATE_USER, "user")
        ip_limiter = StrictRateLimiter(redis_pool, auth_conf.AUTH_OTP_RATE_IP, "ip")
        security = MfaSecurity(db_pool, secret)
        trusted_devices = TrustedDeviceStore(db_pool)
        resolver = MfaPolicyResolver(db_pool)
        state = MfaStateMachine(db_pool, backup_codes=backup_codes)
        providers = {
            PROVIDER_TOTP: TOTPProvider(app=app, db_pool=db_pool, store=store),
            PROVIDER_EMAIL: EmailOTPProvider(secret=secret),
            PROVIDER_BACKUP: BackupCodeProvider(backup_codes),
        }
    except Exception as err:  # pylint: disable=W0703
        logger.critical("MFA: could not build services (%s); BasicAuth logins will be refused", type(err).__name__)
        return MfaServices(backend=backend, available=False)
    if not available:
        logger.critical("MFA: tables unavailable; BasicAuth logins will be refused until they exist")
    return MfaServices(
        backend=backend,
        available=available,
        redis_pool=redis_pool,
        db_pool=db_pool,
        secret=secret,
        store=store,
        user_limiter=user_limiter,
        ip_limiter=ip_limiter,
        security=security,
        trusted_devices=trusted_devices,
        backup_codes=backup_codes,
        resolver=resolver,
        state=state,
        providers=providers,
    )
