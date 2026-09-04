"""PasswordRecoveryHandler — the three-step recovery endpoints (FEAT-098,
Module 6).

Assembles the store (M3), policy (M2), limiter (M4) and revoker (M5) into
the three-step HTTP flow described in the spec's Component Diagram, and is
the integration point that replaces the broken pre-FEAT-098
``handlers/recovery.py`` (renamed ``recovery_legacy.py`` by TASK-062,
deleted by this task).

Everything security-relevant that is *not* owned by another module lives
here: the uniform step-1 response (no account enumeration, D9), latency
padding, and keeping the raw token out of every HTTP response and log
line.
"""
import asyncio
import importlib
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from asyncdb.exceptions import NoDataFound
from navigator.views import BaseView

from navigator_auth.conf import (
    AUTH_RECOVERY_SECRET,
    AUTH_RECOVERY_TTL,
    AUTH_RECOVERY_CONFIRM_TTL,
    AUTH_RECOVERY_CALLBACK,
    AUTH_RECOVERY_URL_TEMPLATE,
    AUTH_RECOVERY_RATE_EMAIL,
    AUTH_RECOVERY_RATE_IP,
    AUTH_RECOVERY_PWD_MIN_LENGTH,
    AUTH_RECOVERY_PWD_REQUIRE_LETTER,
    AUTH_RECOVERY_PWD_REQUIRE_DIGIT,
    REDIS_AUTH_URL,
)
from navigator_auth.models import User
from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.handlers.recovery.limiter import RateLimiter
from navigator_auth.handlers.recovery.policy import PasswordPolicy
from navigator_auth.handlers.recovery.revoke import SessionRevoker
from navigator_auth.handlers.recovery.store import RecoveryTokenStore, _hash_token
from navigator_auth.handlers.recovery.types import NotificationPayload

logger = logging.getLogger("navigator.recovery")

# Registered route names (handlers/__init__.py) that mean "step 3, confirm"
# rather than "step 1, request" when a POST lands on post(). Route names,
# not path strings, so the dispatch doesn't need to know the literal path
# of every alias.
_CONFIRM_ROUTE_NAMES = frozenset({
    "api_password_recovery_confirm",
    "api_reset_password",
})

# Minimum wall-clock time step 1 takes to respond, regardless of whether the
# address is known. A real lookup hits Postgres; a miss may not — without
# this floor the latency delta alone reveals account existence (D9).
_STEP1_LATENCY_FLOOR = 0.25  # seconds

_GENERIC_STEP1_BODY = {
    "message": "If that email address is registered, recovery instructions "
    "have been sent."
}


async def _find_user_by_email(request, email: str) -> Optional[User]:
    """Look up an active user by ``email``, falling back to ``alt_email``.

    ``idp.get_user()`` cannot be reused here — it only searches
    ``username_attribute``. ``User.email`` has no unique constraint: if a
    query is ambiguous (more than one row), refuse to guess and take the
    generic not-found path, logging a warning.

    Uses a raw, parameterized SQL SELECT (only ``user_id``) rather than
    ``User.filter()`` — the latter hydrates every returned row into a
    ``User(**row)`` and breaks on any DB column the model does not
    declare (``asyncdb``'s ``get()`` filters columns to the model's known
    fields first; ``filter()`` does not). Once a single unambiguous match
    is found, ``User.get(user_id=...)`` — which *does* filter columns —
    builds the real model instance.
    """
    db = request.app["authdb"]
    async with await db.acquire() as conn:
        User.Meta.connection = conn
        rows, err = await conn.query(
            "SELECT user_id FROM auth.users "
            "WHERE (LOWER(email) = $1 OR LOWER(alt_email) = $1) "
            "AND is_active = true",
            email,
        )
        if err:
            logger.error("PasswordRecovery: email lookup failed: %s", err)
            return None
        rows = rows or []
        if len(rows) > 1:
            logger.warning(
                "PasswordRecovery: multiple users match email=%r; refusing to guess",
                email,
            )
            return None
        if not rows:
            return None
        row = rows[0]
        user_id = row["user_id"] if isinstance(row, dict) else row[0]
        try:
            return await User.get(user_id=user_id)
        except NoDataFound:
            return None


class PasswordRecoveryHandler(BaseView):
    """Three-step, HMAC-signed password recovery flow.

    A single ``web.View``-based class registered at all five paths (three
    canonical + two legacy aliases, see ``handlers/__init__.py``);
    ``post()`` disambiguates step 1 (request) from step 3 (confirm) by the
    matched route's *name*, not its literal path, so the legacy aliases
    dispatch identically to their canonical counterparts.
    """

    # Class-level, lazily-created, shared across every request for the
    # life of the process — one ConnectionPool, never redis.from_url()
    # per request (the mistake in the module this replaces). BaseView
    # instances are created fresh per request by aiohttp's add_view(), so
    # there is no per-backend on_startup hook to use here; this achieves
    # the same "created once" property.
    _pool: Optional[aioredis.ConnectionPool] = None
    _store: Optional[RecoveryTokenStore] = None
    _policy: Optional[PasswordPolicy] = None
    _email_limiter: Optional[RateLimiter] = None
    _ip_limiter: Optional[RateLimiter] = None
    _revoker: Optional[SessionRevoker] = None

    @classmethod
    def _ensure_resources(cls) -> None:
        if cls._pool is not None:
            return
        cls._pool = aioredis.ConnectionPool.from_url(
            REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        cls._store = RecoveryTokenStore(cls._pool, secret=AUTH_RECOVERY_SECRET)
        cls._policy = PasswordPolicy(
            min_length=AUTH_RECOVERY_PWD_MIN_LENGTH,
            require_letter=AUTH_RECOVERY_PWD_REQUIRE_LETTER,
            require_digit=AUTH_RECOVERY_PWD_REQUIRE_DIGIT,
        )
        cls._email_limiter = RateLimiter(cls._pool, AUTH_RECOVERY_RATE_EMAIL, "email")
        cls._ip_limiter = RateLimiter(cls._pool, AUTH_RECOVERY_RATE_IP, "ip")
        cls._revoker = SessionRevoker(cls._pool)

    def __init__(self, request, *args, **kwargs):
        super().__init__(request, *args, **kwargs)
        self._ensure_resources()

    # --- HTTP-verb dispatch -------------------------------------------
    async def post(self):
        route_name = getattr(self.request.match_info.route, "name", None)
        if route_name in _CONFIRM_ROUTE_NAMES:
            return await self._step3_confirm()
        return await self._step1_request()

    async def get(self):
        return await self._step2_validate()

    # --- Step 1: POST /api/v1/password-recovery -----------------------
    async def _step1_request(self):
        start = time.monotonic()
        try:
            data = await self.json_data() or {}
        except Exception:  # pylint: disable=W0703
            data = {}
        email = data.get("email") if isinstance(data, dict) else None

        if email:
            email_norm = str(email).strip().lower()
            client_ip = self.request.remote or "unknown"
            allowed = await self._email_limiter.check(email_norm)
            if allowed:
                allowed = await self._ip_limiter.check(client_ip)
            if allowed:
                await self._process_recovery_request(email_norm)
            else:
                # Rate-limit rejection still returns the generic body — a
                # distinct 429 would itself tell an attacker the address is
                # being tracked (D9 outweighs the RFC-flavoured 429 hint in
                # the spec's Component Diagram; see Completion Note).
                logger.warning(
                    "PasswordRecovery: rate limit exceeded for step1 request"
                )
        # else: no email in the body -> treated exactly like "not found",
        # no DB/Redis work, so its latency profile matches a real miss.

        await self._pad_latency(start)
        return self.json_response(response=_GENERIC_STEP1_BODY, status=200)

    async def _process_recovery_request(self, email: str) -> None:
        user = await _find_user_by_email(self.request, email)
        if user is None:
            await self._invoke_callback(
                NotificationPayload(
                    email=email,
                    display_name="",
                    username="",
                    token="",
                    url="",
                    expires_at=self._far_future(),
                    found=False,
                )
            )
            return
        token, payload = await self._store.issue_recovery(user)
        url = self._build_url(token)
        display_name = getattr(user, "display_name", None) or user.username
        await self._invoke_callback(
            NotificationPayload(
                email=email,
                display_name=display_name,
                username=user.username,
                token=token,
                url=url,
                expires_at=self._recovery_expiry(payload.issued_at),
                found=True,
            )
        )

    # --- Step 2: GET /api/v1/password-recovery/{token} ----------------
    async def _step2_validate(self):
        token = self.request.match_info.get("token")
        if not token:
            return self.error(reason="Invalid recovery link", status=400)
        recovery_payload = await self._store.validate_recovery(token)
        if recovery_payload is None:
            # Same message for miss / expired / bad-signature — no need to
            # distinguish them for the caller.
            return self.error(reason="Invalid or expired recovery link", status=400)
        try:
            confirm_token, _confirmation = await self._store.issue_confirmation(token)
        except LookupError:
            return self.error(reason="Invalid or expired recovery link", status=400)
        return self.json_response(
            response={
                "token": confirm_token,
                "expires_in": AUTH_RECOVERY_CONFIRM_TTL,
                "username": recovery_payload.username,
            },
            status=200,
        )

    # --- Step 3: POST /api/v1/password-recovery/confirm ---------------
    async def _step3_confirm(self):
        try:
            data = await self.json_data() or {}
        except Exception:  # pylint: disable=W0703
            data = {}
        password = data.get("password") if isinstance(data, dict) else None
        confirm_password = data.get("confirm_password") if isinstance(data, dict) else None
        token = data.get("token") if isinstance(data, dict) else None

        if not token:
            return self.error(reason="Missing confirmation token", status=400)
        if not password or password != confirm_password:
            return self.error(reason="Passwords do not match", status=400)

        # Non-destructive peek first (D4/D5 for the read side): a policy
        # failure below must leave BOTH tokens usable, so we must not
        # GETDEL the confirmation before we know the password is valid.
        confirmation = await self._store.peek_confirmation(token)
        if confirmation is None:
            return self.error(reason="Invalid or expired confirmation token", status=400)

        # Lookup, policy check and password write all share ONE acquired
        # connection (matching handlers/users/session.py's
        # password_change/password_reset) — releasing the connection
        # between the lookup and the later .update() left a stale
        # Model.Meta.connection reference and, under load, starved the
        # pool badly enough to hang the whole process.
        db = self.request.app["authdb"]
        async with await db.acquire() as conn:
            User.Meta.connection = conn
            try:
                user = await User.get(user_id=confirmation.user_id)
            except NoDataFound:
                return self.error(
                    reason="Invalid or expired confirmation token", status=400
                )

            current_hash = getattr(user, "password", None)
            violations = self._policy.validate(password, current_hash=current_hash)
            if violations:
                return self.json_response(
                    response={
                        "violations": [
                            {"rule": v.rule, "message": v.message} for v in violations
                        ]
                    },
                    status=422,
                )

            # Policy passed: now consume (single-use GETDEL). If this races
            # with a concurrent step-3 call, the second one lands here.
            consumed = await self._store.consume_confirmation(token)
            if consumed is None:
                return self.error(
                    reason="Invalid or expired confirmation token", status=400
                )

            user.password = set_basic_password(password)
            # D17 — self-service reset is NOT the same as a superuser-driven
            # password_reset (which sets is_new=True). Do not "harmonise"
            # them.
            user.is_new = False
            await user.update()

        await self._store.drop_pair(consumed.recovery_key, _hash_token(token))

        revoked = await self._revoker.revoke_user(self.request, user)
        logger.info(
            "PasswordRecovery: revoked %d session/jti record(s) for user_id=%s",
            revoked, user.user_id,
        )

        # D15 — no auto-login: no token/refresh_token in the response.
        return self.json_response(
            response={
                "action": "Password was changed successfully",
                "status": "OK",
            },
            status=202,
        )

    # --- Helpers --------------------------------------------------------
    async def _pad_latency(self, start: float) -> None:
        elapsed = time.monotonic() - start
        remaining = _STEP1_LATENCY_FLOOR - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

    def _build_url(self, token: str) -> str:
        if not AUTH_RECOVERY_URL_TEMPLATE:
            logger.error(
                "PasswordRecovery: AUTH_RECOVERY_URL_TEMPLATE is not configured"
            )
            return ""
        try:
            return AUTH_RECOVERY_URL_TEMPLATE.format(token=token)
        except (KeyError, IndexError, ValueError) as ex:
            logger.error(
                "PasswordRecovery: invalid AUTH_RECOVERY_URL_TEMPLATE: %s", ex
            )
            return ""

    def _recovery_expiry(self, issued_at: float) -> datetime:
        return datetime.fromtimestamp(issued_at + AUTH_RECOVERY_TTL, tz=timezone.utc)

    def _far_future(self) -> datetime:
        """Placeholder expires_at for the found=False notification, which
        carries no real token/TTL."""
        return datetime.now(timezone.utc)

    async def _invoke_callback(self, payload: NotificationPayload) -> None:
        """Hand off to AUTH_RECOVERY_CALLBACK. Never raises, never logs the
        raw token — only the NotificationPayload's own (redacting) repr."""
        if not AUTH_RECOVERY_CALLBACK:
            logger.warning(
                "PasswordRecovery: no AUTH_RECOVERY_CALLBACK configured; "
                "dropping notification"
            )
            return
        try:
            pkg, name = AUTH_RECOVERY_CALLBACK.rsplit(".", 1)
            mod = importlib.import_module(pkg)
            callback = getattr(mod, name)
            if asyncio.iscoroutinefunction(callback):
                await callback(payload)
            else:
                callback(payload)
        except Exception as ex:  # pylint: disable=W0703
            # Failure is logged, never changes the response and never
            # includes the payload itself (which would log the token).
            logger.error("PasswordRecovery: notification callback failed: %s", ex)
