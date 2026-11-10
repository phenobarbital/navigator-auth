# TASK-138: MfaServices container + `BasicAuth.on_startup` / `authenticate` second-factor hook

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-135, TASK-136, TASK-137 (transitively TASK-129…TASK-134)
**Assigned-to**: unassigned

> **NOT delegation-eligible** (spec §3 delegation table, §7 R2). This task edits
> the single most security-sensitive method in the package. A wrong edit does
> not fail a test — it silently makes 2FA bypassable. Thinking model only.

---

## Context

Implements **spec §3 Module 9** — the single integration point between the
second factor and `BasicAuth`. Everything before this task built parts that
cannot mint a session (stores, providers, policy, state). This task wires them
into `BasicAuth.authenticate()` so that a valid password either proceeds
exactly as today or ends in an `MfaSignal` — **without creating anything that
would have to be retracted** (spec §2 Overview, Option A).

It also creates `navigator_auth/mfa/services.py`, the process-lifetime
container that owns every MFA component (D12), and its `evaluate()` method:
the **one consistent snapshot** (`MfaEvaluation`) used both to issue a
challenge here and to re-validate it in TASK-140's verify.

### The correctness argument (read before editing)

`authenticate()` has exactly three call sites in `auth.py` (`:369`, `:380`,
`:487`). Two naive ways to signal "a factor is owed" are both fatal
(spec §7 R2):

1. **Returning a challenge envelope** — `api_login` does `if userdata: break`
   (`auth.py:488`) then `JSONResponse(userdata)` + `load_session(...)`
   (`:502-503`): the envelope becomes a real session. First factor alone
   authenticates.
2. **Raising a plain `AuthException`** (or returning `False`) — the loop's
   `except (AuthException, UserNotFound, InvalidAuth, FailedAuth): continue`
   (`:490-491`) swallows it, and a falsy return also continues: the **next
   backend** gets the same credentials and may mint a session with no factor.

Therefore **every terminal outcome of the hook is an `MfaSignal`** (D1):
`MFARequired` (challenge issued) or `MFARefused` (fail closed —
`strong_factor_required` 403, `no_factor_available` 403, `mfa_unavailable` 503).
TASK-139 makes all three call sites catch `MfaSignal` before their generic
handlers. Inside the hook: **no `return False`, no plain `AuthException`, no
swallowed error** once a factor may be owed. The only non-signal outcomes are
`None` ("no factor owed, open the session exactly as today") and the login dict
of a session opened on a valid trusted device.

### Why the hook is in `authenticate()` and not `open_session()`

`TokenExchangeAuth` (`backends/exchange.py:31`, override at `:125`) and
`PasskeyAuth` (`backends/passkey.py:63`, override at `:397`) override
`authenticate()` and call `open_session()` directly. Hooking `open_session()`
would challenge machine-to-machine exchanges and stack an OTP on a passkey.
Both classes **inherit** `on_startup()` and `configure()` unchanged, which is
why ownership of the services is decided by
`type(self).authenticate is BasicAuth.authenticate` (D12) — zero edits to
those classes, and AC10/AC11 hold by construction.

---

## Scope

- Create `navigator_auth/mfa/services.py`: `MFA_APP_KEY`, `MfaServicesSlot`,
  `MfaServices` (with `evaluate()` and `close()`), `get_mfa_services()`,
  `build_mfa_services()` (never raises).
- Modify `navigator_auth/backends/basic.py`:
  - `configure()` — register an empty `MfaServicesSlot` on the app (pre-freeze).
  - `on_startup()` — fill the slot via `build_mfa_services()` (owner only).
  - `on_cleanup()` — close owned services.
  - `authenticate()` — call the new `_second_factor()` hook after
    `validate_user()`, before the unchanged `open_session()` call.
  - New private methods `_second_factor()` and `_trusted_device()`.
- Write `tests/test_mfa_basic_auth_hook.py`.

**NOT in scope**:
- `auth.py` call sites and `finalize_login()` — TASK-139 (this task's signals
  are only *safe* once TASK-139 lands; do not ship one without the other).
- The verify / resend HTTP endpoints — TASK-140.
- Enrollment / disenrollment / admin endpoints — TASK-141/142.
- Any edit to `TokenExchangeAuth` or `PasskeyAuth` (they must stay untouched;
  D12 makes edits unnecessary).
- `open_session()` itself — signature and body unchanged (spec §2 Integration
  Points: "uses (unchanged)").

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/services.py` | CREATE | `MfaServices`, slot, builder, `evaluate()` |
| `navigator_auth/backends/basic.py` | MODIFY | configure / on_startup / on_cleanup / authenticate hook |
| `tests/test_mfa_basic_auth_hook.py` | CREATE | Hook unit tests (no live server) |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11). Symbols marked *(TASK-NNN)*
> are created by a dependency — confirm they exist (`grep -n`) before starting.

### Verified Imports

```python
# --- existing, verified ---
from aiohttp import web                                     # basic.py:10
from .. import conf as auth_conf                            # pattern verified: backends/passkey.py:18
from .abstract import BaseAuthBackend, user_is_active       # basic.py:17 (user_is_active: abstract.py:43)
from ..exceptions import AuthException, FailedAuth, UserNotFound, InvalidAuth   # basic.py:20-25
import redis.asyncio as aioredis                            # used package-wide (passkey.py:15)
# --- created by dependencies ---
from ..exceptions import MfaSignal, MFARequired, MFARefused                       # (TASK-129)
from ..mfa.types import (MfaState, MfaEvaluation, AMR_PASSWORD, AMR_TRUSTED_DEVICE,
                         MFA_DEVICE_TOKEN_KEY, PROVIDER_EMAIL, PROVIDER_TOTP,
                         PROVIDER_BACKUP, TRUSTED_COOKIE)                         # (TASK-129)
from navigator_auth.mfa.abstract import AbstractOTPProvider                       # (TASK-129)
from navigator_auth.mfa.migrations import setup_mfa_tables                        # (TASK-130)
from navigator_auth.mfa.store import MfaChallengeStore                            # (TASK-131)
from navigator_auth.mfa.limiter import StrictRateLimiter                          # (TASK-131)
from navigator_auth.mfa.security import MfaSecurity                               # (TASK-132)
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore                 # (TASK-133)
from navigator_auth.mfa.backup_codes import BackupCodeStore, BackupCodeProvider   # (TASK-134)
from navigator_auth.mfa.policy import MfaPolicyResolver                           # (TASK-135)
from navigator_auth.mfa.state import MfaStateMachine, _user_id                    # (TASK-135; _user_id shared per contract D26)
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device                 # (TASK-133; the single AC17 predicate, D27)
from navigator_auth.mfa.totp import TOTPProvider                                  # (TASK-136)
from navigator_auth.mfa.email_otp import EmailOTPProvider                         # (TASK-137)
# --- created by this task ---
from ..mfa.services import MFA_APP_KEY, MfaServicesSlot, build_mfa_services, get_mfa_services
```

Settings read **at call time** through `auth_conf` (so tests can monkeypatch):
`AUTH_BASIC_2FA_ENABLED`, `AUTH_OTP_SECRET` (bytes or None), `AUTH_OTP_CHALLENGE_TTL`,
`AUTH_OTP_RATE_USER`, `AUTH_OTP_RATE_IP` *(TASK-129)*; `REDIS_AUTH_URL`
(verified `conf.py:297`).

### Existing signatures (verified)

```python
# navigator_auth/backends/basic.py
class BasicAuth(BaseAuthBackend):                                     # :44
    def configure(self, app):                                         # :53  (runs inside AuthHandler.setup(), BEFORE app freeze — auth.py:719)
        ...
        app[AUTH_EXCLUDE_LIST_KEY].append(check_credentials)          # :62
        super().configure(app)                                        # :63
    async def on_startup(self, app: web.Application):                 # :65  (runs AFTER app freeze — auth.py:181-183)
        ...
            self.get_successful_callbacks()                           # :75  (last line of on_startup)
    async def on_cleanup(self, app: web.Application):                 # :77
        ...
                self.logger.warning(f"BasicAuth: error closing access_token_storage Redis: {ex}")   # :84 (last line)
    async def validate_user(self, login: str = None, password: str = None): ...   # :86
    _JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at", "mfa", "amr")       # :153
    async def open_session(self, request, user: dict, extra: Optional[dict] = None,
                           expiration: Optional[int] = None) -> dict: ...                       # :170
        # returns {"token": token, **userdata}  (:294) — a FRESH dict; adding keys to it never touches the session
        # extra is merged into userdata AND userdata[AUTH_SESSION_OBJECT] (:215-217) — i.e. PERSISTED. Never put secrets in extra (D14).
    async def authenticate(self, request):                            # :296
        ...
                user = await self.validate_user(login=user, password=pwd)    # :307
            ...
            try:                                                      # :314
                return await self.open_session(request, user)         # :315
            except (FailedAuth, InvalidAuth):                         # :316
                raise
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(f"BasicAuth: Authentication Error: {err}")
                return False                                          # :320
# backends/exchange.py:31  class TokenExchangeAuth(BasicAuth) — overrides authenticate at :125; inherits on_startup/configure
# backends/passkey.py:63   class PasskeyAuth(BasicAuth)       — overrides authenticate at :397; on_startup calls super() at :95
```

`user` returned by `validate_user()` is the `AUTH_USER_VIEW` model instance from
`IdentityProvider.get_user()` (`backends/idp/__init__.py:146`); it supports
`user[...]` indexing (used at `basic.py:99,206-207`). Read the id with
`user[self.userid_attribute]` exactly as `open_session` does.

### aiohttp frozen-app constraint (verified — why the slot exists)

`aiohttp 3.14.3` `Application.__setitem__` calls `_check_frozen()`
(`.venv/.../aiohttp/web_app.py:201-216`), which emits
`DeprecationWarning("Changing state of started or joined application is deprecated")`
once the app is frozen. `on_startup` runs after freeze, and `pyproject.toml`
sets `filterwarnings = ["error", …]`. So `on_startup` **must not** do
`app[MFA_APP_KEY] = …`. Instead `configure()` (pre-freeze) registers an empty
`MfaServicesSlot`, and `on_startup` fills `slot.services` (attribute mutation,
no app state change). `get_mfa_services(app)` reads through the slot — its
signature (`-> Optional[MfaServices]`) is unchanged for every other task.

### Dependency contracts this task consumes (from the FEAT-106 contract)

```python
# TASK-129
class MFARequired(MfaSignal): __init__(challenge, providers, preferred, expires_in, status=401); payload() -> dict
class MFARefused(MfaSignal):  __init__(code, message=None, status=403); payload() -> dict
class MfaEvaluation(MfaModel): user_id, policy: TenantMfaPolicy, memberships: tuple[int,...], state: MfaState,
                               has_strong_factor, totp_confirmed, providers: tuple[str,...], preferred: Optional[str],
                               security_version: int, context_digest: str
# TASK-130
async def setup_mfa_tables(db_pool) -> bool          # never raises
# TASK-131
MfaChallengeStore(pool, secret, ttl=AUTH_OTP_CHALLENGE_TTL, max_attempts=AUTH_OTP_MAX_ATTEMPTS)
    async issue(user, providers, preferred, *, security_version, context_digest, email_code_hash=None) -> tuple[str, MfaChallenge]
StrictRateLimiter(pool, spec, prefix)
# TASK-132
MfaSecurity(db_pool, secret); async current_version(conn, user_id) -> int
    def context_digest(*, user, memberships, policy, state, has_strong_factor) -> str
# TASK-133
TrustedDeviceStore(db_pool); async consume_and_rotate(raw_token, user_id) -> Optional[tuple[int, str]]
def may_offer_trusted_device(*, has_strong_factor: bool, remember_days: int) -> bool   # D27 — the ONLY AC17 rule; never re-implement it
# TASK-134
BackupCodeStore(db_pool, secret); BackupCodeProvider(store)
# TASK-135
MfaPolicyResolver(db_pool); async memberships(user_id, *, conn=None); async effective(user, *, conn=None, memberships=None)
def _user_id(user) / def _field(user, name, default=None)   # D26 — shared dict-or-Model accessors in mfa/state.py
MfaStateMachine(db_pool, backup_codes=None); async state_of(user, policy, *, conn=None)  # may raise MFARefused(strong_factor_required)
    async totp_confirmed(user_id, *, conn=None); async has_strong_factor(user, *, conn=None)
    async available_providers(user, policy, *, conn=None) -> tuple[list[str], Optional[str]]
# TASK-136
TOTPProvider(*, app, db_pool, store, issuer=AUTH_TOTP_ISSUER, clock=time.time)
# TASK-137
EmailOTPProvider(*, secret: bytes, callback=AUTH_OTP_EMAIL_CALLBACK, code_length=…, ttl=…); async challenge(request, user) -> {"code_hash": str}   # keyed hash, D30
```

### Does NOT Exist (do not reference)

- ~~`app[MFA_APP_KEY] = <MfaServices>` set in `on_startup`~~ — forbidden (frozen app, see above). The key holds an `MfaServicesSlot`.
- ~~`BasicAuth._mfa_capable` / `_mfa_owner` class flags~~ — not used; D12 decides ownership from the `authenticate` identity.
- ~~an MFA attribute on `TokenExchangeAuth` / `PasskeyAuth`~~ — do not edit those classes.
- ~~`abac.context._resolve_tenant()` in the hook~~ — forbidden (§7 R14); membership comes from `MfaPolicyResolver.memberships(user_id)` (D7).
- ~~`load_vault_for_session()` for the seed~~ — forbidden (§7 R12); TOTP reads its seed itself (TASK-136).
- ~~`MfaChallengeStore.ttl` attribute~~ — not part of the contract; use `auth_conf.AUTH_OTP_CHALLENGE_TTL` for `expires_in` (the builder constructs the store with that default).
- ~~`UserDevices` (models.py:143)~~ — not the trusted-device store.
- ~~a local `_user_id` / `_field` helper in `services.py`~~ — import the shared ones from `mfa/state.py` (D26).
- ~~`conn.execute(...)` anywhere in `services.py`~~ — asyncdb's `execute()` swallows every exception and returns
  from `finally` (verified `.venv/.../asyncdb/drivers/pg.py:937-972`, contract D25), so a fail-closed read/write
  through it would silently "succeed". This task issues no SQL itself; keep it that way.

---

## Implementation Blueprint

### `navigator_auth/mfa/services.py` — CREATE (block 1 of 2: container + slot)

```python
"""MFA service container (FEAT-106, spec §3 Module 9, contract D12).

Process-lifetime objects owned by the BasicAuth backend that actually runs
``BasicAuth.authenticate``. Holds NO policy: the tenant policy is read on every
login (spec M7, AC22). Lives on the app inside an ``MfaServicesSlot`` registered
before the app is frozen.

NOTE (contract D5): this module must never name the session-minting methods of
the backend; it only stores a reference to it.
"""
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
from navigator_auth.mfa.types import (
    MfaEvaluation, PROVIDER_BACKUP, PROVIDER_EMAIL, PROVIDER_TOTP,
)

logger = logging.getLogger("navigator.auth.mfa")

MFA_APP_KEY = "navigator_auth.mfa"


class MfaServices:
    """Every MFA component, built once per process. ``available`` False ⇒ refuse logins (D13)."""

    def __init__(
        self, *, backend: Any, available: bool, redis_pool: Any = None, db_pool: Any = None,
        secret: bytes = b"", store: Optional[MfaChallengeStore] = None,
        user_limiter: Optional[StrictRateLimiter] = None, ip_limiter: Optional[StrictRateLimiter] = None,
        security: Optional[MfaSecurity] = None, trusted_devices: Optional[TrustedDeviceStore] = None,
        backup_codes: Optional[BackupCodeStore] = None, resolver: Optional[MfaPolicyResolver] = None,
        state: Optional[MfaStateMachine] = None, providers: Optional[dict[str, AbstractOTPProvider]] = None,
    ) -> None:
        # FILL IN: assign every argument to a same-named attribute; providers defaults to {} —
        # bounded by contract §3 TASK-138 attribute list (other tasks read these names).

    async def evaluate(self, user: Mapping, *, conn: Any = None) -> MfaEvaluation:
        """One consistent snapshot of policy, factor state and security context.

        Used to ISSUE a challenge (hook, conn=None ⇒ one pooled connection for the
        whole snapshot) and to RE-VALIDATE it under the user lock (TASK-140,
        conn = the lock's transaction connection).

        Raises:
            MFARefused: ``strong_factor_required`` from ``state_of`` (AC33).
            Exception: any storage failure — callers translate it to ``mfa_unavailable``.
        """
        if conn is None:
            async with await self.db_pool.acquire() as own:
                return await self._evaluate(user, own)
        return await self._evaluate(user, conn)

    async def _evaluate(self, user: Mapping, conn: Any) -> MfaEvaluation:
        # FILL IN, in exactly this order (contract §3 TASK-138):
        #  1. user_id = int(_user_id(user))
        #  2. memberships = await self.resolver.memberships(user_id, conn=conn)          # D7, never headers (R14)
        #  3. policy = await self.resolver.effective(user, conn=conn, memberships=memberships)  # fresh per call (AC22)
        #  4. state = await self.state.state_of(user, policy, conn=conn)                 # may raise MFARefused (AC33)
        #  5. totp = await self.state.totp_confirmed(user_id, conn=conn)
        #     strong = await self.state.has_strong_factor(user, conn=conn)
        #  6. providers, preferred = await self.state.available_providers(user, policy, conn=conn)
        #  7. version = await self.security.current_version(conn, user_id)
        #  8. digest = self.security.context_digest(user=user, memberships=memberships, policy=policy,
        #                                           state=state, has_strong_factor=strong)
        #  9. return MfaEvaluation(user_id=..., providers=tuple(providers), ...)
        #  Do NOT catch anything here: storage errors must reach the caller (fail closed, R5).

    async def close(self) -> None:
        """Disconnect the Redis pool (called from BasicAuth.on_cleanup)."""
        # FILL IN: if self.redis_pool is not None: await self.redis_pool.disconnect()


class MfaServicesSlot:
    """Mutable holder registered on the app BEFORE it is frozen (aiohttp forbids setitem after)."""

    def __init__(self, services: Optional[MfaServices] = None) -> None:
        self.services = services


def get_mfa_services(app: Any) -> Optional[MfaServices]:
    """The app's MFA services, or None when 2FA was never set up for this app."""
    slot = app.get(MFA_APP_KEY) if app is not None else None
    return slot.services if isinstance(slot, MfaServicesSlot) else None
```

`_user_id` is the shared dict-or-Model accessor from `mfa/state.py` (D26):
the idp returns `AUTH_USER_VIEW` model instances, tests pass dicts, and two
private copies of that rule would drift.

**Why `evaluate()` lives here and not in the hook.** TASK-140 must recompute
*exactly* the same snapshot under the lock and compare `security_version` and
`context_digest` with the signed challenge (spec §3 "Challenge validity and
invalidation"). Two hand-written copies of this sequence would drift; a digest
computed from a different field order or a different membership source would
make every challenge "stale" — or worse, make a stale one look fresh.

**Why no `try/except` inside `_evaluate`.** R5: every borrowed component in this
code base fails *open* by house style. Here, "policy read failed" must become
"login refused", which is the caller's decision (`mfa_unavailable`), not a
default `OFF` policy. `test_policy_read_failure_fails_closed` pins it.

### `navigator_auth/mfa/services.py` — CREATE (block 2 of 2: builder)

```python
async def build_mfa_services(app: Any, backend: Any) -> MfaServices:
    """Build every MFA component. NEVER raises (spec M8/R13, contract D13).

    A missing secret, a missing ``authdb`` pool, unusable tables or any
    construction error yields ``MfaServices(available=False)`` and a CRITICAL
    log: BasicAuth then refuses every login (fail closed) while the process —
    and every tenant that never enabled 2FA — keeps running.
    """
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
        redis_pool = aioredis.ConnectionPool.from_url(
            auth_conf.REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        store = MfaChallengeStore(redis_pool, secret)
        backup_codes = BackupCodeStore(db_pool, secret)
        # FILL IN: construct, in this order —
        #   user_limiter = StrictRateLimiter(redis_pool, auth_conf.AUTH_OTP_RATE_USER, "user")
        #   ip_limiter   = StrictRateLimiter(redis_pool, auth_conf.AUTH_OTP_RATE_IP, "ip")
        #   security = MfaSecurity(db_pool, secret); trusted_devices = TrustedDeviceStore(db_pool)
        #   resolver = MfaPolicyResolver(db_pool); state = MfaStateMachine(db_pool, backup_codes=backup_codes)
        #   providers = {PROVIDER_TOTP: TOTPProvider(app=app, db_pool=db_pool, store=store),
        #                PROVIDER_EMAIL: EmailOTPProvider(secret=secret),   # keyed code hash (D30)
        #                PROVIDER_BACKUP: BackupCodeProvider(backup_codes)}
        #   — bounded by contract §3 constructor signatures; TOTPProvider resolves the vault keyring
        #     LAZILY (it does not exist yet at this point: auth.py:181 runs before :188, R13).
    except Exception as err:  # pylint: disable=W0703
        logger.critical("MFA: could not build services (%s); BasicAuth logins will be refused", type(err).__name__)
        return MfaServices(backend=backend, available=False)
    if not available:
        logger.critical("MFA: tables unavailable; BasicAuth logins will be refused until they exist")
    # FILL IN: return MfaServices(backend=backend, available=available, redis_pool=redis_pool, db_pool=db_pool,
    #          secret=secret, store=store, ... every component ...)
```

**Why never raise.** `auth_startup()` turns any `on_startup` exception into an
`AuthException` that aborts the whole app (`auth.py:182-186`). Spec §9 S5's
rejected half: "fail the logins, not the process". The `available` flag is the
fail-closed switch (AC24).

**Why the secret has no fallback.** Spec M1: `AUTH_OTP_SECRET` is "required
when enabled"; contract D13 forbids falling back to `SECRET_KEY` (unlike
`AUTH_RECOVERY_SECRET`, `conf.py:624-625`) — a shared key would let a leak of
one HMAC domain forge the other.

### `navigator_auth/backends/basic.py` — MODIFY (block 1: imports)

```python
# AFTER — insert below `from ..identities import AuthUser` (verified: basic.py:28)
# occurrences: 1 (verified: grep -cF 'from ..identities import AuthUser' navigator_auth/backends/basic.py)
from .. import conf as auth_conf
from ..mfa.services import MFA_APP_KEY, MfaServicesSlot, build_mfa_services, get_mfa_services
from ..mfa.trusted_devices import may_offer_trusted_device
from ..mfa.types import (
    AMR_PASSWORD,
    AMR_TRUSTED_DEVICE,
    MFA_DEVICE_TOKEN_KEY,
    PROVIDER_EMAIL,
    TRUSTED_COOKIE,
    MfaState,
)

# AND extend the existing exception import (verified: basic.py:20-25):
# occurrences: 1 (verified: grep -cF 'from ..exceptions import (' navigator_auth/backends/basic.py)
from ..exceptions import (
    AuthException,
    FailedAuth,
    UserNotFound,
    InvalidAuth,
    MfaSignal,
    MFARequired,
    MFARefused,
)
```

**Why the import order is safe.** `basic.py` already imports
`.oauth2.code_backend` (`:18`), so `navigator_auth.backends.oauth2` is fully
loaded before `mfa.services → mfa.limiter → backends.oauth2.dcr` runs; and
`navigator_auth/__init__.py` imports `auth.py` (→ `backends`) eagerly, so the
package is always entered backends-first. Verify in Step 7 with fresh
interpreters; **if** an `ImportError` cycle appears anyway, move the two
`..mfa.*` imports into the bodies of `configure`/`on_startup`/`_second_factor`
(do not reorder `basic.py`'s existing imports).

### `navigator_auth/backends/basic.py` — MODIFY (block 2: configure / on_startup / on_cleanup)

```python
# configure() — BEFORE `        super().configure(app)` (verified: basic.py:63)
# occurrences: 1 (verified: grep -cF '        super().configure(app)' navigator_auth/backends/basic.py)
        # FEAT-106 (D12): register the MFA slot while the app is still mutable.
        if self._owns_mfa() and MFA_APP_KEY not in app:
            app[MFA_APP_KEY] = MfaServicesSlot()

# on_startup() — AFTER `            self.get_successful_callbacks()` (verified: basic.py:75, last line of on_startup)
# occurrences: 1 (verified: grep -cF '            self.get_successful_callbacks()' navigator_auth/backends/basic.py)
        # FEAT-106 (D12): fill the slot once; never raises (build_mfa_services contract).
        slot = app.get(MFA_APP_KEY)
        if self._owns_mfa() and isinstance(slot, MfaServicesSlot) and slot.services is None:
            slot.services = await build_mfa_services(app, self)
            self._mfa_slot = slot
# NOTE: dedent — this must be at on_startup's body level, NOT inside the preceding
# `if self._success_callbacks:` block.

# on_cleanup() — AFTER the warning line (verified: basic.py:84)
# occurrences: 1 (verified: grep -cF 'self.logger.warning(f"BasicAuth: error closing access_token_storage Redis: {ex}")' …)
        slot = getattr(self, "_mfa_slot", None)
        if slot is not None and slot.services is not None:
            try:
                await slot.services.close()
            except Exception as ex:  # pylint: disable=W0703
                self.logger.warning(f"BasicAuth: error closing MFA services: {type(ex).__name__}")
            slot.services = None
# NOTE: dedent to on_cleanup's body level (outside the `if storage is not None:` block).

# new helper method (place right after on_cleanup):
    def _owns_mfa(self) -> bool:
        """True only for a backend whose login path IS ``BasicAuth.authenticate`` (D12).

        TokenExchangeAuth and PasskeyAuth override ``authenticate`` but inherit
        ``configure``/``on_startup``; this identity check keeps them from ever
        owning — or being subject to — the second factor (AC10, AC11).
        """
        return bool(auth_conf.AUTH_BASIC_2FA_ENABLED) and type(self).authenticate is BasicAuth.authenticate
```

**Why the identity check instead of `isinstance`.** `PasskeyAuth` and
`TokenExchangeAuth` *are* `BasicAuth` instances. What makes the hook apply is
running `BasicAuth.authenticate`; a function looked up through the class is the
plain function object, so `is` is exact. A future subclass that does not
override `authenticate` correctly inherits the second factor.

### `navigator_auth/backends/basic.py` — MODIFY (block 3: the authenticate hook)

```python
# BEFORE — insert immediately above the `try:` that wraps open_session (verified: basic.py:314-316)
# anchor (unique 3-line context):
#             try:
#                 return await self.open_session(request, user)
#             except (FailedAuth, InvalidAuth):
# occurrences: 1 (verified: grep -cF '                return await self.open_session(request, user)' navigator_auth/backends/basic.py)
            if auth_conf.AUTH_BASIC_2FA_ENABLED:
                # FEAT-106 — raises MfaSignal, or returns None when no factor is owed.
                session = await self._second_factor(request, user)
                if session is not None:
                    return session
            # (existing, unchanged)
            try:
                return await self.open_session(request, user)
```

**Why the disabled path is untouched.** AC20 requires the login path to be
byte-identical with `AUTH_BASIC_2FA_ENABLED=False`: one boolean read, then the
exact original `try/open_session/except` block. With the flag on and no factor
owed (`state == NONE`), the hook returns `None` and the same original block
runs — `open_session(request, user)` with **no** `extra`, so tenants that never
opted in see no new JWT claims (G8).

### `navigator_auth/backends/basic.py` — MODIFY (block 4: `_second_factor` and `_trusted_device`, after `authenticate`)

```python
    async def _second_factor(self, request: web.Request, user) -> Optional[dict]:
        """Decide whether this password login owes a second factor (FEAT-106 M9).

        Returns None (no factor owed — caller opens the session as before) or the
        login dict of a session opened on a valid trusted device. EVERY other
        outcome is raised as an MfaSignal: MFARequired (challenge issued, nothing
        created) or MFARefused (fail closed). Never returns False and never raises
        a plain AuthException — either would make AuthHandler.api_login try the
        next backend with the same credentials (spec §7 R2, contract D1).
        """
        if not user_is_active(user):
            # Same refusal open_session would give; do not send codes to disabled accounts.
            raise FailedAuth("User account is disabled", status=403)
        services = get_mfa_services(request.app)
        if services is None or not services.available:
            raise MFARefused("mfa_unavailable", "Second factor is temporarily unavailable", status=503)  # D13
        uid = user[self.userid_attribute]
        try:
            evaluation = await services.evaluate(user)
            if evaluation.state == MfaState.NONE:
                return None
            device_token = await self._trusted_device(request, services, evaluation)
            if device_token is not None:
                extra = {"auth_method": "basic", "mfa": True, "amr": [AMR_PASSWORD, AMR_TRUSTED_DEVICE]}
                result = await self.open_session(request, user, extra=extra)
                # D14: the raw token rides on the returned dict ONLY; finalize_login pops it.
                result[MFA_DEVICE_TOKEN_KEY] = {
                    "token": device_token, "max_age": evaluation.policy.remember_days * 86400,
                }
                return result
            if not evaluation.providers:
                raise MFARefused("no_factor_available", "No second factor is available for this account", status=403)
            code_hash = None
            if evaluation.preferred == PROVIDER_EMAIL:
                issued = await services.providers[PROVIDER_EMAIL].challenge(request, user)
                code_hash = issued.get("code_hash")
            token, _record = await services.store.issue(
                user, list(evaluation.providers), evaluation.preferred,
                security_version=evaluation.security_version,
                context_digest=evaluation.context_digest,
                email_code_hash=code_hash,
            )
        except (MfaSignal, FailedAuth, InvalidAuth):
            raise
        except Exception as err:  # pylint: disable=W0703 — fail CLOSED (R5)
            self.logger.error(f"BasicAuth: second factor unavailable for user {uid}: {type(err).__name__}")
            raise MFARefused("mfa_unavailable", "Second factor is temporarily unavailable", status=503) from err
        raise MFARequired(
            challenge=token, providers=list(evaluation.providers),
            preferred=evaluation.preferred, expires_in=auth_conf.AUTH_OTP_CHALLENGE_TTL,
        )

    async def _trusted_device(self, request: web.Request, services, evaluation) -> Optional[str]:
        """Rotate a presented trusted-device cookie; return the NEW raw token, else None.

        Only strong-factor users in a tenant with remember_days > 0 (M6, AC17). The
        enforced-superuser invariant was already applied by evaluate() (state_of
        raises before we get here), so a remembered device never replaces a missing
        strong factor (AC33). Any error means "no trusted device": the login falls
        through to a challenge — fail closed in the bypass direction.
        """
        raw = request.cookies.get(TRUSTED_COOKIE)
        if not raw or not may_offer_trusted_device(  # D27: the single AC17 rule, shared with verify (TASK-140)
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        # FILL IN: rotated = await services.trusted_devices.consume_and_rotate(raw, evaluation.user_id)
        #   inside try/except Exception → log WARNING with type(err).__name__ only (never the token) and return None;
        #   rotated None → None; rotated[0] != evaluation.user_id → None (defence in depth, D15);
        #   else return rotated[1]. — bounded by D15, AC14 (token never logged), AC19.
```

**Why `(FailedAuth, InvalidAuth)` pass through unchanged.** They can only come
from `open_session()` on the trusted-device path (`user_is_active`, `basic.py:202-204`)
or the explicit inactive check above — the same refusals today's path raises
(`basic.py:316-317`), handled the same way by every caller. Everything else is
converted to `mfa_unavailable`; in particular a raising `open_session()` on the
trusted path must **not** become `return False`, which would hand the
credentials to the next backend.

**Why the email code is generated before `store.issue()`.** `EmailOTPProvider.challenge()`
both generates and hands off the code and returns only its hash (TASK-137);
the hash must be inside the signed challenge record. If `issue()` then fails,
the user holds a dead code and gets `mfa_unavailable` — harmless.

**Why `max_age = remember_days * 86400`.** `consume_and_rotate` keeps the
family's original `expires_at` (D15) and the server row is authoritative; the
cookie's Max-Age may overshoot but can never extend the server-side window.

### `tests/test_mfa_basic_auth_hook.py` — CREATE

```python
"""FEAT-106 TASK-138 — BasicAuth second-factor hook (unit level, no live server).

Builds a bare BasicAuth (validate_user / open_session replaced by AsyncMocks) and
an MfaServices whose components are small fakes, so every branch of the hook is
pinned without Redis/Postgres. End-to-end coverage lives in TASK-147.
"""
from unittest.mock import AsyncMock

import pytest
from aiohttp.test_utils import make_mocked_request
from aiohttp import web

from navigator_auth import conf as auth_conf
from navigator_auth.backends.basic import BasicAuth
from navigator_auth.backends.exchange import TokenExchangeAuth
from navigator_auth.backends.passkey import PasskeyAuth
from navigator_auth.exceptions import MFARequired, MFARefused
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.types import MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE, MfaMode, MfaState, TenantMfaPolicy

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]

# FILL IN helpers: _user(**over) -> dict(user_id=7, username="alice", email="a@x.io", is_active=True,
#   is_superuser=False, password="pbkdf2_sha256$…"); _backend() -> BasicAuth.__new__(BasicAuth) with
#   logger, userid_attribute="user_id", validate_user/get_payload/open_session AsyncMocks;
#   _app_with(services) -> web.Application() with app[MFA_APP_KEY] = MfaServicesSlot(services);
#   fake resolver/state/security/store/trusted_devices/providers objects with AsyncMock methods.
#   — bounded by the contract signatures listed in this task's Codebase Contract.


def test_ownership_rule_excludes_overriding_subclasses():
    """D12: only a backend running BasicAuth.authenticate owns MFA (AC10, AC11)."""
    assert TokenExchangeAuth.authenticate is not BasicAuth.authenticate
    assert PasskeyAuth.authenticate is not BasicAuth.authenticate


@pytest.mark.asyncio
async def test_disabled_path_is_unchanged(monkeypatch):
    """AC20: flag off ⇒ open_session(request, user) with no extra; services never consulted."""
    # FILL IN


@pytest.mark.asyncio
async def test_mfa_required_payload_has_no_token(monkeypatch):
    """AC6: owed factor ⇒ MFARequired; payload keys exactly the envelope; open_session NOT called."""
    # FILL IN: assert set(err.payload()) == {"mfa_required","challenge","providers","preferred","expires_in"}


@pytest.mark.asyncio
async def test_token_exchange_never_challenged(monkeypatch):
    """AC11: TokenExchangeAuth.on_startup/configure with 2FA on leave no slot/services."""
    # FILL IN


@pytest.mark.asyncio
async def test_passkey_signin_never_challenged(monkeypatch):
    """AC10: PasskeyAuth never owns MFA; its authenticate is its own override."""
    # FILL IN


@pytest.mark.asyncio
async def test_missing_mfa_tables_refuse_login(monkeypatch):
    """AC24: setup_mfa_tables False ⇒ build never raises, available False, login ⇒ MFARefused 503."""
    # FILL IN


@pytest.mark.asyncio
async def test_policy_read_is_per_login_not_cached(monkeypatch):
    """AC22: resolver.effective called on EVERY login; changing its result changes the next login."""
    # FILL IN


@pytest.mark.asyncio
async def test_policy_read_failure_fails_closed(monkeypatch):
    """R5/AC12: resolver raises ⇒ MFARefused('mfa_unavailable', 503); open_session never called."""
    # FILL IN


@pytest.mark.asyncio
async def test_enforced_superuser_requires_strong_factor_at_login(monkeypatch):
    """AC33: state_of raises strong_factor_required ⇒ propagates; trusted cookie NOT consulted."""
    # FILL IN


@pytest.mark.asyncio
async def test_trusted_device_skips_otp_with_honest_amr(monkeypatch):
    """AC17/AC19/D14: strong + remember_days>0 + valid cookie ⇒ session with amr trusted_device;
    rotated token only in result[MFA_DEVICE_TOKEN_KEY], never in open_session's extra."""
    # FILL IN


@pytest.mark.asyncio
async def test_trusted_device_ignored_for_email_state(monkeypatch):
    """AC17: no strong factor ⇒ consume_and_rotate never called, challenge issued."""
    # FILL IN


@pytest.mark.asyncio
async def test_no_provider_refused(monkeypatch):
    """D10/R3: owed factor with empty providers ⇒ MFARefused('no_factor_available', 403)."""
    # FILL IN


@pytest.mark.asyncio
async def test_storage_error_during_issue_fails_closed(monkeypatch):
    """R2/D1: store.issue raises ⇒ MFARefused 503 — never False, never a plain AuthException."""
    # FILL IN


@pytest.mark.asyncio
async def test_email_preferred_issues_code_hash(monkeypatch):
    """Email preferred ⇒ provider.challenge called once and issue(email_code_hash=…) receives its hash."""
    # FILL IN
```

**Why unit-level fakes.** The hook's correctness is about *which branch raises
what*; the components are each tested in their own tasks. A live-server test
would hide a wrong branch behind setup noise. TASK-147 covers the full stack.

### Steps (in order)

1. Confirm TASK-129…TASK-137 are in `sdd/tasks/completed/` and every
   *(TASK-NNN)* symbol in the Codebase Contract exists (`grep -n`).
2. Confirm TASK-139 is done **or** will land in the same branch before any
   merge: the signals raised here are only safe once all three call sites catch
   `MfaSignal` first (R2). Do not merge this task alone.
3. Create `services.py` (blocks 1–2). Run
   `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` → must print nothing (D5/AC5).
4. Add basic.py block 1 (imports), then block 2 (configure/on_startup/on_cleanup
   + `_owns_mfa`). Watch the indentation notes — both insertions are at method
   body level, outside the preceding `if` blocks.
5. Add block 3 (the two-line hook in `authenticate`) and block 4 (`_second_factor`,
   `_trusted_device`). Re-read `authenticate` top to bottom and check: no path
   after `validate_user()` with 2FA on can `return False` or raise a non-signal
   `AuthException` except `FailedAuth`/`InvalidAuth` from the inactive check / `open_session`.
6. Write the tests; fill each body.
7. Import sanity in fresh interpreters:
   `python -c "import navigator_auth.mfa.services"` and
   `python -c "import navigator_auth.backends.basic"` and `python -c "import navigator_auth"`.
8. Run the test commands below, then the regression gate.

### FILL IN checklist

- [ ] `MfaServices.__init__` attribute assignment
- [ ] `_evaluate` — nine steps, no exception handling — AC22, AC33, R5
- [ ] `close()` — disconnect pool
- [ ] `build_mfa_services` — component construction + final `MfaServices(...)` — D13, AC24
- [ ] `_trusted_device` — rotate, defence-in-depth uid check, never log the token — D15, AC14, AC17, AC19
- [ ] Test helpers (`_user`, `_backend`, `_app_with`, fakes)
- [ ] 13 test bodies

---

## Acceptance Criteria

- [ ] **AC-1** With `AUTH_BASIC_2FA_ENABLED=False`, `authenticate()` calls `open_session(request, user)` exactly as before (no `extra`) and never touches MFA services (spec AC20).
- [ ] **AC-2** With 2FA on and no factor owed (`state == NONE`), `open_session(request, user)` is called with no `extra` (G8).
- [ ] **AC-3** A login owing a factor raises `MFARequired`; `open_session` is not called; the payload contains no `token`/`refresh_token`/session id (spec AC6 — backend half).
- [ ] **AC-4** Every failure inside the hook (policy read, state read, version read, challenge issue, email hand-off) raises `MFARefused("mfa_unavailable", 503)`; the hook never returns `False` and never raises a plain `AuthException` (D1, R2, spec AC12 backend half).
- [ ] **AC-5** MFA services unbuilt or `available=False` with 2FA on ⇒ `MFARefused("mfa_unavailable", 503)`; `build_mfa_services` never raises and startup succeeds (spec AC24).
- [ ] **AC-6** The policy is read on every login (no cache); a change between two logins changes the second outcome (spec AC22).
- [ ] **AC-7** An enforced superuser without a strong factor gets `strong_factor_required` before any trusted-device check (spec AC33, login half).
- [ ] **AC-8** A trusted device is accepted only for strong-factor users with `remember_days > 0`; the session carries `mfa=True`, `amr=["pwd","trusted_device"]`; the rotated raw token is only in `result["_mfa_trusted_device"]`, never in `open_session`'s `extra` (spec AC17, AC19, D14).
- [ ] **AC-9** `TokenExchangeAuth` and `PasskeyAuth` never own MFA services and are never challenged; neither file is modified (spec AC10, AC11).
- [ ] **AC-10** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` prints nothing (spec AC5 as refined by D5).
- [ ] **AC-11** `on_startup` performs no `app[...] = …` assignment (frozen-app constraint); the slot is registered in `configure()`.
- [ ] **AC-13** Trusted-device acceptance calls `may_offer_trusted_device()` (D27) and `services.py` imports `_user_id` from `mfa/state.py` (D26) — no re-implemented copies.
- [ ] **AC-14** `grep -rn "\.execute(" navigator_auth/mfa/ navigator_auth/handlers/mfa.py` shows nothing except `mfa/migrations.py` (contract D25).
- [ ] **AC-12** `pytest tests/test_mfa_basic_auth_hook.py -v` passes; regression `pytest tests/test_basic_auth.py tests/test_basic_open_session.py tests/test_passkey_signin.py tests/test_eval_context_auth_method.py -q` passes unchanged (spec AC3); `ruff check navigator_auth/mfa/services.py navigator_auth/backends/basic.py tests/test_mfa_basic_auth_hook.py` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_basic_auth_hook.py -v
pytest tests/test_basic_auth.py tests/test_basic_open_session.py tests/test_passkey_signin.py tests/test_eval_context_auth_method.py -q   # AC3 regression
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1   # AC5 (D5)
grep -rn "\.execute(" navigator_auth/mfa/ | grep -v "mfa/migrations.py" ; test $? -eq 1   # AC-14 (D25)
ruff check navigator_auth/mfa/services.py navigator_auth/backends/basic.py tests/test_mfa_basic_auth_hook.py
```

Spec §4 rows owned here: `test_mfa_required_payload_has_no_token`,
`test_token_exchange_never_challenged`, `test_passkey_signin_never_challenged`
(unit half; e2e in TASK-147), `test_missing_mfa_tables_refuse_login`,
`test_policy_read_is_per_login_not_cached`, `test_policy_read_failure_fails_closed`,
`test_enforced_superuser_requires_strong_factor_at_login` (login half).

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md`: §2 Overview (the
   "ordering-sensitive" paragraph), §3 M7, M8, M9, "Security contracts shared by
   the modules", §7 R2, R5, R12, R13, R14; and the FEAT-106 contract D1, D5,
   D10–D15.
2. **Check dependencies** — TASK-135, TASK-136, TASK-137 (and their deps) in
   `sdd/tasks/completed/`. Coordinate with TASK-139 (Step 2).
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. If the hook needs a branch the blueprint
   does not show, it must end in `None`, a session dict, or an `MfaSignal` —
   nothing else.
5. **Verify** every acceptance criterion; AC-4 and AC-11 by reading the diff,
   not only by tests.
6. **Move this file** to `sdd/tasks/completed/TASK-138-mfa-basic-auth-hook.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
