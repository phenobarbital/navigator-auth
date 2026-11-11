# TASK-131: Challenge store, pending-enrollment store, TOTP replay guard, fail-closed limiter

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-129
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 2**: every piece of short-lived MFA state that
lives in Redis.

- **`MfaChallengeStore`** — HMAC-signed, TTL'd, single-use challenge records
  keyed by `sha256(token)`, with a **separate atomic attempt counter**; plus the
  pending-TOTP-enrolment records (spec "Pending enrollment and replacement") and
  the TOTP replay guard (`mark_totp_step`).
- **`StrictRateLimiter`** — a fixed-window counter that **fails closed**.

Shape is cloned from `handlers/recovery/store.py:42` (hash-keyed, HMAC-signed,
pooled `aioredis.Redis(connection_pool=…)`, `GETDEL` for single use) — **cloned,
never imported or subclassed** (spec §7 "Never import from handlers/recovery/").
The failure posture is the **inverse** of the recovery components (spec §7 R5):
`handlers/recovery/limiter.py:58-64` returns `True` on a Redis error ("Fail-open
by design"); here every storage error is fatal to the operation.

### The fail-closed rule (binding for every method in this task)

- **Every Redis error raises `MfaStorageError`** (TASK-129). Never return `None`,
  `True`, `0` or a default on a storage error.
- **`None` means only one thing: absent, expired, or failed the HMAC check.**
  Callers can therefore distinguish "the challenge is gone" (401 to the client)
  from "storage is down" (503 `mfa_unavailable`) — the distinction spec AC12 needs.
- The one deliberate exception is `StrictRateLimiter.check()`, whose spec
  contract is a `bool`: a storage error returns **`False`** (refused), never `True`.

### Retry contract this store must make possible (spec "Retry accounting and concurrency")

- Attempts are a **separate Redis key**, not a field of the signed record —
  mutable counters are not signed payload fields.
- Increment/burn is **atomic** (one Lua script), **preserves the record's
  original expiry** and **never recreates** a missing record.
- Invalid codes keep the challenge for attempts 1..(max-1); attempt `max` burns it
  (record + counter deleted). With `AUTH_OTP_MAX_ATTEMPTS = 5`: four wrong codes
  keep it, a correct fifth still succeeds, five wrong codes burn it permanently.
- Success consumes with `GETDEL` (record) + `DEL` (counter) in one atomic Lua call (`_CONSUME_LUA`).
- E-mail resend replaces the code hash in place: **re-signed**, original TTL kept
  (`KEEPTTL`), only if the record still exists (`XX`), counter untouched — so a
  resend can never reset the attempt budget or extend the expiry (spec AC30/AC31).
  The caller holds the per-user lock (TASK-132) while calling it.

### Decomposition decisions this task implements

- **D19** — the strict limiter keeps `parse_rate_limit`'s "(0, 0) = disabled"
  meaning for a malformed spec (a typo must not lock every user out), but logs a
  WARNING at construction when a non-empty spec parses to (0, 0). The
  per-challenge attempt budget still bounds guessing.
- Pending enrolment lives here too (contract §3): one Redis-owning module.
  `ENROLLMENT_TTL = 300` is **absolute** — no method ever extends it (spec:
  "five-minute absolute TTL and no TTL extension on retries").

### Why this task's tests define their own Redis fixtures

TASK-131 depends only on TASK-129 and may run in parallel with TASK-130, which
creates `tests/fixtures/mfa.py`. So `tests/test_mfa_challenge_store.py` declares
local `redis_pool` / `broken_redis_pool` fixtures (pattern:
`tests/test_password_recovery.py:85-124`) and does **not** import the shared module.

---

## Scope

- Create `navigator_auth/mfa/store.py`: constants, `_hash_token`, `canonical_json`,
  `new_opaque_token`, `MfaChallengeStore` (all contract §3 methods).
- Create `navigator_auth/mfa/limiter.py`: `RATE_KEY_PREFIX`, `StrictRateLimiter`.
- Create `tests/test_mfa_challenge_store.py`.

**NOT in scope**: computing `security_version` / `context_digest` (TASK-132/138 pass
them in); sealing the pending seed (TASK-136 passes ciphertext bytes); the per-user
lock (TASK-132); HTTP handling and provider-allowlist checks (TASK-140); hashing the
e-mail code (TASK-137 passes `email_code_hash`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/store.py` | CREATE | Challenge + enrolment records, attempt counters, replay guard |
| `navigator_auth/mfa/limiter.py` | CREATE | `StrictRateLimiter` (fails closed) |
| `tests/test_mfa_challenge_store.py` | CREATE | Real-Redis tests incl. fail-closed and concurrency |

---

## Codebase Contract

> Verified on `dev` @ `b10a3a3` (2026-11-11). Redis server 7.2.3 (live), redis-py 5.2.1.

### Verified Imports

```python
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Mapping
from typing import Optional
import redis.asyncio as aioredis                         # redis 5.2.1
from redis.exceptions import RedisError                  # base of ConnectionError/TimeoutError/ResponseError
from navigator_auth.conf import (
    AUTH_OTP_CHALLENGE_TTL, AUTH_OTP_MAX_ATTEMPTS,        # TASK-129
    AUTH_USERID_ATTRIBUTE, AUTH_USERNAME_ATTRIBUTE,       # conf.py:320-321 ("user_id", "username")
)
from navigator_auth.backends.oauth2.dcr import parse_rate_limit   # dcr.py:104 -> (count, seconds) | (0, 0)
from navigator_auth.mfa.exceptions import MfaStorageError         # TASK-129
from navigator_auth.mfa.types import MfaChallenge, PendingEnrollment   # TASK-129
# tests:
import asyncio
import pytest
import pytest_asyncio
from navigator_auth.conf import REDIS_AUTH_URL                     # conf.py:297
```

### The shape being cloned (NOT imported) — `navigator_auth/handlers/recovery/store.py`

```python
def _hash_token(token: str) -> str:                       # :37 — sha256 hex, the only Redis key
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
class RecoveryTokenStore:                                  # :42
    def __init__(self, pool: aioredis.ConnectionPool, secret: bytes): ...
    def _sign(self, *parts: str) -> str:                   # :54 — hmac.new(secret, msg, sha256).hexdigest()
    async def issue_recovery(self, user): ...              # :67 — token_urlsafe(32); setex
        async with aioredis.Redis(connection_pool=self._pool) as redis: ...   # per-call client on the shared pool
    def _decode_recovery(self, raw): ...                   # :100 — secrets.compare_digest on the signature
```

### The limiter being inverted (NOT imported) — `navigator_auth/handlers/recovery/limiter.py`

```python
class RateLimiter:                                         # :28
    def __init__(self, pool, spec: str, prefix: str):      # :40 — self._count, self._window = parse_rate_limit(spec)
    async def check(self, key: str) -> bool:               # :45
        if self._count <= 0: return True                   # :47 — (0,0) == disabled
        ... INCR; EXPIRE when ==1 ...                      # :53-57 — two round-trips, not atomic
        except Exception: ... return True                  # :58-64 — FAIL-OPEN  ← must be inverted
```

### redis-py / Redis capabilities used (verified)

```python
await r.set(name, value, ex=…, nx=True)        # -> True | None
await r.set(name, value, xx=True, keepttl=True)  # KEEPTTL needs Redis >= 6.0 (server is 7.2.3)
await r.getdel(name)                           # Redis >= 6.2 (recovery store already relies on it)
await r.eval(script, numkeys, *keys_and_args)  # atomic Lua (GETDEL inside Lua needs Redis >= 6.2)
await r.pttl(name)                             # ms; -2 absent, -1 no expiry
```

Do **not** use `pipeline(...)`/`.execute()` here: every multi-command atomic step
is a Lua script, so the D25 gate `grep -rn "\.execute(" navigator_auth/mfa/`
(meant for asyncdb's never-raising `conn.execute()`) has no false positives.

Pools created by TASK-138 / the test fixtures use `decode_responses=True`; still
tolerate `bytes` from `GET` (decode before `json.loads`).

### Does NOT Exist (Anti-Hallucination)

- ~~`navigator_auth/mfa/store.py`, `limiter.py`~~ — created here.
- ~~Reusing `RecoveryTokenStore` / `RateLimiter`~~ — forbidden (spec §7); different namespace, posture, lifetime.
- ~~`fakeredis`~~ — not installed; tests use the live Redis at `REDIS_AUTH_URL`.
- ~~An attempts field inside `MfaChallenge`~~ — attempts are separate state (spec §2 comment).
- ~~`IdentityFlowStore` as a base class~~ (`identity/flow_store.py:18`) — a pattern reference only.

---

## Implementation Blueprint

### `navigator_auth/mfa/store.py` — CREATE (block 1 of 4: header, constants, helpers, init, codec)

```python
"""MFA Redis state (FEAT-106, spec M2): challenges, pending enrolments,
attempt counters and the TOTP replay guard.

Shape cloned from handlers/recovery/store.py (sha256-keyed, HMAC-signed,
pooled), never imported. Posture is the INVERSE of the recovery components:
every Redis error raises MfaStorageError (fail CLOSED, spec R5). ``None``
from a read means only "absent, expired or tampered".
"""
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Mapping
from typing import Optional

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from navigator_auth.conf import (
    AUTH_OTP_CHALLENGE_TTL, AUTH_OTP_MAX_ATTEMPTS, AUTH_USERID_ATTRIBUTE, AUTH_USERNAME_ATTRIBUTE,
)
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import MfaChallenge, PendingEnrollment

logger = logging.getLogger("navigator.mfa")

CHALLENGE_KEY_PREFIX = "auth:mfa:challenge:"
ATTEMPTS_KEY_PREFIX = "auth:mfa:attempts:"
TOTP_REPLAY_PREFIX = "auth:mfa:totp:used:"
ENROLL_KEY_PREFIX = "auth:mfa:enroll:"
ENROLL_ATTEMPTS_PREFIX = "auth:mfa:enroll-attempts:"
ENROLLMENT_TTL = 300   # absolute; never extended (spec "Pending enrollment and replacement")

# Atomic failure accounting, shared by challenges and enrolments (block 3 uses it).
# KEYS[1] = record key, KEYS[2] = attempts key, ARGV[1] = max attempts.
# Returns remaining attempts; 0 = burned (both keys deleted); -1 = record absent.
_REGISTER_FAILURE_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return -1
end
-- FILL IN (exact bounds, spec 'Retry accounting and concurrency'):
--  1. local n = redis.call('INCR', KEYS[2])
--  2. if n == 1: copy the RECORD's remaining life onto the counter —
--     local pttl = redis.call('PTTL', KEYS[1]); if pttl > 0 then PEXPIRE KEYS[2] pttl end.
--     NEVER touch KEYS[1]'s TTL (preserve the original expiry).
--  3. if n >= tonumber(ARGV[1]): DEL KEYS[1] KEYS[2]; return 0
--  4. return tonumber(ARGV[1]) - n
--  The EXISTS guard above is what guarantees an absent/expired record is
--  never recreated and no orphan counter is created for it.
"""

# Single-use consumption: GETDEL the record and DEL its counter atomically.
# KEYS[1] = record key, KEYS[2] = attempts key. Returns the record or nil.
# (Lua, not a MULTI pipeline: D25's `grep "\.execute("` gate must stay clean.)
_CONSUME_LUA = """
local v = redis.call('GETDEL', KEYS[1])
redis.call('DEL', KEYS[2])
return v
"""


def _hash_token(token: str) -> str:
    """sha256 hex digest — the only thing ever used as a Redis key."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def canonical_json(fields: dict) -> bytes:
    """Canonical serialization signed by the HMAC (sorted keys, no whitespace)."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def new_opaque_token() -> str:
    """A fresh 256-bit URL-safe token (challenge or enrolment)."""
    return secrets.token_urlsafe(32)


def _user_field(user: Mapping, name: str):
    """Read ``name`` from a dict or a datamodel Model (idp returns either)."""
    # FILL IN: try user[name]; on (KeyError, TypeError) fall back to
    #  getattr(user, name, None); when still None raise
    #  ValueError(f"user record lacks {name}") — NOT MfaStorageError (this is a
    #  caller bug, not a storage outage). Bounded by: a challenge for an
    #  unidentifiable user must never be issued.


class MfaChallengeStore:
    """HMAC-signed, TTL'd, single-use challenge and enrolment records. Fails CLOSED."""

    def __init__(self, pool: aioredis.ConnectionPool, secret: bytes,
                 ttl: int = AUTH_OTP_CHALLENGE_TTL, max_attempts: int = AUTH_OTP_MAX_ATTEMPTS):
        if not secret:
            raise ValueError("MfaChallengeStore requires a non-empty secret")
        self._pool = pool
        self._secret = secret
        self._ttl = int(ttl)
        self._max_attempts = int(max_attempts)

    def _redis(self) -> aioredis.Redis:
        return aioredis.Redis(connection_pool=self._pool)

    def _sign(self, fields: dict) -> str:
        return hmac.new(self._secret, canonical_json(fields), hashlib.sha256).hexdigest()

    def _decode(self, raw, model):
        """Verify the HMAC and build ``model``; None when malformed or tampered."""
        # FILL IN: bytes -> str; json.loads; pop "signature"; expected = self._sign(rest);
        #  secrets.compare_digest(expected, signature) else log WARNING (no token, no
        #  payload) and return None; return model.model_validate({**rest, "signature": signature});
        #  json/validation errors -> WARNING + None. Bounded by spec test
        #  test_challenge_hmac_tamper_rejected.
```

**Why** `_decode` returns `None` (not raise) for tampering: a tampered record is
indistinguishable, to the client, from an expired one — both are "no valid
challenge" (401). Only *storage* failures are `MfaStorageError` (503). **Why**
`canonical_json` with `default=str`: every signed field is a JSON scalar or a
list of strings; `model_dump(mode="json")` turns the `providers` tuple into a list
on both the signing and verifying side, so the bytes match.

### `navigator_auth/mfa/store.py` — CREATE (block 2 of 4: challenge lifecycle)

```python
    async def issue(self, user: Mapping, providers: list[str], preferred: str, *,
                    security_version: int, context_digest: str,
                    email_code_hash: Optional[str] = None) -> tuple[str, MfaChallenge]:
        """Mint the challenge token; SET NX EX ttl. Returns (raw token, record).
        The raw token is never logged and never used as a key."""
        token = new_opaque_token()
        fields = {
            "user_id": int(_user_field(user, AUTH_USERID_ATTRIBUTE)),
            "username": str(_user_field(user, AUTH_USERNAME_ATTRIBUTE)),
            "providers": list(providers),
            "preferred": preferred,
            "issued_at": time.time(),
            "security_version": int(security_version),
            "context_digest": context_digest,
            "email_code_hash": email_code_hash,
        }
        record = MfaChallenge(**fields, signature=self._sign(fields))
        # FILL IN: SET CHALLENGE_KEY_PREFIX+_hash_token(token) to
        #  json.dumps(record.model_dump(mode="json")) with nx=True, ex=self._ttl;
        #  a falsy reply (collision) -> MfaStorageError; RedisError -> MfaStorageError.
        return token, record

    async def peek(self, token: str) -> Optional[MfaChallenge]:
        """Read without consuming; verifies the HMAC. None when absent/invalid."""
        # FILL IN: GET; None -> None; else self._decode(raw, MfaChallenge);
        #  RedisError -> MfaStorageError.

    async def consume(self, token: str) -> Optional[MfaChallenge]:
        """GETDEL the record and DEL its attempt counter atomically (one Lua call).
        Call only AFTER successful verification, under the user lock. None when
        absent, expired or tampered: the caller must never proceed to a session then."""
        # FILL IN: eval _CONSUME_LUA with keys [record_key, attempts_key];
        #  None reply -> None; else self._decode(reply, MfaChallenge);
        #  RedisError -> MfaStorageError.

    async def discard(self, token: str) -> None:
        """Burn a challenge (stale security context): delete record + counter."""
        # FILL IN: DEL both keys; RedisError -> MfaStorageError.

    async def remaining_ttl(self, token: str) -> int:
        """Seconds left on the record (ceil of PTTL); 0 when absent."""
        # FILL IN: PTTL; <= 0 -> 0; else ceil(ms / 1000); RedisError -> MfaStorageError.
```

**Why** `SET NX`: a token collision is astronomically unlikely, but `NX` turns
"overwrite someone else's live challenge" into a loud error instead of a silent
takeover. **Why** consume deletes the counter in the same Lua call: a leftover
counter for a consumed token is harmless but would outlive its record if the
second command were a separate round-trip that failed. **Why** Lua rather than a
`MULTI` pipeline: equally atomic, and it keeps the text `.execute(` out of
`navigator_auth/mfa/` so contract D25's grep gate (aimed at asyncdb's
never-raising `conn.execute()`) stays meaningful.

### `navigator_auth/mfa/store.py` — CREATE (block 3 of 4: attempts, resend, replay guard)

```python
    # (methods continue inside class MfaChallengeStore; _REGISTER_FAILURE_LUA is
    #  the module-level constant declared in block 1)

    async def register_failure(self, token: str) -> int:
        """Atomically count a failed attempt; burn at max. -1 when absent."""
        h = _hash_token(token)
        # FILL IN: eval _REGISTER_FAILURE_LUA with keys
        #  [CHALLENGE_KEY_PREFIX+h, ATTEMPTS_KEY_PREFIX+h], arg self._max_attempts;
        #  return int(reply); RedisError -> MfaStorageError.

    async def replace_email_code(self, token: str, new_code_hash: str) -> Optional[MfaChallenge]:
        """E-mail resend: re-sign with the new hash, keep TTL and counter.
        Caller holds the per-user lock (TASK-132). None when the record is gone."""
        # FILL IN: GET + _decode (None -> None); fields = record.model_dump(mode="json")
        #  minus "signature", with email_code_hash=new_code_hash; re-sign;
        #  SET record_key value xx=True keepttl=True; a falsy reply (expired in
        #  between) -> None. NEVER touch the attempts key; NEVER set a new TTL.
        #  RedisError -> MfaStorageError. Bounded by AC30/AC31 and spec test
        #  test_resend_preserves_budget_and_expiry.

    async def mark_totp_step(self, user_id: int, step: int, ttl: int) -> bool:
        """False when this step was already accepted (replay). Mandatory:
        without it a captured code is reusable inside its window (AC13)."""
        # FILL IN: SET f"{TOTP_REPLAY_PREFIX}{int(user_id)}:{int(step)}" "1" nx=True ex=ttl;
        #  return bool(reply); RedisError -> MfaStorageError (never True on error).
```

**Why** Lua and not WATCH/MULTI: increment, expiry copy and burn must be one
atomic step under concurrent verification (spec test
`test_concurrent_verify_consumes_once` and "mixed correct/incorrect submissions
preserve the attempt budget"). **Why** the counter copies the record's PTTL on
the first failure: the counter must die with the record, and setting a fresh
TTL on the counter would let it outlive the challenge or (worse) a separate code
path could be tempted to "refresh" the record.

### `navigator_auth/mfa/store.py` — CREATE (block 4 of 4: pending TOTP enrolment)

```python
    async def put_enrollment(self, token: str, *, user_id: int, session_id: str,
                             security_version: int, sealed_seed: bytes) -> PendingEnrollment:
        """Store a sealed pending seed for ENROLLMENT_TTL seconds (absolute).
        ``token`` comes from new_opaque_token(): the caller seals the seed with a
        context that binds _hash_token(token) BEFORE calling this (TASK-136)."""
        fields = {
            "user_id": int(user_id),
            "session_hash": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
            "security_version": int(security_version),
            "sealed_seed": base64.b64encode(sealed_seed).decode("ascii"),
            "issued_at": time.time(),
        }
        record = PendingEnrollment(**fields, signature=self._sign(fields))
        # FILL IN: SET ENROLL_KEY_PREFIX+_hash_token(token) nx=True ex=ENROLLMENT_TTL;
        #  falsy reply -> MfaStorageError; RedisError -> MfaStorageError.
        return record

    async def peek_enrollment(self, token: str) -> Optional[PendingEnrollment]:
        # FILL IN: GET + self._decode(raw, PendingEnrollment); RedisError -> MfaStorageError.

    async def consume_enrollment(self, token: str) -> Optional[PendingEnrollment]:
        """Single-use: GETDEL record + DEL counter in one Lua call (concurrent
        confirmations produce exactly one transition)."""
        # FILL IN: eval _CONSUME_LUA with ENROLL_KEY_PREFIX / ENROLL_ATTEMPTS_PREFIX keys;
        #  decode with self._decode(reply, PendingEnrollment).

    async def register_enrollment_failure(self, token: str) -> int:
        """Same atomic budget as challenges (five attempts), ENROLL_* keys.
        Never extends the 5-minute absolute TTL."""
        # FILL IN: eval _REGISTER_FAILURE_LUA with ENROLL_KEY_PREFIX/ENROLL_ATTEMPTS_PREFIX keys.
```

**Why** `session_hash` and not the session id: the record is readable by anyone
who can read Redis; the raw session id is a bearer credential. **Why** one Lua
script for both budgets: identical semantics, one place to get them right.

### `navigator_auth/mfa/limiter.py` — CREATE

```python
"""StrictRateLimiter — fixed-window Redis counter that fails CLOSED (FEAT-106, spec M2).

Deliberately NOT a reuse of handlers/recovery/limiter.py:28, whose check()
returns True on a Redis error ("Fail-open by design", :35). For a second
factor that is a security hole (spec R5).
"""
import hashlib
import logging

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from navigator_auth.backends.oauth2.dcr import parse_rate_limit

logger = logging.getLogger("navigator.mfa")

RATE_KEY_PREFIX = "auth:mfa:rate:"

# KEYS[1] = counter key, ARGV[1] = window seconds. Returns the new count.
# INCR and the first-hit EXPIRE in one atomic step (no TTL-less counter can survive a crash).
_INCR_WINDOW_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""


def _hash_key(value: str) -> str:
    """Never place a raw username/IP in Redis."""
    return hashlib.sha256(str(value).strip().lower().encode("utf-8")).hexdigest()


class StrictRateLimiter:
    """Fixed-window counter (INCR + first-hit EXPIRE in one Lua call). Fails CLOSED."""

    def __init__(self, pool: aioredis.ConnectionPool, spec: str, prefix: str):
        self._pool = pool
        self._prefix = prefix
        self._count, self._window = parse_rate_limit(spec)
        # FILL IN: when spec is a non-empty string and (count, window) == (0, 0),
        #  logger.warning("StrictRateLimiter %r: unparseable spec %r — limiting disabled", prefix, spec)
        #  — bounded by D19 (disabled, not blocked; visible).

    async def check(self, key: str) -> bool:
        """True when allowed. A storage error returns False."""
        if self._count <= 0:
            return True        # (0, 0) == limiting disabled (D19)
        redis_key = f"{RATE_KEY_PREFIX}{self._prefix}:{_hash_key(key)}"
        # FILL IN: async with aioredis.Redis(connection_pool=self._pool) as r:
        #  current = int(await r.eval(_INCR_WINDOW_LUA, 1, redis_key, self._window)).
        #  On RedisError: logger.warning("StrictRateLimiter %r: storage error,
        #  refusing: %s", self._prefix, type(err).__name__); return False.
        #  return current <= self._count.
```

**Why** one Lua call: the recovery limiter's two round-trips (`INCR`, then
`EXPIRE` if 1) can leave a counter without a TTL if the process dies in
between — permanent lock-out of that key. Doing both inside one script makes
that impossible, and (as in the store) keeps `.execute(` out of the package (D25 gate).

### `tests/test_mfa_challenge_store.py` — CREATE

```python
"""FEAT-106 TASK-131 — MfaChallengeStore + StrictRateLimiter against real Redis."""
import asyncio

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from navigator_auth.conf import REDIS_AUTH_URL
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.limiter import StrictRateLimiter
from navigator_auth.mfa.store import (
    ATTEMPTS_KEY_PREFIX, CHALLENGE_KEY_PREFIX, ENROLLMENT_TTL, MfaChallengeStore, _hash_token,
)

SECRET = b"test-mfa-store-secret"
USER = {"user_id": 731001, "username": "mfa_store_user"}


@pytest_asyncio.fixture
async def redis_pool():
    # FILL IN: ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True); purge
    #  "auth:mfa:*" before and after (scan_iter); disconnect (pattern:
    #  tests/test_password_recovery.py:85-91).


@pytest_asyncio.fixture
async def broken_redis_pool():
    # FILL IN: unreachable host, socket_connect_timeout=1 (test_password_recovery.py:111-124).


@pytest.fixture
def store(redis_pool):
    return MfaChallengeStore(redis_pool, SECRET, ttl=60, max_attempts=5)


async def _issue(store, **kw):
    return await store.issue(USER, ["email"], "email", security_version=0,
                             context_digest="d" * 64, email_code_hash=kw.get("h", "a" * 64))


@pytest.mark.asyncio
async def test_challenge_keyed_by_hash_only(store, redis_pool):  # spec §4 M2
    # FILL IN: no Redis key contains the raw token; CHALLENGE_KEY_PREFIX+_hash_token(token) exists.

@pytest.mark.asyncio
async def test_challenge_single_use(store):  # spec §4 M2
    # FILL IN: consume -> record; second consume -> None.

@pytest.mark.asyncio
async def test_challenge_hmac_tamper_rejected(store, redis_pool):  # spec §4 M2
    # FILL IN: rewrite the stored JSON with user_id changed -> peek/consume return None.

@pytest.mark.asyncio
async def test_challenge_retry_budget(store):  # spec §4 M2 part (4 keep, 5th burns)
    # FILL IN: register_failure x4 -> 4,3,2,1 and peek still works; 5th -> 0 and peek None;
    #  6th -> -1; no attempts key left behind.

@pytest.mark.asyncio
async def test_attempt_budget_burns_challenge(store):  # spec §4 M2
    # FILL IN: after max failures the challenge cannot be consumed.

@pytest.mark.asyncio
async def test_expiry_during_verification(redis_pool):  # spec §4 M2 part
    # FILL IN: ttl=1 store; sleep past expiry; consume -> None; register_failure -> -1;
    #  neither record nor counter key exists afterwards (never recreated).

@pytest.mark.asyncio
async def test_resend_preserves_budget_and_expiry(store, redis_pool):  # spec §4 M2 part
    # FILL IN: 2 failures; PTTL before; replace_email_code -> new hash, valid HMAC;
    #  PTTL not increased; next register_failure returns 2 (budget kept).

@pytest.mark.asyncio
async def test_concurrent_verify_consumes_once(store):  # spec §4 M2 part (store half)
    # FILL IN: asyncio.gather 10x consume(token) -> exactly one non-None.

@pytest.mark.asyncio
async def test_totp_step_replay_guard(store):  # store half of test_totp_replay_rejected
    # FILL IN: mark_totp_step(u, s, 90) True then False; other step True.

@pytest.mark.asyncio
async def test_enrollment_ttl_absolute_and_single_use(store, redis_pool):  # store half of test_totp_pending_seed_isolated
    # FILL IN: put_enrollment; PTTL <= ENROLLMENT_TTL*1000; failures never raise PTTL;
    #  consume_enrollment once -> record, again -> None; sealed_seed round-trips (base64).

@pytest.mark.asyncio
async def test_store_fails_closed(broken_redis_pool):  # AC12 store half
    # FILL IN: issue/peek/consume/register_failure/mark_totp_step all raise MfaStorageError.

@pytest.mark.asyncio
async def test_strict_limiter_fails_closed(broken_redis_pool):  # spec §4 M2
    # FILL IN: StrictRateLimiter(broken, "10/hour", "user").check("u") is False.

@pytest.mark.asyncio
async def test_strict_limiter_window(redis_pool):
    # FILL IN: "2/hour": True, True, False; key has a TTL (first-hit EXPIRE applied inside the Lua script).
```

### Steps (in order)

1. Confirm TASK-129 landed (`MfaStorageError`, `MfaChallenge`, `PendingEnrollment` importable).
2. Write `store.py` blocks 1→4 (one file); fill `_user_field` and `_decode` first —
   every other method uses them.
3. Fill the Lua body; run `test_challenge_retry_budget` and
   `test_expiry_during_verification` before anything else that depends on it.
4. Fill the remaining methods; run the matching test after each.
5. Write `limiter.py`; fill the warning and `check`.
6. Run the full Test Specification, including the D5 regression test.

### FILL IN checklist

- [ ] `_user_field` — dict and Model records; ValueError when missing
- [ ] `_decode` — HMAC compare_digest; malformed/tampered → None, no secret in the log
- [ ] `issue` SET NX EX — collision/RedisError → MfaStorageError
- [ ] `peek`, `consume` (`_CONSUME_LUA`), `discard`, `remaining_ttl`
- [ ] `_REGISTER_FAILURE_LUA` body — steps 1-4, expiry preserved, never recreate
- [ ] `register_failure`, `register_enrollment_failure`
- [ ] `replace_email_code` — re-sign, XX + KEEPTTL, counter untouched — AC30/AC31
- [ ] `mark_totp_step` — NX EX, error never True — AC13
- [ ] `put_enrollment`, `peek_enrollment`, `consume_enrollment`
- [ ] `StrictRateLimiter.__init__` warning (D19) and `check` (`_INCR_WINDOW_LUA`, fail closed)
- [ ] Two local fixtures + thirteen test bodies

---

## Acceptance Criteria

- [ ] **AC-1** Redis holds only `sha256(token)`-derived keys under `auth:mfa:`; no raw challenge or enrolment token is ever a key or a logged value (part of spec **AC14**).
- [ ] **AC-2** Challenge and enrolment records carry an HMAC over their canonical immutable fields; any mutation makes `peek`/`consume` return `None`.
- [ ] **AC-3** `consume()` is single-use under concurrency: N parallel calls yield exactly one record (store half of spec **AC31**).
- [ ] **AC-4** `register_failure()` is atomic: attempts 1..4 keep the challenge, the 5th deletes record and counter; an absent record returns -1 and nothing is recreated; the record's TTL is never changed (spec **AC31** store half).
- [ ] **AC-5** `replace_email_code()` re-signs the record, keeps its TTL (`KEEPTTL`) and leaves the attempt counter untouched; returns `None` if the record expired (spec **AC30** store half).
- [ ] **AC-6** `mark_totp_step()` returns `False` for an already-accepted `(user, step)` (store half of spec **AC13**).
- [ ] **AC-7** Pending enrolments expire after at most 300 s, are single-use, and no operation extends their TTL (store half of spec **AC29**).
- [ ] **AC-8** Every store method raises `MfaStorageError` on a Redis error; `StrictRateLimiter.check()` returns `False` on a Redis error (store/limiter half of spec **AC12**).
- [ ] **AC-9** Nothing under `navigator_auth/handlers/recovery/` is imported or modified.
- [ ] **AC-10** `pytest tests/test_mfa_challenge_store.py tests/test_mfa_types.py -v` passes; `ruff check navigator_auth/mfa/store.py navigator_auth/mfa/limiter.py tests/test_mfa_challenge_store.py` is clean.
- [ ] **AC-11** `grep -n "\.execute(" navigator_auth/mfa/store.py navigator_auth/mfa/limiter.py` prints nothing — atomic multi-command steps are Lua scripts, not pipelines (D25 gate).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_challenge_store.py -v
pytest tests/test_mfa_types.py -q          # D5 regression over store.py / limiter.py
ruff check navigator_auth/mfa/store.py navigator_auth/mfa/limiter.py tests/test_mfa_challenge_store.py
grep -rn "handlers.recovery\|handlers/recovery" navigator_auth/mfa/ ; test $? -eq 1
grep -n "\.execute(" navigator_auth/mfa/store.py navigator_auth/mfa/limiter.py ; test $? -eq 1   # D25 gate
```

Spec §4 rows owned (fully or the store half): `test_challenge_keyed_by_hash_only`, `test_challenge_single_use`,
`test_challenge_hmac_tamper_rejected`, `test_attempt_budget_burns_challenge`, `test_strict_limiter_fails_closed` (all M2);
store halves of `test_challenge_retry_budget`, `test_resend_preserves_budget_and_expiry`, `test_expiry_during_verification`,
`test_concurrent_verify_consumes_once`, `test_totp_replay_rejected`, `test_totp_pending_seed_isolated`.

---

## Agent Instructions

1. **Read the spec** — §3 M2, §3 "Security contracts" (Pending enrollment; Challenge validity; Retry accounting), §7 R5, AC12/AC13/AC29-AC31.
2. **Check dependencies** — TASK-129 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Apply the fail-closed rule to every method — no `except Exception: return None`.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-131-mfa-challenge-store.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: gpt-5.6-luna (codex), 1 attempt
**Date**: 2026-11-11
**Notes**: MFA challenge store delivered; merge-tier validation green.

**Deviations from spec**: `issue()` takes keyword-only `security_version`/`context_digest`/`email_code_hash`
(spec skeleton lists only `user, providers, preferred`, but `MfaChallenge` requires them); enrolment storage,
`replace_email_code`, `discard`, `remaining_ttl` added per the FEAT-106 task contract §3. List anything else here.
