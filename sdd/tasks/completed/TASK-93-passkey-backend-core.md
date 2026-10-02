# TASK-93: `PasskeyAuth` core — lifecycle, routes, challenge store, decoys, payload

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 5, §2 Overview items 1–2, §7 R1/R9, AC1, AC2, AC14)
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-86, TASK-87, TASK-88, TASK-89
**Assigned-to**: unassigned

---

## Context

This is the skeleton of the new backend. It holds everything the ceremonies share:
- startup and cleanup: the lazy `webauthn` import, the Redis pool, `PasskeyStore`, the migration and the RP resolver;
- route registration;
- the single-use challenge store;
- deterministic decoy ids;
- the fail-fast `get_payload`.

The ceremonies are filled in by TASK-94 (enrollment) and TASK-95 (sign-in). Management is TASK-96.

Module 5 is **not** delegation-eligible (spec §3): it is security-sensitive, so review it closely.

---

## Scope

- Create `navigator_auth/backends/passkey.py` with `PasskeyUser(AuthUser)` and `PasskeyAuth(BasicAuth)`.
- `configure(app)`:
  - build `RelyingPartyResolver(auth_conf.PASSKEY_RELYING_PARTIES)` (`ConfigError` on an empty map, AC1);
  - register `POST /api/v1/auth/passkey/register/options`, `.../register/verify` and `.../login/options`;
  - append **only** `login/options` to `app[AUTH_EXCLUDE_LIST_KEY]`;
  - call `super().configure(app)`.
- `on_startup(app)`:
  - `await super().on_startup(app)`, because `access_token_storage` is load-bearing;
  - import `webauthn` lazily into `self._webauthn` (`ConfigError` if missing, AC1);
  - create the Redis pool like `ExternalAuth`;
  - create `self._store = PasskeyStore(app["authdb"])`;
  - `await setup_passkey_tables(app["authdb"])`.
- `on_cleanup(app)`: disconnect the pool, then `await super().on_cleanup(app)`.
- `_save_challenge` / `_pop_challenge`:
  - Redis `SETEX` with `PASSKEY_CHALLENGE_TTL`, under the key `passkey_{kind}_{key}`, holding the `ChallengeState` JSON;
  - consume with `GETDEL`;
  - a missing key raises `InvalidAuth("Passkey: ceremony expired", status=401)` (E1, E2);
  - Redis errors are wrapped in `AuthException` (R1).
- `_decoy_ids(rp, username)`: `PASSKEY_DECOY_CREDENTIALS` ids, each
  `HMAC-SHA256(SECRET_KEY, rp_id + "\x00" + username.casefold() + "\x00" + str(i))`. The result
  is deterministic, and differs per RP (E5).
- `_session_user(request)`: `request.get("authenticated")`, else `raise self.Unauthorized(...)`; return `request.user`.
- `get_payload(request) -> (challenge_id, credential)`: fail fast with `InvalidAuth(401)` and **no**
  I/O when the body is not JSON or lacks either field (E11, R1).
- Handler stubs `register_options`, `register_verify`, `login_options` and `authenticate`, each
  raising `web.HTTPNotImplemented`. TASKS 94 and 95 replace them.
- Export `PasskeyAuth` from `navigator_auth/backends/__init__.py`. The module must import without
  `webauthn` installed (AC2, R9).
- Write `tests/test_passkey_backend_unit.py`.

**NOT in scope**: the ceremony logic (TASKS 94 and 95), the management routes (TASK-96), and any `auth.py` change (AC14).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/passkey.py` | CREATE | Backend core |
| `navigator_auth/backends/__init__.py` | MODIFY | Export `PasskeyAuth` |
| `tests/test_passkey_backend_unit.py` | CREATE | Unit tests: payload, decoys, config, lazy import |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
import redis.asyncio as aioredis                         # backends/external.py:18, azure.py:14
from aiohttp import web
from .. import conf as auth_conf                         # read PASSKEY_* / SECRET_KEY / REDIS_AUTH_URL at call time
from ..conf import AUTH_EXCLUDE_LIST_KEY                 # conf.py:47
from ..exceptions import AuthException, ConfigError, InvalidAuth   # exceptions.py:3, :26, :42
from ..identities import AuthUser                        # identities.py:95 (basic.py:27 imports it)
from ..passkey import ChallengeState, PasskeyStore, RelyingParty, RelyingPartyResolver   # TASKS 87–89
from ..passkey.migrations import setup_passkey_tables    # TASK-87
from .basic import BasicAuth                             # basic.py:43; backends/__init__.py:6
```

### Existing Signatures to Use
```python
class BasicAuth(BaseAuthBackend):                         # basic.py:43
    def configure(self, app)                              # :52 — registers check_credentials, appends to app[AUTH_EXCLUDE_LIST_KEY], super().configure
    async def on_startup(self, app)                       # :64 — self.access_token_storage = AccessTokenStorage(); callbacks
    async def on_cleanup(self, app)                       # :76 — closes access_token_storage.redis
    async def open_session(self, request, user, extra=None, expiration=None) -> dict   # :171
class BaseAuthBackend:
    self._idp      # IdentityProvider                     # abstract.py:112
    self.logger    # logging.getLogger(f"Auth.{self._service}")   # abstract.py:100
    def Unauthorized(self, reason, **kwargs) -> web.HTTPError   # abstract.py:248 — RETURNS; caller must `raise`
# Redis pool pattern — backends/external.py:184-193:
self._pool = aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
async with aioredis.Redis(connection_pool=self._pool) as redis: ...       # azure.py:214
await self._pool.disconnect(inuse_connections=True)                        # on_cleanup
# Session-gate pattern — auth.py:454-461:
if not request.get("authenticated", False):
    raise self.Unauthorized(reason="Access Denied")
user = request.user   # user.user_id
# Fallback loop — auth.py:484-490: catches (AuthException, UserNotFound, InvalidAuth, FailedAuth) → continue;
#   any other Exception aborts the whole login → get_payload must raise InvalidAuth before I/O (R1).
```
- Backends load from `AUTHENTICATION_BACKENDS` dotted paths (`conf.py:192-196`), e.g.
  `navigator_auth.backends.PasskeyAuth`. `AuthHandler.setup` calls `backend.configure(app)`
  (`auth.py:729`) and `auth_startup` → `on_startup` (`auth.py:174`).

### Does NOT Exist
- `navigator_auth/backends/passkey.py`, `PasskeyAuth` and `PasskeyUser`.
- A module-level `exclude_list` read by the middleware. Use `app[AUTH_EXCLUDE_LIST_KEY]`.
- A Redis `GETDEL` helper in the repo. Call `redis.getdel(key)` (redis-py ≥ 4, server ≥ 6.2, Q8).
- A module-level `import webauthn`. **Forbidden**, because it breaks installs without the extra (R9).

---

## Implementation Blueprint

### Steps (in order)
1. Write the module header and `PasskeyUser`, then the class attributes and `configure`. Build the
   resolver in `configure` so an empty map fails at app setup, before serving (AC1).
2. Write `on_startup` and `on_cleanup`. Call `super()` first in startup and last in cleanup:
   startup needs `access_token_storage` before anything can call `open_session`.
3. Write the challenge helpers, decoys, session gate and `get_payload`.
4. Write the handler stubs and the export, then the unit tests.

### `navigator_auth/backends/passkey.py` — CREATE (part 1: lifecycle)
```python
"""PasskeyAuth — WebAuthn passkey authentication backend (FEAT-101).

`webauthn` (optional extra ``navigator-auth[passkey]``) is imported lazily in
``on_startup``; importing this module never requires it.
"""
import hashlib
import hmac
import secrets
from typing import Any

import redis.asyncio as aioredis
from aiohttp import web

from .. import conf as auth_conf
from ..conf import AUTH_EXCLUDE_LIST_KEY
from ..exceptions import AuthException, ConfigError, InvalidAuth
from ..identities import AuthUser
from ..passkey import ChallengeState, PasskeyStore, RelyingParty, RelyingPartyResolver
from ..passkey.migrations import setup_passkey_tables
from .basic import BasicAuth

PASSKEY_PREFIX = "/api/v1/auth/passkey"


class PasskeyUser(AuthUser):
    """User authenticated with a WebAuthn passkey."""


class PasskeyAuth(BasicAuth):
    """Passkey (WebAuthn) authentication; sign-in goes through POST /api/v1/login."""

    _ident: AuthUser = PasskeyUser
    _description: str = "Passkey (WebAuthn) authentication"
    _service_name: str = "passkey"

    def configure(self, app: web.Application) -> None:
        """Register ceremony routes and build the RP resolver (ConfigError if the map is empty)."""
        self._resolver = RelyingPartyResolver(auth_conf.PASSKEY_RELYING_PARTIES)
        router = app.router
        router.add_route("POST", f"{PASSKEY_PREFIX}/register/options", self.register_options,
                         name="passkey_register_options")
        router.add_route("POST", f"{PASSKEY_PREFIX}/register/verify", self.register_verify,
                         name="passkey_register_verify")
        router.add_route("POST", f"{PASSKEY_PREFIX}/login/options", self.login_options,
                         name="passkey_login_options")
        app[AUTH_EXCLUDE_LIST_KEY].append(f"{PASSKEY_PREFIX}/login/options")
        super().configure(app)

    async def on_startup(self, app: web.Application) -> None:
        """BasicAuth startup, lazy webauthn import, Redis pool, store and migration."""
        await super().on_startup(app)
        try:
            import webauthn  # pylint: disable=C0415
        except ImportError as err:
            raise ConfigError(
                "PasskeyAuth requires the optional extra: pip install navigator-auth[passkey]"
            ) from err
        self._webauthn = webauthn
        self._pool = aioredis.ConnectionPool.from_url(
            auth_conf.REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        self._store = PasskeyStore(app["authdb"])
        await setup_passkey_tables(app["authdb"])

    async def on_cleanup(self, app: web.Application) -> None:
        """Disconnect the Redis pool, then BasicAuth cleanup."""
        pool = getattr(self, "_pool", None)
        if pool is not None:
            try:
                await pool.disconnect(inuse_connections=True)
            except Exception as err:  # pylint: disable=W0703
                self.logger.warning(f"PasskeyAuth: error closing Redis pool: {err}")
        await super().on_cleanup(app)
```
**Why**: Reading `auth_conf.<NAME>` at call time, instead of `from ..conf import PASSKEY_*`, lets
tests patch `navigator_auth.conf` (TASK-90). `BasicAuth.configure` also registers
`/auth/passkey/check_credentials`, which is harmless.

### `navigator_auth/backends/passkey.py` — CREATE (part 2: shared helpers and stubs)
```python
    def _challenge_key(self, kind: str, key: str) -> str:
        return f"passkey_{kind}_{key}"

    async def _save_challenge(self, kind: str, key: str, state: ChallengeState) -> None:
        """SETEX the ceremony state for PASSKEY_CHALLENGE_TTL seconds."""
        # FILL IN: async with aioredis.Redis(connection_pool=self._pool) as redis:
        #          await redis.setex(key, ttl, state.model_dump_json()); wrap redis errors in
        #          AuthException(status=500) — bounded by R1.

    async def _pop_challenge(self, kind: str, key: str) -> ChallengeState:
        """GETDEL; missing ⇒ InvalidAuth('Passkey: ceremony expired', status=401)."""
        # FILL IN: getdel → None ⇒ InvalidAuth; else ChallengeState.model_validate_json(raw).
        #          Redis errors → AuthException (R1). Single use = E1; TTL expiry = E2.
        raise NotImplementedError

    def _decoy_ids(self, rp: RelyingParty, username: str) -> list[bytes]:
        """Deterministic fake credential ids for unknown users (E5)."""
        secret = auth_conf.SECRET_KEY
        key = secret if isinstance(secret, bytes) else str(secret).encode()
        # FILL IN: for i in range(auth_conf.PASSKEY_DECOY_CREDENTIALS):
        #          hmac.new(key, f"{rp.rp_id}\x00{username.casefold()}\x00{i}".encode(), hashlib.sha256).digest()
        #          bounded by test_decoy_ids_deterministic (same input → same ids; other RP → different).
        raise NotImplementedError

    def _session_user(self, request: web.Request):
        """Return ``request.user`` for a live session, else raise 401 (E12)."""
        if not request.get("authenticated", False):
            raise self.Unauthorized(reason="Passkey: a session is required")
        return request.user

    async def get_payload(self, request: web.Request) -> tuple[str, dict]:
        """Return ``(challenge_id, credential)``; InvalidAuth(401) with no I/O when absent (E11)."""
        # FILL IN: require content_type application/json; await request.json() inside try
        #          (ValueError → InvalidAuth); both fields present and of type str/dict, else
        #          InvalidAuth("Passkey: missing assertion", status=401). No Redis/DB access here.
        raise NotImplementedError

    async def register_options(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="TASK-94")

    async def register_verify(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="TASK-94")

    async def login_options(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="TASK-95")

    async def authenticate(self, request: web.Request) -> dict:
        """Sign-in (TASK-95). Until then: fail fast so the api_login fallback loop continues."""
        await self.get_payload(request)
        raise InvalidAuth("Passkey: not implemented", status=401)
```
**Why**: An `authenticate` that raises `InvalidAuth` keeps `api_login`'s header-less fallback loop
safe even before TASK-95 lands (R1, `test_fallback_loop_unaffected`).

### `navigator_auth/backends/__init__.py` — MODIFY
```python
# AFTER — insert below `from .exchange import TokenExchangeAuth` (verified: backends/__init__.py:18; occurrences: 1)
from .passkey import PasskeyAuth
# AFTER — insert below `    "TokenExchangeAuth",` in __all__ (verified: :45; occurrences: 1)
    "PasskeyAuth",
```

### `tests/test_passkey_backend_unit.py` — CREATE
```python
"""FEAT-101 TASK-93 — PasskeyAuth core (no Redis/DB)."""
import subprocess
import sys

import pytest

from navigator_auth.exceptions import ConfigError, InvalidAuth


def test_backends_import_without_webauthn():
    """AC2/R9: importing navigator_auth.backends works when webauthn is unimportable."""
    # FILL IN: subprocess python -c with sys.modules['webauthn'] = None before
    #          `import navigator_auth.backends`; assert returncode 0.


async def test_get_payload_fast_fail():
    """E11: missing assertion → InvalidAuth before any Redis/DB access."""
    # FILL IN: backend with _pool/_store set to objects that fail on any attribute access;
    #          make_mocked_request with an empty JSON body; pytest.raises(InvalidAuth).


def test_decoy_ids_deterministic(passkey_rp_config):
    """Same RP + username → same ids (casefold); other RP → different ids; count = setting."""


def test_configure_empty_rp_map_raises(monkeypatch):
    """AC1: an empty PASSKEY_RELYING_PARTIES → ConfigError at configure()."""


async def test_on_startup_without_webauthn_raises(monkeypatch):
    """AC1: webauthn missing → ConfigError at on_startup (patch sys.modules['webauthn'] = None)."""
```
Import the fixtures with `from tests.fixtures.passkey import passkey_rp_config  # noqa: F401`.
Construct the backend the way `tests/test_oauth2_upstream_idp.py:52-58` does, with `MagicMock` collaborators.

### FILL IN checklist
- [ ] `_save_challenge` and `_pop_challenge` with R1 wrapping.
- [ ] `_decoy_ids`.
- [ ] `get_payload` validation.
- [ ] Five unit tests.

---

## Acceptance Criteria

- [ ] AC1: `ConfigError` on an empty RP map (configure) and on missing `webauthn` (startup).
- [ ] AC2: `import navigator_auth.backends` works without `webauthn`.
- [ ] AC14: `auth.py` is untouched (`git diff --stat navigator_auth/auth.py` is empty).
- [ ] `pytest tests/test_passkey_backend_unit.py -v` passes.
- [ ] `ruff check navigator_auth/backends/passkey.py navigator_auth/backends/__init__.py tests/test_passkey_backend_unit.py` is clean.

---

## Test Specification

See the blueprint above (spec §4: `test_get_payload_fast_fail`, `test_decoy_ids_deterministic`).

---

## Agent Instructions

1. Read the spec (Module 5, §2 items 1–2, R1, R9) and TASK-86's verified py_webauthn block in spec §6.
2. Confirm TASKS 86 to 89 are in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Sonnet 5.5, sequential fallback)
**Date**: 2026-10-02
**Notes**: Backend core with lifecycle, routes, challenge store, decoys, get_payload; handler stubs for 94/95. 16 unit tests pass; auth.py untouched. Note: pre-existing auth_error passes deprecated body= to aiohttp (test ignores that warning).
**Deviations from spec**: none
