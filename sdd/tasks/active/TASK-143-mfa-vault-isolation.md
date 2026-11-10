# TASK-143: Reserved `mfa:` vault namespace — HTTP rejection + filtered session-vault loader

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-129
**Assigned-to**: unassigned

---

## Context

Implements the **spec §3 Security contracts — "Protected seed namespace"**
paragraph (part of M10's "Additional integration scope") and closes **AC28**.

The TOTP seed (TASK-136) lives in the *same* table the general Session Vault
uses — `auth.user_vault_secrets`, key `mfa:totp` — sealed under its own
`purpose="mfa"` AAD context. Without this task, three things go wrong:

1. **The general vault HTTP API is an alternative enrolment route.**
   `POST /api/v1/user/vault {"key": "mfa:totp", "value": …}` reaches
   `SessionVault.set()`, whose upsert is
   `ON CONFLICT (user_id, key) WHERE deleted_at IS NULL DO UPDATE` — it would
   **overwrite the active seed** with attacker-chosen bytes. `DELETE` would
   soft-delete it (silently disabling the factor), and `GET`/listing would
   reveal enrolment state.
2. **Every login decrypts — and fails on — the seed.** `api_login` calls
   `load_vault_for_session()` (`auth.py:526-535`), which calls
   `SessionVault.load_for_session()`. In the installed `navigator-session`
   1.1.1 that loader **eagerly opens every active row**
   (`session_vault.py:409-500`, `SELECT … WHERE user_id = $1 AND deleted_at IS NULL`).
   The seed's `purpose="mfa"` context cannot open under the vault's
   `"user-vault"` context, so each login of an enrolled user would log an
   integrity error and write an `integrity_fail` audit row.
3. **A seed must never be exported to session-vault consumers** (agents,
   integrations reading `request.vault`).

The spec's instruction is explicit: *"If the session vault loader eagerly opens
all rows, it must exclude reserved MFA rows before decryption. Implement the
filtering in the navigator-auth vault integration adapter if the installed vault
API cannot filter them directly … do not silently change an external dependency."*
The installed API cannot filter (`_SELECT_ALL_ACTIVE` is a module constant), so
this task adds a navigator-auth subclass that re-implements only the loader with
a filtered `SELECT`, and rejects reserved keys in `_validate_key` (which upstream
calls from `set`/`get`/`delete`).

---

## Scope

- Create `navigator_auth/vault/reserved.py`: `is_reserved_key()` and
  `ReservedPrefixSessionVault(SessionVault)` overriding `_validate_key` and
  `load_for_session` (filtered SELECT; reserved rows never decrypted; an
  in-loop belt-and-braces skip as well).
- Modify `navigator_auth/vault/integration.py` so the loader used by
  `load_vault_for_session()` (and therefore `get_session_vault()` and
  `api_login`) is the filtered subclass.
- Modify `navigator_auth/handlers/vault.py`: reserved keys answer
  **400 `{"error": "reserved_key"}`** on `GET /vault/{key}`, `POST` and
  `DELETE`; listings omit them.
- Write `tests/test_mfa_vault_isolation.py`, including a drift guard on the
  upstream loader this task re-implements.

**NOT in scope**:
- Sealing/reading/installing the seed — TASK-136 (it writes the row directly,
  not through `SessionVault`).
- Any change to `navigator_session` (external dependency — explicitly forbidden).
- Changing the vault's per-user key limit, audit table or Redis layout.
- Any other `mfa:`-prefixed storage (only the vault table is shared).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/vault/reserved.py` | CREATE | `is_reserved_key`, `ReservedPrefixSessionVault` |
| `navigator_auth/vault/integration.py` | MODIFY | Bind the loader to the filtered subclass |
| `navigator_auth/handlers/vault.py` | MODIFY | 400 `reserved_key` on GET-key/POST/DELETE; filter listings |
| `tests/test_mfa_vault_isolation.py` | CREATE | AC28 tests + upstream drift guard |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` against installed **navigator-session 1.1.1**
> (2026-11-11). Every import below was **executed** in the project venv.

### Verified Imports

```python
from navigator_session.vault import KeyRing                                   # used by integration.py:17
from navigator_session.vault.envelope import open_sealed
#   open_sealed(blob, context, keyring, *, session_uuid=None) -> bytes        — executed
from navigator_session.vault.models import VaultSecretMetadata                # executed
from navigator_session.vault.session_vault import INTEGRITY_ERRORS, SessionVault
#   INTEGRITY_ERRORS == (VaultIntegrityError, UnknownKeyVersionError, UnsupportedFormatError)  — executed
from navigator_session.vault.targets.postgres import acquire_connection, fetch_rows
#   acquire_connection(pool) -> AsyncIterator[conn] (async context manager)  — executed
#   fetch_rows(conn, sql, *args) -> list                                      — executed
from navigator_auth.mfa.types import MFA_VAULT_PREFIX                         # TASK-129 == "mfa:"
from navigator_auth.vault.reserved import ReservedPrefixSessionVault, is_reserved_key   # this task
```

Tests additionally use (all executed): `from navigator_session.vault import seal_value`,
`from navigator_session.vault.session_vault import _SELECT_ALL_ACTIVE`,
`from navigator_session.vault.crypto import deserialize_value`.

### Upstream code being re-implemented — `navigator_session/vault/session_vault.py` (1.1.1)

```python
PURPOSE = "user-vault"                                           # :48
INTEGRITY_ERRORS = (VaultIntegrityError, UnknownKeyVersionError, UnsupportedFormatError)  # :52
_SELECT_ALL_ACTIVE = """
SELECT key, ciphertext_db, key_version, updated_at
FROM auth.user_vault_secrets
WHERE user_id = $1 AND deleted_at IS NULL
"""                                                              # :75-79

class SessionVault:
    def __init__(self, session_uuid: str, user_id: int, db_pool: Any, redis: Any = None,
                 session_ttl: int = 3600, *, keyring: Optional[KeyRing] = None)    # :158
    def _validate_key(self, key: str) -> None                    # :189 — called by set (:291), get (:334), delete (:365)
    def _db_context(self, key: str) -> VaultContext              # :204
    def _seal_session(self, plaintext: bytes, key: str) -> bytes # :216
    async def _redis_set(self, key: str, ciphertext_mem: bytes) -> None   # :237
    async def _audit(self, conn, key, operation, key_version=None) -> None  # :257
    async def keys(self) -> list[str]        # :377 — returns list(self._cache)
    async def exists(self, key) -> bool      # :385 — key in self._cache
    async def list_metadata(self)            # :396 — from self._metadata ∩ self._cache
    @classmethod
    async def load_for_session(cls, session_uuid, user_id, db_pool, redis=None,
                               session_ttl=3600, *, keyring=None) -> "SessionVault"   # :409-500
```

The body of `load_for_session` (`:434-500`), which this task copies with a
filtered SELECT, is: build `vault = cls(...)`; `async with acquire_connection(db_pool) as conn: rows = await fetch_rows(conn, _SELECT_ALL_ACTIVE, vault._user_id)`;
for each row: `open_sealed(bytes(row["ciphertext_db"]), vault._db_context(key), vault._keyring)`
(on `INTEGRITY_ERRORS` → `logger.error(...)`, append `(key, row["key_version"])` to
`failures`, `continue`); then `ciphertext_mem = vault._seal_session(plaintext, key)`,
`vault._cache[key] = ciphertext_mem`, `await vault._redis_set(key, ciphertext_mem)`,
`vault._metadata[key] = VaultSecretMetadata(key=key, updated_at=row["updated_at"] or datetime.now(timezone.utc), key_version=row["key_version"])`
(any other exception → `vault._cache.pop(key, None)` + `logger.error`); if `failures`:
one more `acquire_connection` and `await vault._audit(conn, key, "integrity_fail", key_version)`
per failure (errors logged, never raised); final `logger.info(...)`; `return vault`.

### navigator-auth sites touched

```python
# navigator_auth/vault/integration.py
from navigator_session.vault.session_vault import SessionVault           # :18   (1 occurrence)
from .migrations import ensure_vault_tables                              # :19
async def load_vault_for_session(...) -> Optional[SessionVault]:         # :50
        vault = await SessionVault.load_for_session(                     # :87   (1 occurrence)
async def get_session_vault(request, session, user_id) -> Optional[SessionVault]:   # :116 (calls load_vault_for_session)

# navigator_auth/handlers/vault.py
from navigator_auth.vault import VAULT_SESSION_KEY, get_session_vault    # :21
from navigator_auth.responses import JSONResponse, json_error as _json_error   # :22
VAULT_INTEGRITY_ERROR = "vault_integrity_error"                          # :28  (1 occurrence)
    async def get(self):                                                 # :89
        if key := self.request.match_info.get("key"):                    # :96  (1 occurrence)
        secrets = [_metadata_dict(...) for metadata in await vault.list_metadata()]   # :111 (1 occurrence)
    async def post(self):                                                # :114
            _json_error(400, "'key' is required")                        # :131 (1 occurrence)
    async def delete(self):                                              # :146
            _json_error(400, "Key parameter is required for deletion.") # :155 (1 occurrence)
```

`_json_error(status, message)` **raises** the status-specific aiohttp exception
with body `{"error": message}` (`responses.py:124-140`; verified by the existing
test `tests/unit/vault/test_vault_view.py:118-120`, which asserts
`{"error": "vault_integrity_error"}`).

**Existing tests patch `navigator_auth.vault.integration.SessionVault`**
(`tests/unit/vault/test_integration.py:57, 70, 88, 100, 112, 126, 138`). The
integration change below keeps that module attribute name, bound to the
filtered subclass, so those tests keep patching the class that is actually
called.

`SessionVault` is used **only** in `navigator_auth/vault/integration.py`
(verified: `grep -rn "SessionVault\|load_for_session" navigator_auth` outside
that file → nothing).

Postgres is 17.3 (`starts_with(text, text)` available since 11; verified
`select starts_with('mfa:totp','mfa:')` → true).

### Does NOT Exist (Anti-Hallucination)

- ~~a filter / `exclude_prefix` parameter on `SessionVault.load_for_session`~~ — the SELECT is a module constant; hence the subclass.
- ~~`{schema}.user_vault_secrets`~~ — the vault kernel hard-codes `auth.user_vault_secrets`; keep it literal (match upstream).
- ~~a vault HTTP route other than `/api/v1/user/vault` and `/api/v1/user/vault/{key}`~~ (`auth.py:696-697`).
- ~~`VaultView.patch` / `put`~~ — only `get`, `post`, `delete` exist.
- ~~monkeypatching `navigator_session`~~ — forbidden by the spec ("do not silently change an external dependency").

---

## Implementation Blueprint

### `navigator_auth/vault/reserved.py` — CREATE

```python
"""Session-vault loader that never decrypts reserved MFA rows (FEAT-106).

``auth.user_vault_secrets`` is shared with the MFA package: the sealed TOTP
seed lives there under ``MFA_VAULT_PREFIX`` ("mfa:"), sealed with its own
``purpose="mfa"`` context. The installed navigator-session SessionVault loads
EVERY active row and cannot be told to skip some (its SELECT is a module
constant), so this subclass re-implements ``load_for_session`` with a filtered
SELECT and rejects reserved keys in ``_validate_key`` (used by set/get/delete).

Re-implemented from navigator-session 1.1.1 ``session_vault.py:409-500``;
``tests/test_mfa_vault_isolation.py`` fails if the upstream SELECT changes,
which is the signal to re-sync this copy.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from navigator_session.vault import KeyRing
from navigator_session.vault.envelope import open_sealed
from navigator_session.vault.models import VaultSecretMetadata
from navigator_session.vault.session_vault import INTEGRITY_ERRORS, SessionVault
from navigator_session.vault.targets.postgres import acquire_connection, fetch_rows

from navigator_auth.mfa.types import MFA_VAULT_PREFIX

logger = logging.getLogger("navigator.vault")

_SELECT_ACTIVE_UNRESERVED = """
SELECT key, ciphertext_db, key_version, updated_at
FROM auth.user_vault_secrets
WHERE user_id = $1 AND deleted_at IS NULL AND NOT starts_with(key, $2)
"""


def is_reserved_key(key: Any) -> bool:
    """True for keys in the MFA-reserved namespace (``mfa:``)."""
    return isinstance(key, str) and key.startswith(MFA_VAULT_PREFIX)


class ReservedPrefixSessionVault(SessionVault):
    """SessionVault that cannot read, write, delete or load reserved MFA keys."""

    def _validate_key(self, key: str) -> None:
        """Upstream validation, then refuse the reserved namespace (ValueError)."""
        super()._validate_key(key)
        if is_reserved_key(key):
            raise ValueError("Vault key uses a reserved namespace")

    @classmethod
    async def load_for_session(
        cls,
        session_uuid: str,
        user_id: int,
        db_pool: Any,
        redis: Any = None,
        session_ttl: int = 3600,
        *,
        keyring: Optional[KeyRing] = None,
    ) -> "ReservedPrefixSessionVault":
        """Upstream loader with reserved rows excluded BEFORE decryption."""
        vault = cls(
            session_uuid=session_uuid,
            user_id=user_id,
            db_pool=db_pool,
            redis=redis,
            session_ttl=session_ttl,
            keyring=keyring,
        )
        async with acquire_connection(db_pool) as conn:
            rows = await fetch_rows(conn, _SELECT_ACTIVE_UNRESERVED, vault._user_id, MFA_VAULT_PREFIX)

        failures: list[tuple[str, Optional[int]]] = []
        for row in rows:
            key = row["key"]
            if is_reserved_key(key):
                continue  # belt and braces: never decrypt a reserved row
            try:
                plaintext = open_sealed(bytes(row["ciphertext_db"]), vault._db_context(key), vault._keyring)
            except INTEGRITY_ERRORS as err:
                logger.error(
                    "Vault secret failed integrity check: user=%s key=%s error=%s",
                    vault._user_id, key, type(err).__name__,
                )
                failures.append((key, row["key_version"]))
                continue
            try:
                ciphertext_mem = vault._seal_session(plaintext, key)
                vault._cache[key] = ciphertext_mem
                await vault._redis_set(key, ciphertext_mem)
                vault._metadata[key] = VaultSecretMetadata(
                    key=key,
                    updated_at=row["updated_at"] or datetime.now(timezone.utc),
                    key_version=row["key_version"],
                )
            except Exception as err:  # noqa: BLE001 - one secret must not break login (upstream)
                vault._cache.pop(key, None)
                logger.error(
                    "Failed to load vault secret key=%s for user=%s: %s",
                    key, vault._user_id, type(err).__name__,
                )
        # FILL IN: copy upstream's failure-audit block verbatim (one
        #  acquire_connection, `await vault._audit(conn, key, "integrity_fail",
        #  key_version)` per failure, errors logged at ERROR and never raised)
        #  and the final logger.info(...) summary line — bounded by "same
        #  behaviour as navigator-session 1.1.1 session_vault.py:476-500 except
        #  the filter".
        return vault
```

**Why re-implement instead of post-filtering.** Calling `super().load_for_session()`
and then dropping `mfa:` keys from `_cache` is too late: upstream has already
tried to open the seed under the `"user-vault"` context, failed, logged an
integrity error and written an `integrity_fail` audit row — on every login of
every enrolled user. The spec requires exclusion *before* decryption. The
filter lives in SQL (`NOT starts_with(key, $2)`, bound parameter — no `LIKE`
wildcard pitfalls) and again in the loop, so even a future upstream helper that
returns extra rows cannot reintroduce the decrypt attempt.

**Why `_validate_key`.** Upstream calls it first in `set`, `get` and `delete`,
so one override closes every server-side path (HTTP handler, agents,
integrations) — not just the HTTP routes the handler change below guards.
`keys()`/`exists()`/`list_metadata()` only see `_cache`, which the loader never
populates with reserved keys.

### `navigator_auth/vault/integration.py` — MODIFY (one block)

Replace the import line:

```python
# BEFORE — anchor `from navigator_session.vault.session_vault import SessionVault` (verified: integration.py:18)
# occurrences: 1 (verified: grep -cF 'from navigator_session.vault.session_vault import SessionVault' navigator_auth/vault/integration.py)
from navigator_session.vault.session_vault import SessionVault
```

with:

```python
from .reserved import ReservedPrefixSessionVault

# FEAT-106: the session loader is the filtered subclass, so reserved "mfa:"
# rows (sealed TOTP seeds) are never decrypted into a session vault nor
# writable through it. Bound to the historical name so the call site at
# load_vault_for_session() and existing patch targets
# (tests/unit/vault/test_integration.py) keep working unchanged.
SessionVault = ReservedPrefixSessionVault
```

**Why rebinding the name instead of editing the call site at :87.** The call
`SessionVault.load_for_session(...)` (1 occurrence, :87) and the return
annotations `Optional[SessionVault]` stay correct (the subclass *is* a
`SessionVault`), and seven existing tests patch
`navigator_auth.vault.integration.SessionVault`. Changing the call site to a new
name would leave those tests patching an unused attribute — they would then run
the real loader against a mock pool. The comment makes the indirection explicit.

Also confirm the module docstring's "Provides" list still reads true (it does —
no new public function), and that `navigator_auth/vault/__init__.py` needs no
change (it re-exports functions, not the class).

### `navigator_auth/handlers/vault.py` — MODIFY (five blocks)

**Block 1 — import + error code:**

```python
# AFTER — insert below `from navigator_auth.vault import VAULT_SESSION_KEY, get_session_vault` (verified: vault.py:21)
# occurrences: 1 (verified: grep -cF 'from navigator_auth.vault import VAULT_SESSION_KEY, get_session_vault' navigator_auth/handlers/vault.py)
from navigator_auth.vault.reserved import is_reserved_key
```

```python
# AFTER — insert below `VAULT_INTEGRITY_ERROR = "vault_integrity_error"` (verified: vault.py:28)
# occurrences: 1 (verified: grep -cF 'VAULT_INTEGRITY_ERROR = "vault_integrity_error"' navigator_auth/handlers/vault.py)
VAULT_RESERVED_KEY = "reserved_key"


def _reject_reserved(key: str) -> None:
    """400 for the MFA-reserved namespace (FEAT-106). Raises; never returns on a hit."""
    if is_reserved_key(key):
        _json_error(400, VAULT_RESERVED_KEY)
```

Also extend the module docstring's "Errors:" list with
`- 400 {"error": "reserved_key"} — the key is in the reserved "mfa:" namespace.`

**Block 2 — `get()` single key:**

```python
# AFTER — insert as the FIRST statement inside the block opened by
#   `        if key := self.request.match_info.get("key"):` (verified: vault.py:96)
# occurrences: 1 (verified: grep -cF '        if key := self.request.match_info.get("key"):' navigator_auth/handlers/vault.py)
            _reject_reserved(key)
```

**Block 3 — `get()` listing:**

```python
# REPLACE — `        secrets = [_metadata_dict(metadata, getattr(metadata, "key", "")) for metadata in await vault.list_metadata()]` (verified: vault.py:111)
# occurrences: 1 (verified: grep -cF the line above)
        secrets = [
            _metadata_dict(metadata, getattr(metadata, "key", ""))
            for metadata in await vault.list_metadata()
            if not is_reserved_key(getattr(metadata, "key", ""))
        ]
```

**Block 4 — `post()`:**

```python
# AFTER — insert below `            _json_error(400, "'key' is required")` (verified: vault.py:131), at the
#   SAME indentation as the `if not key:` that precedes it (8 spaces)
# occurrences: 1 (verified: grep -cF "            _json_error(400, \"'key' is required\")" navigator_auth/handlers/vault.py)
        _reject_reserved(key)
```

**Block 5 — `delete()`:**

```python
# AFTER — insert below `            _json_error(400, "Key parameter is required for deletion.")` (verified: vault.py:155),
#   at 8-space indentation (outside the `if not key:` body)
# occurrences: 1 (verified: grep -cF '            _json_error(400, "Key parameter is required for deletion.")' navigator_auth/handlers/vault.py)
        _reject_reserved(key)
```

**Why reject in the handler as well as in `_validate_key`.** Defence in depth
with *distinct* answers: without the handler check, `GET /vault/mfa:totp` would
answer **404** from `vault.exists()` (the loader never caches it), which is
indistinguishable from "no such secret" and invites retries; `DELETE` would also
404; only `POST` would surface the `_validate_key` ValueError (as 400 with the
upstream message). One explicit `400 reserved_key` across all three verbs is a
clear, documented contract and does not depend on the vault object behind it
(the existing tests swap in an `AsyncMock` vault). The ordering — after the
session/vault load, before any vault call — keeps 401/503 semantics for
unauthenticated or vault-less requests unchanged.

### `tests/test_mfa_vault_isolation.py` — CREATE

```python
"""FEAT-106 — reserved "mfa:" vault namespace (spec §3 Protected seed namespace, AC28)."""
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_session import SESSION_OBJECT
from navigator_session.vault import KeyRing, VaultContext, VaultSecretMetadata, seal_value
from navigator_session.vault.session_vault import _SELECT_ALL_ACTIVE

import navigator_auth.vault.reserved as reserved_mod
from navigator_auth.handlers.vault import VaultView
from navigator_auth.vault import integration
from navigator_auth.vault.reserved import ReservedPrefixSessionVault, is_reserved_key

SESSION_UUID = "550e8400-e29b-41d4-a716-446655440000"
UPDATED = datetime(2026, 11, 11, tzinfo=timezone.utc)


@pytest.fixture
def keyring():
    return KeyRing({1: b"\x00" * 32}, 1)


@pytest.fixture
def rows(keyring):
    """One ordinary secret sealed like the vault does, one MFA seed sealed under purpose='mfa'."""
    probe = ReservedPrefixSessionVault(session_uuid=SESSION_UUID, user_id=7, db_pool=None, keyring=keyring)
    ordinary = seal_value("tok-123", probe._db_context("jira:token"), keyring)
    seed_ctx = VaultContext(purpose="mfa", layer="db",
                            fields=(("user_id", 7), ("provider", "totp"), ("key", "mfa:totp")))
    seed = seal_value(b"\x01" * 20, seed_ctx, keyring)
    return [
        {"key": "jira:token", "ciphertext_db": ordinary, "key_version": 1, "updated_at": UPDATED},
        {"key": "mfa:totp", "ciphertext_db": seed, "key_version": 1, "updated_at": UPDATED},
    ]


@pytest.fixture
def fake_db(monkeypatch, rows):
    """Patch the loader's DB helpers in reserved.py; record the SQL and args."""
    calls = []

    @asynccontextmanager
    async def _acquire(pool):
        yield object()

    async def _fetch(conn, sql, *args):
        calls.append((sql, args))
        # FILL IN: return ALL rows (simulating a bypassed SQL filter) so the
        #  in-loop skip is exercised too.
        return rows

    monkeypatch.setattr(reserved_mod, "acquire_connection", _acquire)
    monkeypatch.setattr(reserved_mod, "fetch_rows", _fetch)
    return calls


class TestLoader:
    @pytest.mark.asyncio
    async def test_loader_filters_reserved_rows_in_sql(self, fake_db, keyring):
        # FILL IN: load_for_session(SESSION_UUID, 7, db_pool=object(), keyring=keyring);
        #  the SQL contains "starts_with(key, $2)" and args == (7, "mfa:")

    @pytest.mark.asyncio
    async def test_loader_never_decrypts_reserved_rows(self, fake_db, keyring, caplog):
        """Even when the DB returns the seed row, it is skipped: no integrity error, no audit."""
        # FILL IN: keys() == ["jira:token"]; "integrity" not in caplog.text;
        #  await vault.get("jira:token") == "tok-123" (ordinary loading still works — AC28)

    def test_upstream_select_unchanged(self):
        """Drift guard: re-sync reserved.py if navigator-session changes its loader SELECT."""
        # FILL IN: " ".join(_SELECT_ALL_ACTIVE.split()) ==
        #  "SELECT key, ciphertext_db, key_version, updated_at FROM auth.user_vault_secrets WHERE user_id = $1 AND deleted_at IS NULL"

    def test_integration_uses_filtered_loader(self):
        assert integration.SessionVault is ReservedPrefixSessionVault


class TestValidateKey:
    @pytest.mark.parametrize("key", ["mfa:totp", "mfa:", "mfa:anything"])
    def test_reserved_keys_rejected(self, keyring, key):
        # FILL IN: ReservedPrefixSessionVault(...)._validate_key(key) raises ValueError

    @pytest.mark.parametrize("key", ["jira:access_token", "mfa", "xmfa:totp", "MFA:totp"])
    def test_ordinary_keys_accepted(self, keyring, key):
        # FILL IN: no exception; is_reserved_key(key) is False
        #  (prefix match is exact and case-sensitive, like the SQL filter)


# --- HTTP layer: reuse the existing VaultView harness shape (tests/unit/vault/test_vault_view.py) ---
class _FakeSession(dict):
    def decode(self, key):
        return {"id": 42, "user_id": 42}


def meta(key, version=1):
    return VaultSecretMetadata(key=key, updated_at=UPDATED, key_version=version)


@pytest.fixture
def mock_vault():
    vault = AsyncMock()
    vault.list_metadata.return_value = [meta("jira:access_token", 2), meta("mfa:totp")]
    vault.exists.return_value = True
    vault.set.return_value = meta("new_secret")
    return vault


@pytest.fixture
def create_view(mock_vault):
    def _create_view(method, path, match_info=None, body=None):
        payload = json.dumps(body).encode("utf-8") if body else None
        request = make_mocked_request(method, path, match_info=match_info or {}, payload=payload)
        request[SESSION_OBJECT] = _FakeSession()
        if body is not None:
            request.json = AsyncMock(return_value=body)
        view = VaultView(request)

        async def _vault():
            return mock_vault

        view._get_session_and_vault = _vault
        return view

    return _create_view


class TestVaultHttp:
    @pytest.mark.asyncio
    async def test_vault_rejects_mfa_namespace(self, create_view, mock_vault):
        """GET/POST/DELETE on mfa:* answer 400 reserved_key and never touch the vault (AC28)."""
        # FILL IN: for each verb assert pytest.raises(web.HTTPBadRequest) with body
        #  {"error": "reserved_key"}; mock_vault.get/set/delete/exists not awaited

    @pytest.mark.asyncio
    async def test_listing_omits_reserved_keys(self, create_view):
        # FILL IN: GET list ⇒ only "jira:access_token" in the secrets

    @pytest.mark.asyncio
    async def test_ordinary_secrets_still_work(self, create_view, mock_vault):
        """POST/GET/DELETE of an ordinary key behave exactly as before (AC28)."""
        # FILL IN: POST {"key": "jira:access_token", "value": "x"} ⇒ 201; GET key ⇒ 200; DELETE ⇒ 200
```

**Why unit-level DB fakes here.** TASK-143 depends only on TASK-129, so the
shared Postgres fixtures (TASK-130) are not guaranteed to exist yet; and the
property under test — *which rows reach `open_sealed`* — is fully observable by
patching the two helpers `reserved.py` imports. The ciphertexts are real
(sealed with a real `KeyRing`), so the "ordinary secret still loads" assertion
exercises the genuine crypto path. TASK-147's end-to-end suite repeats the
check against live Postgres with an enrolled user.

### Steps (in order)

1. Confirm TASK-129 is in `sdd/tasks/completed/` and
   `python -c "from navigator_auth.mfa.types import MFA_VAULT_PREFIX; print(MFA_VAULT_PREFIX)"` prints `mfa:`.
   Also confirm `navigator_auth.mfa` imports neither `navigator_auth.vault`
   nor `navigator_auth.auth` (no import cycle once `vault/integration.py`
   imports `vault/reserved.py` → `mfa/types.py`).
2. Diff the installed upstream loader against the contract excerpt:
   `sed -n '409,500p' .venv/lib/python3.11/site-packages/navigator_session/vault/session_vault.py`.
   If the installed version is not 1.1.1 or the body differs, re-copy from the
   installed file.
3. Write `reserved.py`; fill the audit/summary tail by copying upstream.
4. Apply the `integration.py` rebinding.
5. Apply the five `handlers/vault.py` blocks.
6. Write the tests; run them, then the existing vault suites (regression):
   `pytest tests/unit/vault -q`.
7. `ruff check navigator_auth/vault/reserved.py navigator_auth/vault/integration.py navigator_auth/handlers/vault.py tests/test_mfa_vault_isolation.py`.

### FILL IN checklist

- [ ] `reserved.py` — upstream failure-audit block + final INFO summary, verbatim
- [ ] `fake_db._fetch` — return all rows (bypassed filter)
- [ ] `TestLoader` — 4 bodies (SQL filter, no decrypt + ordinary load, drift guard, binding)
- [ ] `TestValidateKey` — 2 parametrized bodies
- [ ] `TestVaultHttp` — 3 bodies

---

## Acceptance Criteria

- [ ] **AC-1** `ReservedPrefixSessionVault.load_for_session` queries with `NOT starts_with(key, $2)` bound to `"mfa:"` and never calls `open_sealed` on a reserved row, even when one is returned; no integrity error is logged and no `integrity_fail` audit is written for it.
- [ ] **AC-2** Ordinary secrets load, decrypt and are readable exactly as with the upstream loader when an `mfa:totp` row is present.
- [ ] **AC-3** `_validate_key` raises `ValueError` for any key starting with `mfa:` (case-sensitive) and accepts every other key upstream accepts — so `set`/`get`/`delete` refuse the namespace server-side.
- [ ] **AC-4** `navigator_auth.vault.integration.SessionVault is ReservedPrefixSessionVault`; `load_vault_for_session`, `get_session_vault` and `api_login`'s vault load therefore use the filtered loader; `pytest tests/unit/vault -q` still passes unchanged.
- [ ] **AC-5** `GET /api/v1/user/vault/mfa:…`, `POST` with `key="mfa:…"` and `DELETE /api/v1/user/vault/mfa:…` answer **400 `{"error": "reserved_key"}`** without touching the vault; `GET /api/v1/user/vault` omits reserved keys.
- [ ] **AC-6** A drift-guard test fails if navigator-session's `_SELECT_ALL_ACTIVE` changes.
- [ ] **AC-7** Closes spec **AC28** ("The general vault API cannot read, replace, delete or list MFA seeds; normal vault loading and ordinary secret operations remain usable") and the `test_vault_rejects_mfa_namespace` row of spec §4.
- [ ] **AC-8** `pytest tests/test_mfa_vault_isolation.py tests/unit/vault -v` passes; `ruff check` clean; `navigator_session` is untouched.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_vault_isolation.py -v
pytest tests/unit/vault -q          # regression: existing vault suites, unchanged
ruff check navigator_auth/vault/reserved.py navigator_auth/vault/integration.py \
           navigator_auth/handlers/vault.py tests/test_mfa_vault_isolation.py
```

```python
from navigator_auth.vault import integration
from navigator_auth.vault.reserved import ReservedPrefixSessionVault
assert integration.SessionVault is ReservedPrefixSessionVault
```

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §3 Security
   contracts "Protected seed namespace", §3 "Additional integration scope",
   §5 AC28, §7 R5 and R12.
2. **Check dependencies** — TASK-129 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Never edit files under
   `.venv/…/navigator_session/`.
5. **Verify** every acceptance criterion, AC-4's regression run included.
6. **Move this file** to `sdd/tasks/completed/TASK-143-mfa-vault-isolation.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
