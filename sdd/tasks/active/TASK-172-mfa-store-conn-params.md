# TASK-172: conn= parameters for every store call made inside a lock scope

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Review finding **#3** / goal **G3** (spec §1): inside a `user_lock` scope, code must never acquire a
second pool connection. Spec §3 Module 2 lists every store call that runs inside a lock scope and must
accept the caller's connection:

- `IdentityProvider.user_from_id`;
- `TOTPProvider.verify` / `_load_seed`;
- `TrustedDeviceStore.consume_and_rotate`;
- `PasskeyStore.save_credential` / `delete_credential`.

This task adds those kw-only `conn=` parameters. Without `conn` every method behaves exactly as today.
With `conn` it runs on the given connection and never touches the pool. `consume_and_rotate` also stops
owning a transaction: it runs inside the caller's.

The callers that pass `conn=` are later tasks: the gate (TASK-181), the passkey transition sites
(TASK-178), and the transition itself (TASK-177). The lock core (`LOCK_CONNECTION`, timeout) is TASK-171,
which runs in parallel. This task does not depend on it.

---

## Scope

- Add `conn: Any = None` (kw-only) to:
  - `IdentityProvider.user_from_id`;
  - `TOTPProvider._load_seed` and `TOTPProvider.verify`;
  - `TrustedDeviceStore.consume_and_rotate`;
  - `PasskeyStore.save_credential` and `PasskeyStore.delete_credential`.
- `consume_and_rotate(..., conn=conn)`: run the rotation statements on the caller's connection inside
  the caller's transaction. Issue no `transaction()`, `commit()` or `rollback()` of its own. A replay's
  family revocation is committed by the caller.
- `TOTPProvider.verify(..., conn=conn)`: the seed read and the `last_used_at` touch both run on `conn`.
- `PasskeyStore.save_credential`: use `fetchval … RETURNING`, so a failed insert raises instead of
  being swallowed by asyncdb `execute`. Inside a security transition this is what rolls the transition
  back.
- Write tests for the new `conn=` paths: TOTP (unit, fakes) and trusted devices (live DB).

**NOT in scope**:
- Changing which table the TOTP seed lives in (TASK-174 replaces `VAULT_SECRETS_TABLE`).
- `BackupCodeStore.consume` — it deliberately keeps its own connection (D16, spec §3 M2). Do not touch it.
- Any caller change (gate, handlers, passkey backend, transitions). Callers keep calling without `conn`
  until their own tasks.
- `LOCK_CONNECTION` and the lock timeout (TASK-171).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/idp/__init__.py` | MODIFY | `user_from_id(uid, *, conn=None)` |
| `navigator_auth/mfa/totp.py` | MODIFY | `_load_seed(..., *, conn=None)`, `verify(..., *, conn=None)` |
| `navigator_auth/mfa/trusted_devices.py` | MODIFY | `consume_and_rotate(..., *, conn=None)` + `_rotate_on` helper |
| `navigator_auth/passkey/store.py` | MODIFY | `save_credential(..., *, conn=None)`, `delete_credential(..., *, conn=None)` |
| `tests/test_mfa_trusted_devices.py` | MODIFY | live tests for rotation on the caller's connection |
| `tests/test_mfa_totp_provider.py` | MODIFY | unit tests for `verify(conn=)` (no pool acquire) |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
> `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`). The code is identical to the spec's `3f14b3c`.

### Verified Imports
```python
from typing import Union                                                   # verified: navigator_auth/backends/idp/__init__.py:2 (add Any)
from typing import Any, Callable, Optional                                 # verified: navigator_auth/mfa/totp.py:9
from typing import Any, AsyncIterator, Optional                            # verified: navigator_auth/mfa/trusted_devices.py:9
from contextlib import asynccontextmanager                                 # verified: navigator_auth/mfa/trusted_devices.py:7
from typing import Any, Optional                                           # verified: navigator_auth/passkey/store.py:4 (add AsyncIterator)
from navigator_auth.mfa.exceptions import MfaStorageError                  # verified: navigator_auth/mfa/trusted_devices.py:12
from navigator_auth.mfa.totp import TOTPProvider, mfa_seed_context, pending_seed_context  # verified: tests/test_mfa_totp_provider.py:8
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device    # verified: tests/test_mfa_trusted_devices.py:3
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore          # verified: navigator_auth/mfa/trusted_devices.py:32
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY         # verified: navigator_auth/mfa/totp.py:18
from navigator_session.vault import KeyRing, seal_value                    # verified: navigator_auth/mfa/totp.py:15
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401      # verified: tests/test_mfa_security_core.py:12 (same import style)
```

### Existing Signatures to Use
```python
# navigator_auth/backends/idp/__init__.py
class IdentityProvider:                                                     # line 39
    async def user_from_id(self, uid: int) -> Identity:                     # lines 124-144
        # db = self.app["authdb"]; async with await db.acquire() as conn:
        #   self.user_search.Meta.connection = conn; user = await self.user_search.get(**search)
        # NoDataFound -> UserNotFound; ValidationError re-raised; other -> UserNotFound; falsy -> UserNotFound

# navigator_auth/mfa/totp.py
VAULT_SECRETS_TABLE = "auth.user_vault_secrets"                             # line 31 (TASK-174 replaces it later)
TOTP_VAULT_KEY = "mfa:totp"                                                 # line 26
USER_MFA_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa"                               # line 32
REPLAY_TTL                                                                  # line 30
class TOTPProvider(AbstractOTPProvider):                                    # line 70
    def __init__(self, *, app, db_pool, store, issuer=AUTH_TOTP_ISSUER, clock=time.time)  # line 76; self._db, self._store, self._app
    def _keyring(self) -> KeyRing                                           # line 89 (app[VAULT_KEYRING_APP_KEY] else MfaStorageError)
    def match_step(self, seed: bytes, code: str, now: float) -> Optional[int]  # line 100
    async def _load_seed(self, user_id: int) -> Optional[bytes]:            # lines 113-131 (acquires own conn at :115)
    async def verify(self, request, user, code, challenge=None) -> bool     # lines 210-230 (own conn for the touch at :222)
    async def _disenroll_on(self, conn: Any, user_id: int) -> None:         # line 241
    async def _install_seed(self, conn: Any, user_id: int, seed: bytes) -> None:  # line 268
# self._store.mark_totp_step(user_id, step, REPLAY_TTL) -> bool              # used at :219 (MfaChallengeStore)

# navigator_auth/mfa/trusted_devices.py
class TrustedDeviceStore:                                                   # line 32
    async def _scope(self, conn: Any = None) -> AsyncIterator[Any]          # line 40 (@asynccontextmanager) — pattern to mirror
    async def issue(self, user_id, days, label, *, conn=None) -> str        # line 48
    async def consume_and_rotate(self, raw_token: str, user_id: int) -> Optional[tuple[int, str]]:  # lines 71-124 (own tx)
    async def revoke_all(self, user_id, reason, *, conn=None) -> int        # line 126

# navigator_auth/passkey/store.py
class PasskeyStore:                                                         # line 17; self._pool
    async def save_credential(self, credential: StoredCredential) -> None:  # lines 66-84 (conn.execute — swallows errors)
    async def delete_credential(self, user_id: int, credential_id: bytes, *, keep_last: bool = False) -> bool:  # lines 110-129
```

### Does NOT Exist
- ~~`BackupCodeStore.consume(..., conn=...)`~~ — deliberately absent (D16). Keep it that way.
- ~~`LOCK_CONNECTION`~~ / ~~`advisory_user_lock`~~ — TASK-171, not a dependency here. Do not import them.
- ~~`TOTPProvider.verify(..., conn=...)` today~~, ~~`IdentityProvider.user_from_id(..., conn=...)` today~~ —
  created by THIS task.
- ~~`PasskeyStore._scope`~~ — not present today. Add a private helper if you want one; it is not a contract.
- ~~`MFA_SECRETS_TABLE`~~ — TASK-174. Keep `VAULT_SECRETS_TABLE` in the SQL here.
- ~~a passkey store test in this task's file list~~ — `tests/test_passkey_store.py` exists and is run as
  a regression check only. The `conn=` atomicity of the passkey store is proven by TASK-178 (AC16).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/idp/__init__.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/totp.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/trusted_devices.py", "action": "MODIFY"},
    {"path": "navigator_auth/passkey/store.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_trusted_devices.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_totp_provider.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/idp/__init__.py#IdentityProvider.user_from_id",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider._load_seed",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider.verify",
    "sym:navigator_auth/mfa/totp.py#mfa_seed_context",
    "sym:navigator_auth/mfa/trusted_devices.py#TrustedDeviceStore",
    "sym:navigator_auth/mfa/trusted_devices.py#TrustedDeviceStore.consume_and_rotate",
    "sym:navigator_auth/mfa/trusted_devices.py#TrustedDeviceStore.issue",
    "sym:navigator_auth/passkey/store.py#PasskeyStore.save_credential",
    "sym:navigator_auth/passkey/store.py#PasskeyStore.delete_credential",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# navigator_auth/mfa/trusted_devices.py:39-46 — the existing "caller conn or own conn" scope:
@asynccontextmanager
async def _scope(self, conn: Any = None) -> AsyncIterator[Any]:
    if conn is not None:
        yield conn
        return
    async with await self._pool.acquire() as own:
        yield own
```

### Key Constraints
- Every new parameter is **kw-only** with default `None`. Existing positional calls must keep working.
- Without `conn`, every method's observable behaviour is unchanged. One exception:
  `save_credential` now raises on a failed insert (`fetchval … RETURNING` instead of `execute`). That is
  the project's fail-closed rule (memory `asyncdb-execute-never-raises`). `tests/test_passkey_store.py`
  must still pass.
- With `conn`, never call `self._pool.acquire()` / `self._db.acquire()` / `self.app["authdb"].acquire()`.
- With `conn`, `consume_and_rotate` issues no `transaction()`, `commit()` or `rollback()`. The caller
  owns the transaction. Paths that wrote nothing just return `None`. The row lock from `FOR UPDATE` is
  held until the caller's commit, which is intended.
- With `conn`, a failing `last_used_at` touch in `TOTPProvider.verify` must **raise `MfaStorageError`**,
  not just log. In PostgreSQL a failed statement aborts the caller's transaction, so swallowing it
  would let the lock scope continue on a dead transaction. Without `conn`, keep today's warning-only
  behaviour.
- `User.Meta.connection` / `self.user_search.Meta.connection` is class-level shared state. Set it
  immediately before the model call, with no other `await` in between (spec §7 Known Risks).
- Error messages carry exception type names only (no SQL, no secrets).

### References in Codebase
- `navigator_auth/mfa/trusted_devices.py:71-124` — the rotation logic to split.
- `navigator_auth/mfa/totp.py:113-131, 210-230` — seed read and verify.
- `tests/test_mfa_security_core.py` — live-DB test style (`mfa_db`, `mfa_user_factory`).

---

## Implementation Blueprint

### Steps (in order)
1. Add `conn=` to `IdentityProvider.user_from_id` — *why*: the gate re-reads the user on the lock
   connection (spec M5 step 1). Today it acquires from `app["authdb"]`.
2. Add `conn=` to `TOTPProvider._load_seed` and `verify` — *why*: TOTP verification runs under the lock
   in the gate (spec M5 verify step 6).
3. Split `consume_and_rotate` into a transaction-free `_rotate_on(conn, …)` plus the two entry modes —
   *why*: one copy of the rotation SQL serves both the pooled path (own transaction) and the caller's
   transaction.
4. Add `conn=` to `PasskeyStore.save_credential` / `delete_credential` and switch the insert to
   `fetchval … RETURNING` — *why*: the passkey transition (TASK-178) must write on the transition
   connection and fail closed.
5. Write the tests and run the Validation Commands — *why*: `test_consume_and_rotate_on_caller_conn`
   is a spec §4 row.

### `navigator_auth/backends/idp/__init__.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from typing import Union' navigator_auth/backends/idp/__init__.py)
# REPLACE — `from typing import Union` (verified: navigator_auth/backends/idp/__init__.py:2)
from typing import Any, Union

# occurrences: 1 (verified: grep -c 'async def user_from_id(self, uid: int) -> Identity:' navigator_auth/backends/idp/__init__.py)
# REPLACE — the method from that line through its final `return user` (verified: navigator_auth/backends/idp/__init__.py:124-144)
    async def user_from_id(self, uid: int, *, conn: Any = None) -> Identity:
        """Return the user with ``uid``.

        Args:
            uid: The user id.
            conn: When given, the lookup runs on this connection and no pool connection is
                acquired (callers inside an MFA ``user_lock`` scope pass the lock connection).

        Raises:
            UserNotFound: no such user, or the lookup failed.
            ValidationError: the stored row does not fit the user model.
        """
        user = None
        search = {self.userid_attribute: uid}
        try:
            if conn is not None:
                self.user_search.Meta.connection = conn
                user = await self.user_search.get(**search)
            else:
                db = self.app["authdb"]
                async with await db.acquire() as own:
                    self.user_search.Meta.connection = own
                    user = await self.user_search.get(**search)
        except NoDataFound as ex:
            raise UserNotFound(f"Invalid credentials for User {search!s}") from ex
        except ValidationError as ex:
            self.logger.error(f"Invalid User Information {search!s}: {ex}")
            self.logger.warning(f"Error on User Model = {ex.payload!r}")
            raise
        except Exception as e:
            raise UserNotFound(f"Error getting User {search!s}: {e!s}") from e
        if not user:
            raise UserNotFound(f"Invalid credentials for User {search!s}")
        return user
```
**Why**: The behaviour is today's, minus the pool acquire when `conn` is given. `search` moves before
the `try`, so the error messages never hit an unbound name.

### `navigator_auth/mfa/totp.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'async def _load_seed(self, user_id: int) -> Optional[bytes]:' navigator_auth/mfa/totp.py)
# REPLACE — from that line through the `raise MfaStorageError(f"totp seed read failed: ...")` of its except (verified: navigator_auth/mfa/totp.py:113-122)
    async def _load_seed(self, user_id: int, *, conn: Any = None) -> Optional[bytes]:
        sql = (
            f"SELECT ciphertext_db FROM {VAULT_SECRETS_TABLE} "
            "WHERE user_id = $1 AND key = $2 AND deleted_at IS NULL"
        )
        try:
            if conn is not None:
                row = await conn.fetch_one(sql, user_id, TOTP_VAULT_KEY)
            else:
                async with await self._db.acquire() as own:
                    row = await own.fetch_one(sql, user_id, TOTP_VAULT_KEY)
        except Exception as err:
            raise MfaStorageError(f"totp seed read failed: {type(err).__name__}") from err
        # (lines 123-131 — the unseal and length check — stay unchanged)

# occurrences: 1 (verified: grep -c 'async def verify(' navigator_auth/mfa/totp.py) — next line
#   `self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None` (count 1, :211)
# REPLACE — the method from `async def verify(` through its final `return True` (verified: navigator_auth/mfa/totp.py:210-230;
#   NOTE `        return True` occurs twice (:208, :230) — replace by the method span, not by that line)
    async def verify(
        self,
        request: web.Request,
        user: Mapping,
        code: str,
        challenge: Optional[MfaChallenge] = None,
        *,
        conn: Any = None,
    ) -> bool:
        """Verify a code against the active seed, failing closed on storage errors.

        With ``conn`` the seed read and the ``last_used_at`` touch run on it; a touch failure then
        raises ``MfaStorageError`` because it aborts the caller's transaction.
        """
        user_id = int(_field(user, "user_id"))
        seed = await self._load_seed(user_id, conn=conn)
        if seed is None:
            return False
        step = self.match_step(seed, code, self._clock())
        if step is None or not await self._store.mark_totp_step(user_id, step, REPLAY_TTL):
            return False
        touch = f"UPDATE {USER_MFA_TABLE} SET last_used_at = now() WHERE user_id=$1 AND provider=$2 RETURNING 1"
        if conn is not None:
            try:
                await conn.fetchval(touch, user_id, PROVIDER_TOTP)
            except Exception as err:
                raise MfaStorageError(f"totp last-used touch failed: {type(err).__name__}") from err
            return True
        try:
            async with await self._db.acquire() as own:
                await own.fetchval(touch, user_id, PROVIDER_TOTP)
        except Exception as err:
            self.logger.warning("MFA last-used touch failed: %s", type(err).__name__)
        return True
```
**Why**: The verification order and the replay mark are unchanged. Only the connection source differs.
The touch on the caller's connection fails closed, because a failed statement poisons the caller's
transaction (see Key Constraints).

### `navigator_auth/mfa/trusted_devices.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'async def consume_and_rotate(self, raw_token: str, user_id: int) -> Optional[tuple[int, str]]:' navigator_auth/mfa/trusted_devices.py)
# REPLACE — the whole method (verified: navigator_auth/mfa/trusted_devices.py:71-124)
    async def consume_and_rotate(
        self, raw_token: str, user_id: int, *, conn: Any = None
    ) -> Optional[tuple[int, str]]:
        """Validate and rotate a live token, or revoke its family on replay.

        Args:
            raw_token: The cookie value presented by the browser.
            user_id: The user the token must belong to.
            conn: When given, run inside the CALLER's transaction: no own transaction, commit or
                rollback; a replay's family revocation is committed by the caller.

        Returns:
            ``(user_id, new_raw_token)`` after a rotation, else ``None``.

        Raises:
            MfaStorageError: on any storage failure.
        """
        if not raw_token:
            return None
        try:
            if conn is not None:
                result, _commit = await self._rotate_on(conn, raw_token, user_id)
                return result
            async with await self._pool.acquire() as own:
                await own.transaction()
                try:
                    result, commit = await self._rotate_on(own, raw_token, user_id)
                    if commit:
                        await own.commit()
                    else:
                        await own.rollback()
                    return result
                except BaseException:
                    await own.rollback()
                    raise
        except MfaStorageError:
            raise
        except Exception as err:
            raise MfaStorageError(f"trusted device rotation failed: {type(err).__name__}") from err

    async def _rotate_on(
        self, conn: Any, raw_token: str, user_id: int
    ) -> tuple[Optional[tuple[int, str]], bool]:
        """Run the rotation statements on ``conn`` with no transaction control.

        Returns:
            ``(result, should_commit)``: ``should_commit`` is True when rows were written
            (a rotation or a replay's family revocation).
        """
        # FILL IN: move the statements of today's lines 79-117 here verbatim, mapping each
        #          `await conn.rollback(); return None` -> `return None, False`,
        #          the replay branch's `await conn.commit(); logger.warning(...); return None` -> log then `return None, True`,
        #          the success `await conn.commit(); return int(row["user_id"]), new_raw` -> `return (int(row["user_id"]), new_raw), True`
        #          — bounded by spec §3 M2 consume_and_rotate contract and test_consume_and_rotate_on_caller_conn
```
**Why**: Today's rotation SQL (`SELECT … FOR UPDATE`, replay family revocation, rotate and insert) moves
unchanged into `_rotate_on`. Only the transaction control is lifted out. That makes the "caller's
transaction" mode a one-liner and keeps the pooled path byte-for-byte equivalent.

### `navigator_auth/passkey/store.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'import secrets' navigator_auth/passkey/store.py)
# AFTER — insert below `import secrets` (verified: navigator_auth/passkey/store.py:3)
from contextlib import asynccontextmanager

# occurrences: 1 (verified: grep -c 'from typing import Any, Optional' navigator_auth/passkey/store.py)
# REPLACE — (verified: navigator_auth/passkey/store.py:4)
from typing import Any, AsyncIterator, Optional

# occurrences: 1 (verified: grep -c 'async def save_credential(self, credential: StoredCredential) -> None:' navigator_auth/passkey/store.py)
# REPLACE — the method (verified: navigator_auth/passkey/store.py:66-84); insert _scope directly above it
    @asynccontextmanager
    async def _scope(self, conn: Any = None) -> AsyncIterator[Any]:
        """Yield the caller's connection, or acquire one from the pool."""
        if conn is not None:
            yield conn
            return
        async with await self._pool.acquire() as own:
            yield own

    async def save_credential(self, credential: StoredCredential, *, conn: Any = None) -> None:
        """Insert a newly registered credential, on ``conn`` when given.

        Raises:
            RuntimeError: the insert returned no row (never silently ignored).
            Exception: database errors (e.g. a unique violation) propagate to the caller.
        """
        async with self._scope(conn) as db:
            inserted = await db.fetchval(
                f"INSERT INTO {_CREDENTIALS} "
                "(credential_id, user_id, rp_id, public_key, sign_count, transports, "
                "aaguid, device_type, backed_up, label) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $10) RETURNING credential_id",
                credential.credential_id,
                credential.user_id,
                credential.rp_id,
                credential.public_key,
                credential.sign_count,
                credential.transports,
                credential.aaguid,
                credential.device_type,
                credential.backed_up,
                credential.label,
            )
        if inserted is None:
            raise RuntimeError("passkey credential insert returned no row")

# occurrences: 1 (verified: grep -c 'async def delete_credential(self, user_id: int, credential_id: bytes, *, keep_last: bool = False) -> bool:' navigator_auth/passkey/store.py)
# REPLACE — signature + the `async with await self._pool.acquire() as conn:` of this method only
#           (verified: navigator_auth/passkey/store.py:110 and :121; that acquire line occurs 9 times in the file — edit the one inside delete_credential)
    async def delete_credential(
        self, user_id: int, credential_id: bytes, *, keep_last: bool = False, conn: Any = None
    ) -> bool:
        # (docstring: add `conn: run on the caller's connection (security transition) instead of the pool.`)
        guard = f" AND (SELECT count(*) FROM {_CREDENTIALS} WHERE user_id = $1) > 1" if keep_last else ""
        async with self._scope(conn) as db:
            removed = await db.fetchval(
                # FILL IN: today's statement and parameters unchanged (lines 122-128) — bounded by the
                #          existing keep_last atomicity test (tests/test_passkey_store.py::test_delete_keep_last_is_atomic)
            )
        return bool(removed)
```
**Why**: `register` and `remove` in TASK-178 call these inside `security_transition` with its connection.
A write that silently fails (`execute`) would let the transition commit a version bump and audit for a
credential that was never stored (AC16).

### `tests/test_mfa_totp_provider.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.totp import TOTPProvider, mfa_seed_context, pending_seed_context' tests/test_mfa_totp_provider.py)
# AFTER — insert below that import (verified: tests/test_mfa_totp_provider.py:8); add `import pytest` to the stdlib block
from navigator_session.vault import KeyRing, seal_value

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY

# APPEND at end of file
class _NoPool:
    """A pool that must never be used: any acquire() fails the test."""

    def acquire(self):
        raise AssertionError("pool acquired although conn= was given")


class _Conn:
    """Fake lock connection returning a sealed seed and recording statements."""

    def __init__(self, ciphertext: bytes, *, fail_touch: bool = False) -> None:
        self.ciphertext, self.fail_touch, self.calls = ciphertext, fail_touch, []

    async def fetch_one(self, sql, *args):
        self.calls.append(("fetch_one", sql))
        return {"ciphertext_db": self.ciphertext}

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql))
        if self.fail_touch:
            raise RuntimeError("touch failed")
        return 1


@pytest.mark.asyncio
async def test_verify_on_caller_conn_never_acquires() -> None:
    """verify(conn=) reads the seed and touches last_used on conn only (spec M2)."""
    # FILL IN: KeyRing({1: os.urandom(32)}, 1); seed = os.urandom(20);
    #          ciphertext = seal_value(seed, mfa_seed_context(7), keyring);
    #          provider = TOTPProvider(app={VAULT_KEYRING_APP_KEY: keyring}, db_pool=_NoPool(), store=<fake with
    #          async mark_totp_step -> True>, clock=lambda: 1_700_000_010); valid code -> True; conn saw fetch_one + fetchval


@pytest.mark.asyncio
async def test_verify_on_caller_conn_touch_failure_raises() -> None:
    """A failed touch on the caller's connection fails closed (MfaStorageError), never a silent True."""
    # FILL IN: same setup with _Conn(..., fail_touch=True) -> pytest.raises(MfaStorageError)
```
**Why**: Fakes prove the "no pool acquire" property deterministically, with no database. The seed is
sealed with the real vault, so `_load_seed`'s unseal path is exercised too.

### `tests/test_mfa_trusted_devices.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.trusted_devices import may_offer_trusted_device' tests/test_mfa_trusted_devices.py)
# REPLACE — that import (verified: tests/test_mfa_trusted_devices.py:3); add `import pytest` above it
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore, may_offer_trusted_device
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401

# APPEND at end of file
@pytest.mark.asyncio
async def test_consume_and_rotate_on_caller_conn(mfa_db, mfa_user_factory):
    """With conn, rotation and replay revocation commit only with the caller's transaction (spec §4 M2)."""
    # FILL IN: issue a device; in a manual tx (`async with await mfa_db.acquire() as conn: await conn.transaction()`)
    #          rotate with conn=conn -> (uid, new_raw); ROLLBACK -> the old token still rotates via the pooled path.
    #          Second round: rotate on conn, COMMIT -> replaying the old token (pooled) revokes the family and
    #          the new token is then refused — bounded by spec §3 M2 consume_and_rotate docstring


@pytest.mark.asyncio
async def test_consume_and_rotate_pooled_path_unchanged(mfa_db, mfa_user_factory):
    """Without conn, rotation still runs in its own transaction (regression)."""
    # FILL IN: issue -> consume_and_rotate(raw, uid) returns (uid, new); consume_and_rotate(raw, uid) again -> None (replay)
```

### FILL IN checklist
- [ ] `trusted_devices.py::_rotate_on` — move today's statements and map the transaction outcomes; bounded by spec §3 M2.
- [ ] `passkey/store.py::delete_credential` — statement unchanged; bounded by `test_delete_keep_last_is_atomic`.
- [ ] `test_verify_on_caller_conn_never_acquires` / `..._touch_failure_raises` — setup and assertions; bounded by spec §3 M2.
- [ ] `test_consume_and_rotate_on_caller_conn` / `..._pooled_path_unchanged` — live-DB bodies; bounded by spec §4 M2 row.

---

## Acceptance Criteria

- [ ] All six methods accept kw-only `conn=`. Without it, behaviour is unchanged: existing suites pass.
- [ ] With `conn`, no pool acquire happens in any of them (proven for TOTP by `_NoPool`).
- [ ] `consume_and_rotate(..., conn=conn)` writes nothing durable unless the caller commits.
- [ ] `PasskeyStore.save_credential` raises on a failed insert. The register 409-on-duplicate
      behaviour still works (`passkey.py:326-327` matches the unique-violation error).
- [ ] `BackupCodeStore.consume` is untouched (D16).
- [ ] No linting errors in the touched files.

---

## Validation Commands

- `pytest tests/test_mfa_trusted_devices.py -q`
- `pytest tests/test_mfa_totp_provider.py -q`
- `pytest tests/test_passkey_store.py -q`

---

## Test Specification

```python
# tests/test_mfa_totp_provider.py — unit, fakes only (see blueprint): verify(conn=) never acquires; touch failure raises.
# tests/test_mfa_trusted_devices.py — live Postgres via tests.fixtures.mfa (skips when down):
#   rollback of the caller's tx leaves the old token usable; commit makes the rotation durable.
# tests/test_passkey_store.py — existing suite, run unchanged as a regression check.
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`
   (branch `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633), never on `dev`.
2. **Read the spec** at the path listed above, §3 Module 2.
3. **Check dependencies**: none.
4. **Verify the Codebase Contract**: re-run the `grep -c` counts in the blueprint before editing.
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"`.
6. **Implement**: start from the blueprint blocks and complete every `# FILL IN:` marker.
7. **Verify**: run the Validation Commands.
8. **Commit the code**: stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-172 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
