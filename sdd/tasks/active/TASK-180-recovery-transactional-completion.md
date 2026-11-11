# TASK-180: Transactional recovery completion and serialized confirmation rotation

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-171, TASK-175, TASK-176, TASK-177
**Assigned-to**: unassigned

---

## Context

Review finding **#5** (spec §1): recovery completion (`PasswordRecoveryHandler._step3_confirm`) holds a
pooled connection, GETDELs the Redis confirmation **before** the transition, writes the password with
`User.update()` on that pooled connection inside `security_transition` (nested acquire, finding #3), and only
**after** the transition revokes sessions best-effort. A failure after the write leaves a new password whose
confirmation is already burned, with no bump/revoke/audit, and recovery can silently skip session revocation.

This task implements spec §3 **Module 4 — Recovery completion** and the **durable recovery and token revocation
contract**:
- phase 1 (pooled, released): `peek_confirmation`, `User.get`, policy validation (422);
- phase 2 (transition connection, per-user advisory lock — with MFA on *or* off): re-read the hash (drift →
  409), re-validate the signed, unexpired Redis confirmation **and its current rotation status**, insert its
  SHA-256 digest into `recovery_confirm_consumptions` (duplicate → 400), write the password, increment the OAuth
  generation, strictly revoke sessions/JTIs, commit;
- after commit: `drop_pair`, best effort and logged. `consume_confirmation` is no longer called.
- Confirmation **rotation** (`_step2_validate` → `issue_confirmation`) takes the same per-user advisory lock
  before it changes Redis, so it cannot invalidate a confirmation between the step-3 recheck and commit.

---

## Scope

- `handler.py`:
  - imports + module constants `_USERS`, `_MARKER_SKEW_SECONDS`;
  - `_step2_validate`: wrap `issue_confirmation(token)` in `advisory_user_lock(app["authdb"], recovery_payload.user_id)`;
    `MfaStorageError` (lock timeout) → 503;
  - `_step3_confirm`: two-phase rewrite as described above; error mapping: `TransitionAborted("credentials_changed")`
    → 409, `TransitionAborted("invalid_confirmation")` → 400 (same body as today's invalid-token 400),
    `MfaUnavailable` → 503 `mfa_unavailable`, `MfaStorageError` / `RevocationError` / `SecurityStateError` → 503
    `temporarily_unavailable` with everything rolled back.
- `store.py`: add `RecoveryTokenStore.current_confirmation(token)` — read-only (never GETDEL): signed, unexpired,
  and still the live rotation of its recovery record.
- Tests in `tests/test_password_recovery.py` (AC13, AC14, AC15, AC31-recovery, AC32, AC10-recovery, drift 409).

**NOT in scope**: `SessionRevoker` strict mode and `session_revoker()` (TASK-176 — used here); the
`security_state` tables/store (TASK-175 — used here); `security_transition` internals (TASK-177);
`password_change` / `password_reset` (TASK-179); OAuth token rejection by generation (TASK-185); purging expired
consumption markers (no purge job is in scope — markers carry `expires_at` for a future reaper).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/recovery/handler.py` | MODIFY | Two-phase transactional step 3; step-2 rotation under the advisory lock |
| `navigator_auth/handlers/recovery/store.py` | MODIFY | `current_confirmation()` (signed + unexpired + current rotation, read-only) |
| `tests/test_password_recovery.py` | MODIFY | Atomicity, replay, concurrency, 503 and single-connection tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch feat-FEAT-106-basicauth-otp-2fa). Line numbers are from that tree.
> TASK-176 (a dependency) inserts `session_revoker()` right after `_ensure_resources` (handler.py:139-151), so
> every handler.py line below 151 shifts by roughly +10 when you start — always re-locate by the quoted anchor.

### Verified Imports
```python
from datetime import datetime, timezone                                   # verified: navigator_auth/handlers/recovery/handler.py:20
from asyncdb.exceptions import NoDataFound                                 # verified: navigator_auth/handlers/recovery/handler.py:24
from navigator_auth.conf import AUTH_RECOVERY_CONFIRM_TTL                  # verified: navigator_auth/handlers/recovery/handler.py:30 (inside the conf import tuple 27-39)
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE           # verified: navigator_auth/conf.py:33-34
from navigator_auth.models import User                                     # verified: navigator_auth/handlers/recovery/handler.py:40
from navigator_auth.handlers.users.passwd import set_basic_password        # verified: navigator_auth/handlers/recovery/handler.py:41
from navigator_auth.handlers.recovery.revoke import SessionRevoker         # verified: navigator_auth/handlers/recovery/handler.py:44
from navigator_auth.handlers.recovery.store import RecoveryTokenStore, _hash_token  # verified: navigator_auth/handlers/recovery/handler.py:45
from navigator_auth.mfa.events import security_transition                  # verified: navigator_auth/handlers/recovery/handler.py:47
from navigator_auth.mfa.exceptions import MfaStorageError                  # verified: navigator_auth/mfa/exceptions.py:8
import secrets                                                             # stdlib (compare_digest); already imported in store.py:19
# store.py already has: import time (:20), aioredis (:24), AUTH_RECOVERY_CONFIRM_TTL (:26), json_decoder (:27),
#   ConfirmationPayload (:28-31), RECOVERY_KEY_PREFIX / CONFIRM_KEY_PREFIX (:33-34)
# Created by dependency tasks (fixed signatures from the decomposition plan):
from navigator_auth.mfa.security import advisory_user_lock                 # created by TASK-171
from navigator_auth.mfa.events import TransitionAborted                    # created by TASK-177
from navigator_auth.mfa.exceptions import MfaUnavailable                   # created by TASK-177
from navigator_auth.security_state.store import (                          # created by TASK-175
    SecurityStateError, increment_generation, record_confirmation,
)
from navigator_auth.handlers.recovery.revoke import RevocationError        # created by TASK-176
```

### Existing Signatures to Use
```python
# navigator_auth/handlers/recovery/handler.py
class PasswordRecoveryHandler(BaseView):                                  # line 115
    _store: Optional[RecoveryTokenStore] = None                           # line 132
    _policy: Optional[PasswordPolicy] = None                              # line 133
    _revoker: Optional[SessionRevoker] = None                             # line 136
    @classmethod
    def _ensure_resources(cls) -> None:                                   # line 139 (cls._revoker = SessionRevoker(cls._pool) at 151)
    async def _step2_validate(self):                                      # line 227; issue_confirmation call at 237, except LookupError at 238
    async def _step3_confirm(self):                                       # line 250
    #   peek_confirmation 267; db.acquire 278; User.get 281; policy 285-291; consume_confirmation 295;
    #   security_transition 299-307; drop_pair 309; revoke_user 311; 202 response 319-325
    # helpers: self.error(reason=..., status=...), self.json_response(response=..., status=...) (used at 230, 240, 288, 319)

# navigator_auth/handlers/recovery/store.py
def _hash_token(token: str) -> str:                                       # line 37 (sha256 hex)
class RecoveryTokenStore:                                                 # line 42
    async def validate_recovery(self, token: str) -> Optional[RecoveryPayload]:   # line 91 (payload.user_id)
    async def issue_confirmation(self, token: str) -> tuple[str, ConfirmationPayload]:  # line 117
    #   rotation: deletes the previous confirm key (136-138), writes back-pointer data["confirm_key"] = confirm_hash (160-161)
    def _decode_confirmation(self, raw) -> Optional[ConfirmationPayload]: # line 165 (None on bad signature)
    async def peek_confirmation(self, token: str) -> Optional[ConfirmationPayload]:   # line 180 (GET, no consume)
    async def consume_confirmation(self, token: str) -> Optional[ConfirmationPayload]:  # line 198 (GETDEL — kept, no longer used by step 3)
    async def drop_pair(self, recovery_key: str, confirm_key: str) -> None:            # line 207 (bare sha256 hex digests)

# navigator_auth/handlers/recovery/types.py
@dataclass(frozen=True)
class ConfirmationPayload:                                                # line 23: user_id, username, recovery_key, issued_at (epoch float), signature

# --- dependency contracts (fixed) ---
# TASK-171 navigator_auth/mfa/security.py:
@asynccontextmanager
async def advisory_user_lock(db_pool: Any, user_id: int, *, timeout: Optional[float] = None) -> AsyncIterator[Any]
    # ONE pooled conn + ONE tx holding pg_advisory_xact_lock(LOCK_NAMESPACE, key); timeouts -> MfaStorageError;
    # body exception -> rollback + re-raise; same lock key as MfaSecurity.user_lock (which delegates to it)
# TASK-177 navigator_auth/mfa/events.py: security_transition(...) ALWAYS yields ONE connection in ONE tx under the
#   per-user advisory lock (MFA on: user_lock + bump/revoke/audit; MFA off: advisory_user_lock, no bookkeeping);
#   MfaUnavailable before yield; TransitionAborted(reason) -> rollback, logged at INFO (.reason attribute)
# TASK-175 navigator_auth/security_state/store.py:
async def record_confirmation(conn: Any, digest: str, user_id: int, expires_at: datetime) -> bool  # False on duplicate
async def increment_generation(conn: Any, user_id: int) -> int
class SecurityStateError(Exception)
# TASK-176 navigator_auth/handlers/recovery/{revoke,handler}.py:
class RevocationError(Exception)
async def SessionRevoker.revoke_user(self, request, user, *, strict: bool = False) -> int
@classmethod
def PasswordRecoveryHandler.session_revoker(cls) -> SessionRevoker
```

### Does NOT Exist
- ~~`RecoveryTokenStore.current_confirmation`~~ — created by THIS task.
- ~~`RecoveryTokenStore.consume_confirmation(..., conn=)`~~ / ~~a Postgres-backed confirmation store~~ — Redis only; the durable marker lives in `security_state` (TASK-175).
- ~~`advisory_user_lock`~~ (TASK-171), ~~`TransitionAborted`~~ / ~~`MfaUnavailable`~~ (TASK-177), ~~`record_confirmation`~~ / ~~`increment_generation`~~ / ~~`SecurityStateError`~~ (TASK-175), ~~`RevocationError`~~ / ~~`session_revoker()`~~ / ~~`revoke_user(..., strict=)`~~ (TASK-176) — not on today's tree.
- ~~`security_transition(...)` yielding `None`~~ — never after TASK-177; do not branch on `conn is None`.
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path-list drift).
- ~~a purge/reaper for `recovery_confirm_consumptions`~~ — not in scope; do not invent one.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {
      "path": "navigator_auth/handlers/recovery/handler.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/handlers/recovery/store.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_password_recovery.py",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler._ensure_resources",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler._step2_validate",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler._step3_confirm",
    "sym:navigator_auth/handlers/recovery/store.py#_hash_token",
    "sym:navigator_auth/handlers/recovery/store.py#RecoveryTokenStore.validate_recovery",
    "sym:navigator_auth/handlers/recovery/store.py#RecoveryTokenStore.issue_confirmation",
    "sym:navigator_auth/handlers/recovery/store.py#RecoveryTokenStore._decode_confirmation",
    "sym:navigator_auth/handlers/recovery/store.py#RecoveryTokenStore.peek_confirmation",
    "sym:navigator_auth/handlers/recovery/store.py#RecoveryTokenStore.consume_confirmation",
    "sym:navigator_auth/handlers/recovery/store.py#RecoveryTokenStore.drop_pair",
    "sym:navigator_auth/handlers/recovery/types.py#ConfirmationPayload",
    "sym:navigator_auth/handlers/recovery/revoke.py#SessionRevoker",
    "sym:navigator_auth/handlers/users/passwd.py#set_basic_password",
    "sym:navigator_auth/models.py#User",
    "sym:navigator_auth/mfa/events.py#security_transition",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# Fail-closed writes inside the transition use fetchval ... RETURNING (navigator_auth/mfa/security.py:94-108):
version = await conn.fetchval(sql, int(user_id))
if version is None:
    raise ValueError("security version was not returned")
```

### Key Constraints
- **Never GETDEL / consume the Redis confirmation before commit.** The committed SHA-256 digest in
  `recovery_confirm_consumptions` is the authoritative single-use record; Redis cleanup (`drop_pair`) runs after
  commit, best effort, logged with `type(err).__name__` only (AC32: a leftover Redis record cannot be replayed).
- **Phase 2 uses explicit SQL** (`SELECT password ... FOR UPDATE`, `UPDATE ... RETURNING user_id` via
  `conn.fetchval`), not `User.get`/`User.update` — because asyncdb `Model.update()` has a 2 s hard timeout,
  rewrites every column and uses a class-wide WHERE dict (project memory `asyncdb-model-update-pitfalls`), and
  `User.Meta.connection` is class-level shared state (spec §7). `conn.execute` swallows errors (memory
  `asyncdb-execute-never-raises`) — never use it for these writes. Record this under "Deviations from spec".
- **Order inside phase 2 (fixed):** hash recheck → `current_confirmation` recheck → `record_confirmation` →
  password UPDATE (`is_new = false`, D17 — never "harmonise" with admin reset) → `increment_generation` →
  strict `revoke_user`. Everything before commit; any failure rolls back password, marker and generation.
- **No pool acquire inside the transition** (G3, AC10): phase 2 does only `conn.*`, Redis (`current_confirmation`,
  `revoke_user`) and `security_state` calls that take `conn`. `self.session_revoker()` is fetched before the lock.
- **Rotation serialization:** `_step2_validate` takes `advisory_user_lock(app["authdb"], user_id)` BEFORE
  `issue_confirmation` changes Redis; step 3 rechecks validity and rotation while holding the same lock (via the
  transition). This must hold with MFA **off** too (TASK-177's no-services branch uses the same lock key).
- **Marker retention:** `expires_at = issued_at + AUTH_RECOVERY_CONFIRM_TTL + _MARKER_SKEW_SECONDS` (300 s
  clock-skew margin) — at least until the signed confirmation expires (spec durable contract).
- Keep today's response bodies: 400 `"Invalid or expired confirmation token"`, 422 `violations`, 202 body, no
  token/refresh_token in the response (D15). New: 409 `{"error": "credentials_changed"}`, 503
  `{"error": "mfa_unavailable"}` / `{"error": "temporarily_unavailable"}`.
- Raw tokens never appear in logs or responses (existing `test_token_never_logged` / `test_token_never_leaks`).
- `tests/test_password_recovery.py::test_federated_user_can_recover` and `test_step3_revokes_sessions` must stay
  green under strict revocation; if strict mode rejects a case that is legitimate today, stop and report (TASK-176
  owns the strict semantics).

### References in Codebase
- `navigator_auth/handlers/recovery/handler.py:250-325` — the code being replaced.
- `tests/test_password_recovery.py:506-638` — live `recovery_app` fixture (BasicAuth only, MFA off).
- `tests/test_mfa_e2e.py` — MFA-on live recovery (`live.recover`, `test_verify_security_transition_races`); run, do not edit.

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-171/175/176/177 are merged in the worktree (`grep -n "def advisory_user_lock" navigator_auth/mfa/security.py`, `grep -n "def record_confirmation" navigator_auth/security_state/store.py`, `grep -n "def session_revoker" navigator_auth/handlers/recovery/handler.py`, `grep -n "class TransitionAborted" navigator_auth/mfa/events.py`) — *why*: the blocks call their symbols.
2. Add `current_confirmation` to the store (block 1) — *why*: step 3 must recheck validity AND rotation under the lock without consuming anything.
3. Update handler imports/constants (block 2) — *why*: new error types and the explicit-SQL table name.
4. Lock the rotation in `_step2_validate` (block 3) — *why*: rotation must not change Redis between the step-3 recheck and commit.
5. Replace `_step3_confirm` phase 1 (block 4) and phase 2 + post-commit (block 5) — *why*: single transaction for marker + password + generation + strict revocation (AC15, AC32).
6. Add the tests (block 6) and run the Validation Commands.

### `navigator_auth/handlers/recovery/store.py` (MODIFY) — block 1: `current_confirmation`
```python
# occurrences: 1 (verified: grep -c 'async def consume_confirmation(self, token: str) -> Optional[ConfirmationPayload]:' navigator_auth/handlers/recovery/store.py)
# BEFORE — insert above `async def consume_confirmation(self, token: str) -> Optional[ConfirmationPayload]:` (verified: navigator_auth/handlers/recovery/store.py:198)
    async def current_confirmation(self, token: str) -> Optional[ConfirmationPayload]:
        """Return the confirmation only if it is still valid for completion; never consumes it.

        Valid means: the stage-2 record exists, its HMAC signature verifies, it has not
        outlived ``AUTH_RECOVERY_CONFIRM_TTL``, and it is the CURRENT rotation of its
        stage-1 recovery record (the record's ``confirm_key`` back-pointer equals this
        token's hash). Called by step 3 while the per-user advisory lock is held.

        Args:
            token: The raw stage-2 confirmation token.

        Returns:
            The verified payload, or None when it is missing, forged, expired or rotated out.
        """
        confirm_hash = _hash_token(token)
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            raw = await redis.get(f"{CONFIRM_KEY_PREFIX}{confirm_hash}")
            if not raw:
                return None
            confirmation = self._decode_confirmation(raw)
            if confirmation is None:
                return None
            recovery_raw = await redis.get(f"{RECOVERY_KEY_PREFIX}{confirmation.recovery_key}")
        if float(confirmation.issued_at) + AUTH_RECOVERY_CONFIRM_TTL < time.time():
            return None
        # FILL IN: rotation status — when recovery_raw is present, json_decoder(recovery_raw).get("confirm_key")
        #   must equal confirm_hash (compare with secrets.compare_digest), else return None. When recovery_raw is
        #   ABSENT (stage-1 TTL elapsed before stage 2 did): decide accept vs reject — recommended: reject (fail
        #   closed; the user re-requests recovery). Bounded by spec §3 M4 "current rotation status"; record the
        #   decision in the Completion Note. A malformed record (KeyError/ValueError from decoding) -> None.
        return confirmation
```
**Why**: `peek_confirmation` only checks the signature; the spec requires the recheck to include expiry and
rotation. Keeping it read-only is what lets a failed transaction be retried with the same confirmation (AC32).

### `navigator_auth/handlers/recovery/handler.py` (MODIFY) — block 2: imports and constants
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.events import security_transition' navigator_auth/handlers/recovery/handler.py)
# occurrences: 1 (verified: grep -c 'from navigator_auth.handlers.recovery.revoke import SessionRevoker' navigator_auth/handlers/recovery/handler.py)
# REPLACE — line 44 (verified: handler.py:44) with:
from navigator_auth.handlers.recovery.revoke import RevocationError, SessionRevoker
# REPLACE — line 47 (verified: handler.py:47) with:
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from navigator_auth.mfa.events import TransitionAborted, security_transition
from navigator_auth.mfa.exceptions import MfaStorageError, MfaUnavailable
from navigator_auth.mfa.security import advisory_user_lock
from navigator_auth.security_state.store import SecurityStateError, increment_generation, record_confirmation
# ADD `import secrets` after `import logging` (verified: handler.py:18), and below `logger = logging.getLogger("navigator.recovery")` (handler.py:49):
_USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"
# Consumption markers outlive the signed confirmation by this clock-skew margin (spec M4 durable contract).
_MARKER_SKEW_SECONDS = 300
```
**Why**: `_USERS` matches `User.Meta.schema/name` (models.py:68-70). If TASK-176 already changed line 44, merge
`RevocationError` into whatever import line it left — do not duplicate the import.

### `navigator_auth/handlers/recovery/handler.py` (MODIFY) — block 3: `_step2_validate` rotation lock
```python
# occurrences: 1 (verified: grep -c 'confirm_token, _confirmation = await self._store.issue_confirmation(token)' navigator_auth/handlers/recovery/handler.py)
# REPLACE — lines 236-239 (verified: handler.py:236-239), the try/except around issue_confirmation:
        try:
            # Rotation serializes with step-3 completion for the same user: take the per-user advisory
            # lock BEFORE changing Redis, so a rotation cannot land between step 3's recheck and commit.
            async with advisory_user_lock(self.request.app["authdb"], int(recovery_payload.user_id)):
                confirm_token, _confirmation = await self._store.issue_confirmation(token)
        except LookupError:
            return self.error(reason="Invalid or expired recovery link", status=400)
        except MfaStorageError:
            logger.warning("PasswordRecovery: rotation lock unavailable for user_id=%s", recovery_payload.user_id)
            return self.json_response(response={"error": "temporarily_unavailable"}, status=503)
```
**Why**: the lock body only touches Redis; its connection is the only DB connection held (G3). `LookupError`
from the body propagates unchanged after the rollback (advisory_user_lock re-raises body exceptions).

### `navigator_auth/handlers/recovery/handler.py` (MODIFY) — block 4: `_step3_confirm` phase 1
```python
# occurrences: 1 (verified: grep -c 'consumed = await self._store.consume_confirmation(token)' navigator_auth/handlers/recovery/handler.py)
# REPLACE — lines 264-297 (verified: handler.py:264-297): from the comment
#   '# Non-destructive peek first (D4/D5 for the read side): ...' through the 400 return after consume_confirmation
        # Phase 1 (pooled, released): non-destructive peek, user lookup, policy check (D4/D5).
        # Nothing is consumed here, so a policy failure leaves BOTH tokens usable.
        confirmation = await self._store.peek_confirmation(token)
        if confirmation is None:
            return self.error(reason="Invalid or expired confirmation token", status=400)
        db = self.request.app["authdb"]
        async with await db.acquire() as conn:
            User.Meta.connection = conn
            try:
                user = await User.get(user_id=confirmation.user_id)
            except NoDataFound:
                return self.error(reason="Invalid or expired confirmation token", status=400)
            captured_hash = getattr(user, "password", None)
        violations = self._policy.validate(password, current_hash=captured_hash)
        if violations:
            return self.json_response(
                response={"violations": [{"rule": v.rule, "message": v.message} for v in violations]},
                status=422,
            )
        new_hash = set_basic_password(password)
        digest = _hash_token(token)
        revoker = self.session_revoker()
```
**Why**: the pooled connection is released before the transition takes the lock (no nested acquire, AC10);
hashing runs outside the lock to keep its window short.

### `navigator_auth/handlers/recovery/handler.py` (MODIFY) — block 5: `_step3_confirm` phase 2 + post-commit
```python
# occurrences: 1 (verified: grep -c 'async with security_transition(' navigator_auth/handlers/recovery/handler.py)
# REPLACE — lines 299-325 (verified: handler.py:299-325): from 'async with security_transition(' through the 202 return
        # Phase 2: ONE connection, ONE transaction, per-user advisory lock (MFA on or off).
        try:
            async with security_transition(
                self.request.app, user.user_id, "recovery_completion", actor_user_id=user.user_id
            ) as conn:
                current = await conn.fetchval(f"SELECT password FROM {_USERS} WHERE user_id = $1 FOR UPDATE", user.user_id)
                if current is None or not secrets.compare_digest(str(current), str(captured_hash or "")):
                    raise TransitionAborted("credentials_changed")
                live = await self._store.current_confirmation(token)
                if live is None or int(live.user_id) != int(user.user_id):
                    raise TransitionAborted("invalid_confirmation")
                expires_at = datetime.fromtimestamp(
                    float(live.issued_at) + AUTH_RECOVERY_CONFIRM_TTL + _MARKER_SKEW_SECONDS, tz=timezone.utc
                )
                if not await record_confirmation(conn, digest, int(user.user_id), expires_at):
                    raise TransitionAborted("invalid_confirmation")  # committed marker: replay -> 400
                # D17 — self-service reset is NOT a superuser password_reset (is_new=True). Do not "harmonise".
                await conn.fetchval(
                    f"UPDATE {_USERS} SET password = $2, is_new = false WHERE user_id = $1 RETURNING user_id",
                    user.user_id,
                    new_hash,
                )
                await increment_generation(conn, int(user.user_id))
                revoked = await revoker.revoke_user(self.request, user, strict=True)
        except TransitionAborted as aborted:
            if aborted.reason == "credentials_changed":
                return self.json_response(response={"error": "credentials_changed"}, status=409)
            return self.error(reason="Invalid or expired confirmation token", status=400)
        except MfaUnavailable:
            return self.json_response(response={"error": "mfa_unavailable"}, status=503)
        except (MfaStorageError, RevocationError, SecurityStateError) as err:
            logger.error("PasswordRecovery: completion rolled back for user_id=%s: %s", user.user_id, type(err).__name__)
            return self.json_response(response={"error": "temporarily_unavailable"}, status=503)

        # After commit: Redis cleanup is best effort — the committed digest is authoritative (AC32).
        try:
            await self._store.drop_pair(live.recovery_key, digest)
        except Exception as err:  # pylint: disable=W0703
            logger.warning("PasswordRecovery: post-commit cleanup failed for user_id=%s: %s", user.user_id, type(err).__name__)
        logger.info("PasswordRecovery: revoked %d session/jti record(s) for user_id=%s", revoked, user.user_id)

        # D15 — no auto-login: no token/refresh_token in the response.
        return self.json_response(response={"action": "Password was changed successfully", "status": "OK"}, status=202)
```
**Why**: `MfaUnavailable` must be caught before `MfaStorageError` (it is a subclass). Raising `TransitionAborted`
for refusals keeps them at INFO in the transition log. `live` and `revoked` are bound whenever the `async with`
exits cleanly, which is the only path that reaches the post-commit code.

### `tests/test_password_recovery.py` (MODIFY) — block 6: append tests
```python
# AFTER — append a new class at the end of the file (verified: last test is
#   `test_step3_recovery_token_dead_after_success` in TestRecoveryEndToEnd, tests/test_password_recovery.py:1115)
# FILL IN: reuse the module-scoped `recovery_app` fixture (live Postgres + Redis, BasicAuth only, MFA off) and the
#   existing helper `_request_and_confirm_token(client, email)` (tests/test_password_recovery.py:493).
#   Every test must restore the user's password/state it changes (other tests share RECOVERY_TEST_USERNAME) or use
#   its own user inserted like `e2e_user` (tests/test_password_recovery.py:860).


class TestRecoveryTransactional:
    """FEAT-106 review fixes — transactional recovery completion (spec §3 M4)."""

    pytestmark = [
        pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
        pytest.mark.filterwarnings("ignore::DeprecationWarning"),
        pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
        pytest.mark.asyncio(loop_scope="module"),
    ]

    async def test_recovery_success_records_marker_and_generation(self, recovery_app):
        """AC15: success changes the password, records the digest, increments the generation, revokes sessions/jtis."""
        # FILL IN: bounded by AC15 bullet 1 (MFA-off parts; the bump/devices/audit part is covered by tests/test_mfa_e2e.py).
        raise NotImplementedError

    async def test_recovery_revocation_failure_rolls_back(self, recovery_app, monkeypatch):
        """AC15/AC31: a strict revoke_user failure -> 503; password, generation and marker unchanged; same confirmation retries OK."""
        # FILL IN: monkeypatch SessionRevoker.revoke_user to raise RevocationError when strict=True; bounded by AC15, AC31, AC32.
        raise NotImplementedError

    async def test_recovery_hash_drift_409(self, recovery_app, monkeypatch):
        """AC15: a hash change between phase 1 and phase 2 answers 409 and consumes nothing."""
        # FILL IN: change the stored hash after phase 1 (e.g. patch set_basic_password to UPDATE the row first); bounded by AC15.
        raise NotImplementedError

    async def test_recovery_confirmation_transactional(self, recovery_app, monkeypatch):
        """AC32: concurrent reuse succeeds exactly once (MFA off); a committed marker rejects replay even if drop_pair fails."""
        # FILL IN: asyncio.gather two confirms of the same token -> exactly one 202; then make drop_pair raise, complete a
        #   fresh recovery, and replay it with a DIFFERENT valid password -> 400. Bounded by AC32.
        raise NotImplementedError

    async def test_recovery_mfa_failures_503(self, recovery_app, monkeypatch):
        """AC13/AC14 (recovery): MFA unavailable -> 503 mfa_unavailable; write_audit or commit fault -> 503; nothing changes."""
        # FILL IN: monkeypatch navigator_auth.mfa.events.mfa_services_lease (TASK-173/177) to yield services with
        #   available=False (AC13) and, separately, real MfaSecurity on the app's authdb with write_audit raising (AC14);
        #   assert hash, generation and marker unchanged and the same confirmation still works afterwards. Bounded by AC13, AC14, AC32.
        raise NotImplementedError

    async def test_recovery_single_connection(self, single_connection_authdb):
        """AC10: recovery completion finishes on a one-connection authdb within 10 s; no acquire under the lock."""
        # FILL IN: drive _step2_validate/_step3_confirm with app["authdb"] = single_connection_authdb (TASK-171 fixture,
        #   import from tests.fixtures.mfa) under asyncio.wait_for(..., 10); assert acquires_inside_lock == []. Bounded by AC10.
        raise NotImplementedError
```
**Why**: the live `recovery_app` fixture exercises the real handler, Redis and Postgres (with TASK-175's tables
created at startup), which is what AC15/AC32 require; MFA-on variants inject through the services lease.

### FILL IN checklist
- [ ] `store.py::RecoveryTokenStore.current_confirmation` — rotation check; absent stage-1 record → accept vs reject (recommended reject); bounded by spec §3 M4 "current rotation status".
- [ ] Test harness — module fixture reuse and state restoration; only symbols from the Codebase Contract or TASK-171/173/175/176/177.
- [ ] `test_recovery_success_records_marker_and_generation` — AC15.
- [ ] `test_recovery_revocation_failure_rolls_back` — AC15, AC31, AC32.
- [ ] `test_recovery_hash_drift_409` — AC15.
- [ ] `test_recovery_confirmation_transactional` — AC32.
- [ ] `test_recovery_mfa_failures_503` — AC13, AC14.
- [ ] `test_recovery_single_connection` — AC10.

---

## Acceptance Criteria

- [ ] `_step3_confirm` never calls `consume_confirmation`; phase 1 releases its connection before the transition; phase 2 writes marker, password and generation on the transition connection and strictly revokes before commit; `drop_pair` runs after commit, best effort.
- [ ] `_step2_validate` rotates the confirmation only while holding `advisory_user_lock` for the user.
- [ ] AC13 (recovery) — 2FA on + MFA unavailable → 503 `mfa_unavailable`, credential unchanged.
- [ ] AC14 (recovery) — a `write_audit` fault (and separately a commit fault) leaves hash, security version and trusted devices unchanged; 503.
- [ ] AC15 — success changes the password, bumps the version, revokes devices, writes the audit row (MFA on), records the confirmation digest and revokes sessions and jtis; a `revoke_user` failure rolls the change back (503); hash drift answers 409.
- [ ] AC31 (recovery) — injected session-Redis / JTI-index / per-token errors in strict revocation → 503, password and generation unchanged.
- [ ] AC32 — revocation, audit and commit failures after the marker insertion roll back password, generation and marker, and the same unexpired confirmation can be retried; concurrent reuse succeeds exactly once (MFA disabled too); a committed marker rejects replay even when Redis cleanup fails.
- [ ] AC10 (recovery) — completes on a one-connection `authdb` within 10 s; no `acquire()` while `LOCK_CONNECTION` is set.
- [ ] Existing recovery suites stay green (AC21), including `test_federated_user_can_recover`, `test_step3_revokes_sessions`, `test_token_never_logged`.
- [ ] No linting errors: `ruff check navigator_auth/handlers/recovery/` (if ruff is configured).

---

## Validation Commands

- `pytest tests/test_password_recovery.py -q`
- `pytest tests/test_mfa_e2e.py -q`

---

## Test Specification

```python
# tests/test_password_recovery.py (appended — see blueprint block 6)
class TestRecoveryTransactional:
    async def test_recovery_success_records_marker_and_generation(self, recovery_app): ...      # AC15
    async def test_recovery_revocation_failure_rolls_back(self, recovery_app, monkeypatch): ... # AC15/AC31/AC32
    async def test_recovery_hash_drift_409(self, recovery_app, monkeypatch): ...                # AC15
    async def test_recovery_confirmation_transactional(self, recovery_app, monkeypatch): ...    # AC32
    async def test_recovery_mfa_failures_503(self, recovery_app, monkeypatch): ...              # AC13/AC14
    async def test_recovery_single_connection(self, single_connection_authdb): ...              # AC10
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above for full context (§3 M4 recovery completion + durable recovery and token revocation contract; §5 AC10, AC13–AC15, AC31, AC32).
3. **Check dependencies** — TASK-171, TASK-175, TASK-176 and TASK-177 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — before writing ANY code:
   - Confirm every import in "Verified Imports" still exists (`grep` or `read` the source)
   - Confirm every class/method in "Existing Signatures" still has the listed attributes
   - If anything has changed, update the contract FIRST, then implement
   - **NEVER** reference an import, attribute, or method not in the contract without verifying it exists
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"`
   (set `started_at`) and commit only that index file
6. **Implement** — start from the Implementation Blueprint blocks, complete every
   `# FILL IN:` marker, and never change a signature or path the blueprint fixes
7. **Verify** all acceptance criteria are met — run the Validation Commands
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`)
9. **Close the task** with `parrot sdd task close TASK-180 basicauth-otp-2fa-review-fixes verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any (expected: phase-2 re-read/write via explicit SQL instead of `User.get`/`User.update`; the absent-stage-1-record rotation decision)
