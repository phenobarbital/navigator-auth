# TASK-066: `jti` on Basic JWTs + `SessionRevoker`

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 5)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-062
**Assigned-to**: unassigned

---

## Context

This is what makes "revoke sessions on password reset" real rather than
cosmetic. Today a Basic-auth JWT carries **no `jti`**, so a token issued before a
reset stays valid until its `exp` — an attacker holding one keeps access after
the victim recovers their account.

**This task was blocked on FEAT-096 and is now unblocked**: FEAT-096 merged into
`dev` on 2026-09-04, and `BasicAuth.open_session()` exists at
`navigator_auth/backends/basic.py:135` with the signature the spec anticipated.
Write the `jti` record **inside `open_session()`**, not in `authenticate()` —
that way token-exchange sessions (FEAT-096) inherit revocability for free.

The happy accident worth knowing: **the auth middleware needs no change.**
`AuthHandler._token_is_revoked` (`navigator_auth/auth.py:985`) already walks
every backend looking for an `access_token_storage` attribute and checks any
token carrying a `jti`. Emitting the claim and attaching the storage is enough.

---

## Scope

- `IdentityProvider.create_token` emits a `jti` claim.
- `BasicAuth` gains an `access_token_storage` and records the minted `jti`
  inside `open_session()`, plus a per-user jti index.
- Implement `SessionRevoker` in `navigator_auth/handlers/recovery/revoke.py`.

**NOT in scope**: modifying `auth.py` or any middleware (already generic — if
you find yourself editing it, stop and re-read `_token_is_revoked`); the
recovery handler; OAuth2 token behaviour.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/idp/__init__.py` | MODIFY | `create_token` (~line 378) emits `jti` |
| `navigator_auth/backends/basic.py` | MODIFY | `access_token_storage`; record jti in `open_session()` (~line 190) |
| `navigator_auth/handlers/recovery/revoke.py` | CREATE | `SessionRevoker` |
| `tests/test_password_recovery.py` | MODIFY | Add `TestJTI`, `TestSessionRevoker` |

---

## Implementation Notes

### 1. Emit the `jti` (`backends/idp/__init__.py:378`)

`create_token` already builds `payload` and strips reserved claims. Add `jti` the
same additive way `aud` was added by FEAT-093 (the precedent is in the same
function):

```python
payload = {
    "exp": exp,
    "iat": iat,
    "iss": issuer,
    "jti": str(uuid4()),     # NEW — unique per token
    **data,
}
```

Use `str(uuid4())`, not `token_urlsafe`: `OauthAccessTokenRecord.jti` is typed
`UUID` (`backends/oauth2/models.py:303`) and the value must round-trip through it.

Add `"jti"` to the reserved-key strip list at the top of the function so a caller
cannot inject its own via `data`.

### 2. Attach storage and record the jti (`backends/basic.py`)

Give `BasicAuth` an `access_token_storage` — the attribute name is **load-bearing**,
`_token_is_revoked` looks it up by exactly that name:

```python
from .oauth2.code_backend import AccessTokenStorage
...
self.access_token_storage = AccessTokenStorage()
```

In `open_session()`, right after the `create_token` call (~line 190), decode or
capture the `jti` and persist a record. `AccessTokenStorage.save` expects an
`OauthAccessTokenRecord`, which requires `client_id`; **use the literal
`"basic"`** — these are not OAuth2 clients, and the value is only used for
bookkeeping and DB joins that Basic sessions never take.

```python
record = OauthAccessTokenRecord(
    jti=jti, user_id=uid, client_id="basic",
    expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
)
await self.access_token_storage.save(record)
await self._index_user_jti(uid, jti, ttl)     # see below
```

Storing a real record matters: `AccessTokenStorage.revoke` reads it to compute
how long the revocation marker must live (`code_backend.py:347`). With no record
it falls back to a flat 3600 s, which would be **too short** if `SESSION_TIMEOUT`
is longer — a revoked token would start passing again once the marker expired.

### 3. The per-user jti index (new)

Revocation needs to find a user's live tokens. `AccessTokenStorage` is keyed by
jti only, so add a Redis SET:

```
auth:user:jti:{user_id}  ->  {jti, jti, ...}     TTL = session lifetime
```

`SADD` on issue, and refresh the key's TTL to the longest member lifetime. Prune
opportunistically: `SessionRevoker` should `SREM` jtis it revokes.

### 4. `SessionRevoker`

```python
class SessionRevoker:
    async def revoke_user(self, request, user) -> int:
        """Returns the count killed. Best-effort per record."""
```

Two halves, both required:

- **Redis session**: delete `session:{session_id}` **and** the `user:{identity}`
  index key that `navigator_session` writes (`storages/redis.py:275`, ~line 320).
  For Basic auth the identity is the **username** (`backends/basic.py:159` calls
  `remember(request, username, ...)`), not the user_id — getting this wrong
  silently no-ops.
- **JWTs**: for each jti in `auth:user:jti:{user_id}`, call
  `access_token_storage.revoke(jti)`, then `SREM` it.

Wrap each deletion individually: one failure must not abort the rest. Return the
count actually revoked.

### Key Constraints

- **Backward compatibility is non-negotiable.** Tokens minted before this change
  carry no `jti`; `_token_is_revoked` short-circuits on a missing `jti`
  (`auth.py:993`), so they must keep authenticating. There is a test for this.
- Do not change the shape of the Basic login response.
- `tests/test_basic_auth.py` and `tests/test_login.py` must pass **unmodified** —
  they are the regression gate for this task.
- Be aware of the blast radius: every Basic login now writes to Redis and every
  authenticated request carrying a `jti` costs a lookup. This affects **all**
  Basic traffic, not just recovery.

### References in Codebase
- `navigator_auth/auth.py:985` — `_token_is_revoked`, already generic
- `navigator_auth/backends/oauth2/code_backend.py:316` — `AccessTokenStorage`
- `navigator_auth/backends/oauth2/models.py:296` — `OauthAccessTokenRecord`
- `navigator_auth/backends/basic.py:135` — `open_session` (FEAT-096)
- `/home/jesuslara/proyectos/navigator-session/navigator_session/storages/redis.py:275` — where `user:{identity}` is written

---

## Acceptance Criteria

- [ ] `create_token` emits a unique `jti`; a caller cannot inject one via `data`
- [ ] `BasicAuth.access_token_storage` exists under exactly that name
- [ ] A Basic login writes both a jti record and the per-user index entry
- [ ] A token-exchange login (FEAT-096) also gets a jti — verify `open_session`
      is the single write point
- [ ] A JWT minted **without** a `jti` still authenticates (backward compat)
- [ ] `SessionRevoker.revoke_user` removes `session:{sid}` **and** `user:{username}`
- [ ] A revoked jti is rejected by `_token_is_revoked` with **no** middleware change
- [ ] The revocation marker outlives the token (TTL from the record, not the 3600 fallback)
- [ ] One failing deletion does not abort the others
- [ ] `tests/test_basic_auth.py` and `tests/test_login.py` pass **unmodified**
- [ ] `pytest tests/test_password_recovery.py -k "JTI or Revoker" -v` passes

---

## Test Specification

```python
class TestJTI:
    def test_create_token_emits_jti(self, idp):
        tok, _, _, _ = idp.create_token(data={"user_id": 1})
        _, payload = idp.decode_token(tok)
        assert "jti" in payload
        tok2, _, _, _ = idp.create_token(data={"user_id": 1})
        assert idp.decode_token(tok2)[1]["jti"] != payload["jti"]

    def test_caller_cannot_inject_jti(self, idp):
        tok, _, _, _ = idp.create_token(data={"user_id": 1, "jti": "attacker"})
        assert idp.decode_token(tok)[1]["jti"] != "attacker"

    async def test_jti_absent_token_still_valid(self, auth_handler):
        """A pre-upgrade JWT with no jti must keep working."""
        payload = {"user_id": 1}          # minted the old way, no jti
        assert await auth_handler._token_is_revoked(payload) is False


class TestSessionRevoker:
    async def test_revoker_kills_session_and_index(self, revoker, redis, logged_in_user):
        await revoker.revoke_user(request, logged_in_user)
        assert await redis.get(f"session:{sid}") is None
        assert await redis.get(f"user:{logged_in_user['username']}") is None

    async def test_revoker_revokes_jwt(self, revoker, auth_handler, logged_in_user):
        await revoker.revoke_user(request, logged_in_user)
        assert await auth_handler._token_is_revoked({"jti": issued_jti}) is True

    async def test_revocation_marker_outlives_token(self, revoker, redis):
        """TTL comes from the saved record, not the 3600s fallback."""

    async def test_revoker_partial_failure(self, revoker, flaky_redis):
        """One failing delete does not abort the rest; count reflects reality."""
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify TASK-062 is in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-066-basic-jti-session-revocation.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: sdd-worker (session_016Z3wYUV42WJDq92pifU1Fa)
**Date**: 2026-09-04
**Notes**: `create_token` (`backends/idp/__init__.py`) now emits
`"jti": str(uuid4())` and strips any caller-supplied `jti` from `data`
first. `BasicAuth.access_token_storage = AccessTokenStorage()` is set
in `on_startup` (and closed in `on_cleanup`, added to prevent a Redis
client leak that otherwise hangs `pytest-asyncio`'s per-test
`asyncio.Runner.close()` at teardown). `open_session()` records the
minted jti's `OauthAccessTokenRecord` (`expires_at` kept **naive** —
`AccessTokenStorage.revoke()`/`save()` compute `expires_at - _now()`
where `_now()` is naive `datetime.now()`; an aware `expires_at` raised
`TypeError: can't subtract offset-naive and offset-aware datetimes`,
caught silently by the best-effort try/except until traced down via
`tests/test_basic_open_session.py`) and indexes it in a new
`auth:user:jti:{user_id}` Redis SET via `BasicAuth._index_user_jti`,
best-effort so a Redis hiccup never fails a login. `SessionRevoker`
(`handlers/recovery/revoke.py`) kills `session:{sid}` +
`user:{identity}` and every jti in the per-user index (found by
walking `request.app['auth'].backends`, mirroring
`_token_is_revoked`), with every deletion independently try/excepted.
`auth.py` was not touched. Started the existing (stopped)
`docker_postgres_1` container alongside `docker_redis_1` to run the
regression gate — `tests/test_basic_auth.py`/`tests/test_login.py`
now mostly execute instead of erroring on missing connections;
confirmed byte-identical pass/fail counts (8 passed / 1 pre-existing
`test_login_endpoint` failure needing an external `nav-api.dev.local`
server) against unmodified `dev` with the same services running, so no
regression. `tests/test_basic_open_session.py` (FEAT-096) passes
unchanged (5/5). Added `TestJTI` (3 tests) and `TestSessionRevoker` (4
tests, including `test_revocation_marker_outlives_token` and
`test_revoker_partial_failure` from the task's own list) to
`tests/test_password_recovery.py`; all 37 tests in the file pass;
ruff clean (only the 4 pre-existing unused-import warnings in
`basic.py`, confirmed present before this task too).

**Deviations from spec**: None architecturally. Two things worth
flagging: (1) added a `BasicAuth.on_cleanup` body (closing
`access_token_storage.redis`) — not in the task's Files table, but
required once `access_token_storage` became a real live connection
held for the backend's lifetime, otherwise tests using a
module-scoped app hang indefinitely at asyncio teardown; `on_cleanup`
was previously an empty stub. (2) `OauthAccessTokenRecord.expires_at`
is constructed with a naive `datetime.fromtimestamp(exp)` rather than
an aware one, to match the naive-datetime convention `_now()` and
every other caller of `AccessTokenStorage`/`OauthAccessTokenRecord`
in `backends/oauth2/backend.py` already use — using `timezone.utc`
here (the more "correct" choice in isolation) breaks TTL computation
against that pre-existing convention.
