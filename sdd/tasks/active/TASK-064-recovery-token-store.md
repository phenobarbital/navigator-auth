# TASK-064: `RecoveryTokenStore` — two-stage signed Redis token store

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 3)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-062
**Assigned-to**: unassigned

---

## Context

The security core of the feature. It holds the two linked tokens that separate
*"you proved you opened the mailbox"* (stage 1, 1 hour) from *"you are
authorized to write a password"* (stage 2, 15 minutes).

It replaces `RecoveryTokenStorage` in the current `handlers/recovery.py:22`,
which is broken in three ways worth knowing before you start: it encodes with a
*decoder* (`json_decoder(data)` at line 29), opens a new Redis client on every
request and never closes it, and keys Redis by the raw token.

---

## Scope

- Implement `RecoveryTokenStore` in `navigator_auth/handlers/recovery/store.py`.
- HMAC-SHA256 signing, `sha256(token)` key derivation, both stage lifecycles.
- Pooled `aioredis.ConnectionPool`, created once and injected.

**NOT in scope**: the handler, HTTP concerns, rate limiting, the policy
validator, session revocation. Do not delete the old `recovery.py` —
TASK-067 does that.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/recovery/store.py` | CREATE | `RecoveryTokenStore` |
| `tests/test_password_recovery.py` | MODIFY | Add `TestRecoveryTokenStore` |

---

## Implementation Notes

### Pattern to Follow

Copy the shape of `navigator_auth/identity/flow_store.py` — pooled connection,
`setex` to write, `getdel` for single-use consumption:

```python
class RecoveryTokenStore:
    def __init__(self, pool: aioredis.ConnectionPool, secret: bytes): ...

    async def issue_recovery(self, user) -> tuple[str, RecoveryPayload]: ...
    async def validate_recovery(self, token: str) -> Optional[RecoveryPayload]: ...
    async def issue_confirmation(self, token: str) -> tuple[str, ConfirmationPayload]: ...
    async def consume_confirmation(self, token: str) -> Optional[ConfirmationPayload]: ...
    async def drop_pair(self, recovery_key: str, confirm_key: str) -> None: ...
```

Do **not** subclass `IdentityFlowStore` — different key namespace and a signing
concern it does not have.

### Key derivation (D12) — the point of the design

- The token handed out is random: `secrets.token_urlsafe(32)`.
- The payload carries `signature = HMAC-SHA256(secret, f"{user_id}:{username}:{issued_at}:{nonce}")`.
- **Redis is keyed by `hashlib.sha256(token).hexdigest()`, never the token.**
  Namespaces: `auth:recovery:{sha256}` and `auth:recovery:confirm:{sha256}`.

The consequence to preserve: someone who dumps Redis sees hashed keys and signed
payloads, and **cannot reconstruct a usable token**. A test asserts this by
scanning every key and value.

### Stage semantics (D4, D5) — read carefully, this is the subtle part

| Operation | Redis op | Effect |
|---|---|---|
| `issue_recovery` | `SETEX` ttl=`AUTH_RECOVERY_TTL` | stage-1 record |
| `validate_recovery` | **`GET`** — *not* `GETDEL` | stage-1 **survives**; may be called repeatedly |
| `issue_confirmation` | `DEL` old confirm, then `SETEX` ttl=`AUTH_RECOVERY_CONFIRM_TTL` | **rotates**: the previous stage-2 token stops working |
| `consume_confirmation` | `GETDEL` | single use |
| `drop_pair` | `DEL` both | end of flow; link cannot be replayed |

Rotation needs a back-pointer: the stage-1 payload must record the
`sha256` of the currently-live stage-2 token so `issue_confirmation` can delete
it. Update the stage-1 record in place (preserving its **remaining** TTL — use
`KEEPTTL`, or read the TTL and re-apply it; do **not** reset it to a fresh hour).

`ConfirmationPayload.recovery_key` is the forward link, so step 3 can call
`drop_pair` with both keys.

### Key Constraints

- `secrets.compare_digest` for every signature check. Never `==`.
- `json_encoder` to write, `json_decoder` to read (`navigator_auth/libs/json.py`).
  The old module has these backwards — do not copy it.
- A tampered payload must fail the signature check, not raise.
- A token minted under a different secret must be rejected (secret rotation
  invalidates in-flight recoveries by design).
- Never log a raw token, at any level.

### References in Codebase
- `navigator_auth/identity/flow_store.py` — the pattern to copy
- `navigator_auth/backends/external.py:165` — `ConnectionPool.from_url(REDIS_AUTH_URL, ...)` and the `on_cleanup` disconnect
- `navigator_auth/handlers/recovery.py:22` — the broken implementation being replaced

---

## Acceptance Criteria

- [ ] Redis contains no raw token: scanning all keys **and** values after
      `issue_recovery` + `issue_confirmation` finds neither token string
- [ ] `validate_recovery` twice both succeed and the record still exists (D4)
- [ ] `issue_confirmation` twice: only the newest token is accepted
- [ ] `consume_confirmation` twice: the second returns `None`
- [ ] Rotation preserves the stage-1 TTL rather than extending it
- [ ] Wrong-secret and tampered-payload tokens are rejected without raising
- [ ] TTLs are ≈3600 and ≈900
- [ ] `pytest tests/test_password_recovery.py -k Store -v` passes

---

## Test Specification

```python
class TestRecoveryTokenStore:
    async def test_store_key_is_hashed(self, recovery_store, redis):
        token, _ = await recovery_store.issue_recovery(user)
        keys = await redis.keys("auth:recovery:*")
        assert not any(token in k for k in keys)
        for k in keys:
            assert token not in (await redis.get(k) or "")

    async def test_store_recovery_survives_validate(self, recovery_store):
        token, _ = await recovery_store.issue_recovery(user)
        assert await recovery_store.validate_recovery(token) is not None
        assert await recovery_store.validate_recovery(token) is not None   # D4

    async def test_store_confirmation_rotates(self, recovery_store):
        token, _ = await recovery_store.issue_recovery(user)
        c1, _ = await recovery_store.issue_confirmation(token)
        c2, _ = await recovery_store.issue_confirmation(token)
        assert await recovery_store.consume_confirmation(c1) is None
        assert await recovery_store.consume_confirmation(c2) is not None

    async def test_rotation_preserves_stage1_ttl(self, recovery_store, redis):
        token, _ = await recovery_store.issue_recovery(user)
        # advance/inspect: TTL must not jump back up to the full hour
        before = await redis.ttl(key_of(token))
        await recovery_store.issue_confirmation(token)
        assert await redis.ttl(key_of(token)) <= before

    async def test_store_confirmation_single_use(self, recovery_store): ...
    async def test_store_signature_roundtrip(self, recovery_store): ...
    async def test_store_wrong_secret_rejected(self, redis_pool): ...
    async def test_store_ttls(self, recovery_store, redis): ...
    async def test_store_expired_returns_none(self, recovery_store): ...
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify TASK-062 is in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-064-recovery-token-store.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
