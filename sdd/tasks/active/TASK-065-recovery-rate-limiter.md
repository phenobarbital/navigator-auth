# TASK-065: `RateLimiter` for the recovery request endpoint

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 4)
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-062
**Assigned-to**: unassigned

---

## Context

Step 1 of the recovery flow is public and unauthenticated. Without a throttle it
is an inbox-spam tool (repeat one address) and an enumeration oracle (sweep many
addresses). This task provides the counter; TASK-067 wires it in.

---

## Scope

- Implement `RateLimiter` in `navigator_auth/handlers/recovery/limiter.py`.
- Fixed-window Redis counter, reusing the existing spec parser.
- Fail **open** on Redis errors.

**NOT in scope**: a generic app-wide rate-limit middleware (explicit non-goal in
the spec), the handler wiring, HTTP 429 shaping.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/recovery/limiter.py` | CREATE | `RateLimiter` |
| `tests/test_password_recovery.py` | MODIFY | Add `TestRateLimiter` |

---

## Implementation Notes

### Interface

```python
class RateLimiter:
    def __init__(self, pool: aioredis.ConnectionPool, spec: str, prefix: str): ...

    async def check(self, key: str) -> bool:
        """True == allowed."""
```

### Reuse the existing parser — do not write another

`parse_rate_limit` already exists at `navigator_auth/backends/oauth2/dcr.py:104`:

```python
from ..backends.oauth2.dcr import parse_rate_limit
count, seconds = parse_rate_limit("3/hour")   # -> (3, 3600)
```

It accepts `"<count>/<window>"` with `second|minute|hour|day` (singular or
plural) and **returns `(0, 0)` for anything unparseable**, which the caller must
treat as "limiting disabled". That behaviour is deliberate — a malformed setting
must not take the endpoint down — so preserve it rather than raising.

### Counter mechanics

Fixed window, two commands on the first hit of a window:

```
INCR   auth:recovery:rate:{prefix}:{key}
EXPIRE auth:recovery:rate:{prefix}:{key} {seconds}   # only when INCR returned 1
```

Allowed when the post-increment value is `<= count`. Use a pipeline so the two
commands are one round trip. Setting `EXPIRE` only when `INCR` returns 1 is what
makes it a *fixed* window; setting it every time would turn it into a sliding
window that never expires under sustained load.

### Fail-open is deliberate (spec Gotchas)

Any Redis exception → return `True` and log at **WARNING**. A cache outage must
not lock every user out of password recovery. The trade-off — an outage also
lifts the throttle — is accepted and must be visible in the logs.

### Key Constraints

- Hash or normalise the e-mail before using it as a key component: lowercase and
  strip, and do not place a raw address in a Redis key that may be dumped.
  `sha256(email.strip().lower())` is sufficient.
- `prefix` separates the two limiters (`"email"` / `"ip"`) so they count
  independently.
- Never raise out of `check()`.

### References in Codebase
- `navigator_auth/backends/oauth2/dcr.py:104` — `parse_rate_limit`
- `navigator_auth/backends/external.py:165` — pooled Redis construction

---

## Acceptance Criteria

- [ ] 3 calls under `"3/hour"` allowed; the 4th blocked
- [ ] The window expires and re-allows
- [ ] A Redis error makes `check()` return `True` and log a WARNING
- [ ] A malformed spec (`"garbage"`) disables limiting entirely — never blocks
- [ ] `"email"` and `"ip"` prefixes count independently
- [ ] No raw e-mail address appears in any Redis key
- [ ] `check()` never raises
- [ ] `pytest tests/test_password_recovery.py -k Limiter -v` passes

---

## Test Specification

```python
class TestRateLimiter:
    async def test_limiter_allows_under_limit(self, redis_pool):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        assert all([await rl.check("a@b.c") for _ in range(3)])

    async def test_limiter_blocks_over_limit(self, redis_pool):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        for _ in range(3): await rl.check("a@b.c")
        assert await rl.check("a@b.c") is False

    async def test_limiter_fails_open(self, broken_redis_pool, caplog):
        rl = RateLimiter(broken_redis_pool, "3/hour", "email")
        assert await rl.check("a@b.c") is True
        assert "WARNING" in caplog.text

    async def test_limiter_malformed_spec_disables(self, redis_pool):
        rl = RateLimiter(redis_pool, "garbage", "email")
        assert all([await rl.check("a@b.c") for _ in range(50)])

    async def test_limiter_prefixes_independent(self, redis_pool):
        e = RateLimiter(redis_pool, "3/hour", "email")
        i = RateLimiter(redis_pool, "3/hour", "ip")
        for _ in range(3): await e.check("x")
        assert await i.check("x") is True

    async def test_no_raw_email_in_keys(self, redis_pool, redis):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        await rl.check("user@example.com")
        assert not any("user@example.com" in k for k in await redis.keys("*"))
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify TASK-062 is in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-065-recovery-rate-limiter.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
