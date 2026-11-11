# TASK-224: Atomic authorization-code consume and a configurable claim TTL

**Feature**: FEAT-108 — OAuth2 3LO issues
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:cf77c0161ff6`

---

## Context

FEAT-108 (TASK-204, review fixes `d0fa3a1`) resolves the resource owner *before* it
consumes an authorization code, so an identity-store outage leaves the code
retryable. To stop two concurrent redeemers it added a Redis claim
(`AuthorizationCodeStorage.claim_code`, `SET NX EX 30`). Two defects remain
(ledger `issue:cf77c0161ff6`):

1. `AuthorizationCodeStorage.mark_used` is a get-then-set: it returns `True` for
   every caller that reads the code before the first one deletes it. The claim
   compensates only for 30 hard-coded seconds; a redemption slower than that lets a
   second redeemer claim the same code and both mint tokens.
2. A held claim is answered `invalid_grant "Authorization code already used."`
   even when the code was never consumed — a client retrying while the first
   attempt is still in flight (e.g. during an identity-store outage) gets a fatal
   error for a code that is still redeemable.

The per-user advisory lock (`_user_generation`) already serializes redemptions in
one deployment; these fixes are the storage-level guarantee behind it.

---

## Scope

- Make `AuthorizationCodeStorage.mark_used` atomic: exactly one caller per code
  gets `True`, using a `SET <prefix>used:<code> 1 NX EX <OAUTH_CODE_TTL>` marker
  before the record update. Keep the existing `used=True` / `used_at` record update
  so `get_code(...).used` keeps working.
- Add `OAUTH_CODE_CLAIM_TTL` (int seconds, default `30`) to `navigator_auth/conf.py`
  next to `OAUTH_CODE_TTL`; `claim_code(code, ttl=None)` uses it when `ttl` is `None`.
- In `Oauth2Provider._handle_authorization_code`, when the claim is held, re-read
  the code: answer `invalid_grant "Authorization code already used."` only when it
  is gone or marked used; otherwise answer the retryable
  `self._owner_store_unavailable()` (503) without touching the code.
- Update the held-claim test in `tests/test_oauth2_unknown_resource_owner.py` and
  add storage + grant tests in a new `tests/test_oauth2_code_redemption.py`.

**NOT in scope**: moving session creation (TASK-225); userinfo/introspection
(TASK-226); the in-memory test storages' `mark_used` fakes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | Add `OAUTH_CODE_CLAIM_TTL` |
| `navigator_auth/backends/oauth2/code_backend.py` | MODIFY | Atomic `mark_used`; `claim_code` default TTL from conf |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Held claim → re-read the code; 503 while it is still pending |
| `tests/test_oauth2_unknown_resource_owner.py` | MODIFY | Held-claim test split into consumed / still-pending |
| `tests/test_oauth2_code_redemption.py` | CREATE | Atomic `mark_used` and claim-TTL tests |

---

## Codebase Contract (Anti-Hallucination)

Verified on `feat-FEAT-108-oauth2-3lo-issues` @ `30dee03` (the code below exists only on
the feature branch, not on `dev`).

### Verified Imports
```python
from ...conf import REDIS_URL  # verified: navigator_auth/backends/oauth2/code_backend.py:22
from navigator_auth.backends.oauth2.code_backend import AuthorizationCodeStorage  # tests/test_oauth2_unknown_resource_owner.py
```

### Existing Signatures to Use
```python
# navigator_auth/conf.py:810
OAUTH_CODE_TTL = config.getint("OAUTH_CODE_TTL", fallback=600)

# navigator_auth/backends/oauth2/code_backend.py
class AuthorizationCodeStorage:                         # line 45
    prefix = "oauth2:code:"                             # set in __init__, line 55
    async def get_code(self, code: str): ...            # line 73
    async def mark_used(self, code: str) -> bool: ...   # line 88 (get-then-set; NOT atomic)
    async def delete_code(self, code: str): ...         # line 104
    async def claim_code(self, code: str, ttl: int = 30) -> bool: ...  # line 109
    async def release_claim(self, code: str) -> None: ...              # line 113

# navigator_auth/backends/oauth2/backend.py
def _owner_store_unavailable(self) -> web.StreamResponse: ...          # line 534 (503 server_error)
async def _handle_authorization_code(self, payload, request): ...      # line 2171
#   claim block: `claim = getattr(self.code_storage, "claim_code", None)` line 2251
#   `if claim is not None and not await claim(code):` line 2252
```

### Does NOT Exist
- ~~`OAUTH_CODE_CLAIM_TTL`~~ — not in `navigator_auth/conf.py` yet (this task adds it)
- ~~`AuthorizationCodeStorage.consume_code`~~ — no such method; keep `mark_used`
- ~~`redis.getdel`-based consume~~ — not used anywhere; the `SET NX` marker is the chosen primitive

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/conf.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/oauth2/code_backend.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_unknown_resource_owner.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_code_redemption.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/code_backend.py#AuthorizationCodeStorage",
    "sym:navigator_auth/backends/oauth2/code_backend.py#AuthorizationCodeStorage.mark_used",
    "sym:navigator_auth/backends/oauth2/code_backend.py#AuthorizationCodeStorage.claim_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_authorization_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._owner_store_unavailable"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Add `OAUTH_CODE_CLAIM_TTL` to `conf.py` — *why*: the claim TTL must be operator-tunable.
2. Make `mark_used` gate on an atomic `SET NX` marker — *why*: only one redeemer may ever win, regardless of the claim TTL.
3. Default `claim_code`'s TTL from conf — *why*: callers and fakes keep calling `claim(code)`.
4. Answer a held claim by the code's real state — *why*: a pending code must stay retryable.

### `navigator_auth/conf.py` (MODIFY)
```python
# AFTER — insert below `OAUTH_CODE_TTL = config.getint("OAUTH_CODE_TTL", fallback=600)` (verified: line 810)

# Seconds an in-flight authorization-code redemption holds its claim (FEAT-108).
OAUTH_CODE_CLAIM_TTL = config.getint("OAUTH_CODE_CLAIM_TTL", fallback=30)
```

### `navigator_auth/backends/oauth2/code_backend.py` (MODIFY)
```python
from ...conf import REDIS_URL, OAUTH_CODE_TTL, OAUTH_CODE_CLAIM_TTL

    async def mark_used(self, code: str) -> bool:
        """Consume ``code`` atomically (B5): ``True`` for exactly one caller."""
        if not await self.redis.set(f"{self.prefix}used:{code}", "1", nx=True, ex=OAUTH_CODE_TTL):
            return False
        obj = await self.get_code(code)
        if not obj:
            return False
        # FILL IN: keep the used=True / used_at re-save (ex=5) the old body did.

    async def claim_code(self, code: str, ttl: Optional[int] = None) -> bool:
        ttl = OAUTH_CODE_CLAIM_TTL if ttl is None else ttl
        return bool(await self.redis.set(f"{self.prefix}claim:{code}", "1", nx=True, ex=ttl))
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY)
```python
# REPLACE `if claim is not None and not await claim(code):` + its return (verified: line 2252)
if claim is not None and not await claim(code):
    current = await self.code_storage.get_code(code)
    if current is None or current.used:
        return self._error_response("invalid_grant", "Authorization code already used.")
    # Another redemption of this still-unconsumed code is in flight: retryable.
    return self._owner_store_unavailable()
```

### FILL IN checklist
- [ ] `mark_used` — re-save `used=True`, `used_at=_now()` with `ex=5`, return `True`.
- [ ] Held-claim test: consumed code → "already used"; pending code → 503 and no `mark_used`/`delete`.

---

## Acceptance Criteria

- [ ] Two concurrent `mark_used` calls on one code: exactly one returns `True`.
- [ ] `claim_code(code)` uses `OAUTH_CODE_CLAIM_TTL` (default 30); an explicit `ttl` wins.
- [ ] A held claim on a consumed/missing code → 400 `invalid_grant` "Authorization code already used."
- [ ] A held claim on a pending code → 503 `server_error`; the code is neither marked used nor deleted.
- [ ] All validation commands pass; `ruff check` and `black --check` clean on changed files.

---

## Validation Commands

- `pytest tests/test_oauth2_code_redemption.py -q`
- `pytest tests/test_oauth2_unknown_resource_owner.py -q`
- `pytest tests/test_oauth2_p0_correctness.py -q`

---

## Test Specification

```python
# tests/test_oauth2_code_redemption.py
class TestAtomicMarkUsed:
    async def test_only_the_first_caller_wins(self): ...      # fake redis honouring nx=True
    async def test_marker_uses_code_ttl(self): ...
    async def test_missing_code_after_marker_is_false(self): ...

class TestClaimTtl:
    async def test_default_ttl_comes_from_conf(self): ...     # patch code_backend.OAUTH_CODE_CLAIM_TTL
    async def test_explicit_ttl_wins(self): ...
```

---

## Agent Instructions

Work in `.claude/worktrees/feat-FEAT-108-oauth2-3lo-issues`; verify the contract, implement
from the blueprint, run the Validation Commands, commit only the listed files, then
`parrot sdd task close TASK-224 oauth2-3lo-issues verified`.

---

## Completion Note

*(Agent fills this in when done)*
