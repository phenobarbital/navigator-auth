# TASK-225: Bind the token session only after the authorization code is consumed

**Feature**: FEAT-108 — OAuth2 3LO issues
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: low
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-224
**Assigned-to**: unassigned
**Discovered-from**: `issue:42d67472eccd`

---

## Context

`Oauth2Provider._token_session_claims` resolves the owner *and* calls
`_create_user_session` before `_handle_authorization_code` consumes the code with
`mark_used`. A redeemer that then loses `mark_used` has already touched the
session store (ledger `issue:42d67472eccd`).

Verified behaviour of the session store (`navigator_session/storages/redis.py`
`RedisStorage.new_session`): the session is keyed by identity — it reuses the id in
`user:{identity}`. So the losing redeemer does not mint a separate orphan; it
rewrites and extends the *shared* per-user session that the winner (and the user's
browser) use. Deleting that session on the losing path — the fix the issue
suggests — would log the user out. The correct fix is ordering: resolve the
owner before consuming (keeps the FEAT-108 outage guarantee), bind the session
only after `mark_used` succeeds, so a losing redeemer has no session side effect.

---

## Scope

- Give `_token_session_claims` an optional keyword `user` (an already-resolved
  owner); when given it skips `_resolve_resource_owner`.
- In `_handle_authorization_code`, call `_resolve_resource_owner(user_id)` inside the
  existing claim/release `try` (same `UserNotFound`/`FailedAuth`/
  `IdentityStoreUnavailable`/`BaseException` handling), then `mark_used`, then
  `_token_session_claims(request, user_id, conn=conn, user=owner)`.
- Leave the refresh grant unchanged (it re-reads the token under the user lock
  before `_token_session_claims`, so it has no losing path after session creation).
- Update `_grant_provider` in `tests/test_oauth2_unknown_resource_owner.py` so the
  owner lookup is driven through `_resolve_resource_owner`; add ordering tests.

**NOT in scope**: invalidating any session; the refresh/device grants' ordering.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `_token_session_claims(user=...)`; code grant binds after consume |
| `tests/test_oauth2_unknown_resource_owner.py` | MODIFY | Drive owner outcomes via `_resolve_resource_owner` |
| `tests/test_oauth2_code_redemption.py` | MODIFY | Losing redeemer creates no session; bind happens after consume |

---

## Codebase Contract (Anti-Hallucination)

Verified on `feat-FEAT-108-oauth2-3lo-issues` @ `30dee03`.

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
async def _resolve_resource_owner(self, user_id: Any) -> Any: ...      # line 549
async def _create_user_session(self, request, user, response=None, extra=None): ...  # line 705
async def _token_session_claims(self, request: web.Request, user_id: int, *, conn: Any = None) -> dict: ...  # line 844
async def _handle_authorization_code(self, payload, request): ...      # line 2171
#   `session_claims = await self._token_session_claims(request, user_id, conn=conn)` lines 2256 (code) and 2536 (refresh)

# navigator_session/storages/redis.py:284 — new_session reuses get_session_id(conn, identity)
```

### Does NOT Exist
- ~~`Oauth2Provider._bind_token_session`~~ — not a method; extend `_token_session_claims`
- ~~a per-redemption session id~~ — sessions are per identity

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_unknown_resource_owner.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_code_redemption.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._resolve_resource_owner",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_authorization_code"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Add `user: Any = None` to `_token_session_claims` — *why*: the code grant resolves first and binds later.
2. Reorder the code grant: resolve → `mark_used` → bind — *why*: a losing redeemer must not touch the shared session.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY)
```python
async def _token_session_claims(self, request, user_id, *, conn=None, user=None) -> dict:
    if user is None:
        user = await self._resolve_resource_owner(user_id)
    session = await self._create_user_session(request, user)
    # ... unchanged ...

# _handle_authorization_code, inside the claim try:
    owner = await self._resolve_resource_owner(user_id)
# ... existing except branches unchanged ...
if not await self.code_storage.mark_used(code):
    return self._error_response("invalid_grant", "Authorization code already used.")
await self.code_storage.delete_code(code)
session_claims = await self._token_session_claims(request, user_id, conn=conn, user=owner)
```

### FILL IN checklist
- [ ] `_grant_provider` also sets `provider._resolve_resource_owner = AsyncMock(**claims_effect)`.
- [ ] Test: `mark_used` returns False → `_token_session_claims` / `_create_user_session` never awaited.

---

## Acceptance Criteria

- [ ] A redeemer that loses `mark_used` never awaits `_create_user_session`.
- [ ] Owner outcomes on the code grant are unchanged (unknown/disabled → consume + invalid_grant; outage → release + 503).
- [ ] The refresh grant's behaviour is unchanged.
- [ ] All validation commands pass; `ruff check` and `black --check` clean on changed files.

---

## Validation Commands

- `pytest tests/test_oauth2_code_redemption.py -q`
- `pytest tests/test_oauth2_unknown_resource_owner.py -q`
- `pytest tests/test_oauth2_3lo_session_binding.py -q`
- `pytest tests/test_oauth2_refresh.py tests/test_oauth2_pkce.py -q`

---

## Test Specification

```python
# tests/test_oauth2_code_redemption.py
class TestSessionAfterConsume:
    async def test_losing_redeemer_creates_no_session(self, provider): ...
    async def test_session_bound_after_mark_used(self, provider): ...   # call order
```

---

## Agent Instructions

Work in `.claude/worktrees/feat-FEAT-108-oauth2-3lo-issues` after TASK-224; implement from the
blueprint, run the Validation Commands, commit only the listed files, then
`parrot sdd task close TASK-225 oauth2-3lo-issues verified`.

---

## Completion Note

**Completed by**: /sdd-fix session `agent:sdd-fix:d964ca37` (Claude Opus 5.5)
**Date**: 2026-11-12
**Notes**: `_token_session_claims(..., user=None)`; the code grant resolves the owner under the claim,
consumes the code, then binds the session with the already-resolved owner. A redeemer that loses
`mark_used` never awaits `_create_user_session`; nothing is deleted (the session is shared per
identity — `RedisStorage.new_session` reuses `user:{identity}`, so deleting it would log the user
out). Refresh grant unchanged. Commits: `b995fef`, review fix `0cb58e5`.

**Deviations from spec**: Codex review (CONFIRMED, fixed in `0cb58e5`): after the code is consumed, a
session-store exception no longer propagates (it would have cost the client its grant, including
device redemption); the token is issued without session claims, as when no session can be created.
