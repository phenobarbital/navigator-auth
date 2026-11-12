# TASK-204: Token grants refuse unknown or disabled owners; outages keep the code and the refresh chain

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-203
**Assigned-to**: unassigned

---

## Context

Spec §1 S5 / G6, §2 (identity-store paragraph), decisions **D6** (revoke only for a confirmed missing or
disabled owner) and **D7**, §3 Module 6, AC14–AC16a. `_token_session_claims` swallows a failed owner
lookup and returns `{}`, so both grants mint a session-less token ("cannot bind a session to the token
for user_id=35" on every code and refresh grant). After this task:
- a **confirmed** missing/disabled owner → 400 `invalid_grant` "The resource owner of this grant cannot
  be resolved."; the code is consumed; the refresh chain is revoked;
- an **identity-store outage** → generic 503; the code stays redeemable; the refresh chain is kept;
- a session that cannot be *created* (storage down) still yields `{}` — unchanged.

The device-code grant delegates to `_handle_authorization_code` (`backend.py:2104+`), so it inherits this.

---

## Scope

- `_token_session_claims`: resolve the owner through `_resolve_resource_owner` (TASK-203) and let
  `UserNotFound` / `FailedAuth` / `IdentityStoreUnavailable` propagate; delete the swallowing `try/except`.
- `AuthorizationCodeStorage`: add `claim_code(code, ttl=30) -> bool` (Redis `SET NX EX`) and `release_claim(code)`.
- `_handle_authorization_code`: after code, client and PKCE validation and **before** consuming the code —
  claim it (when the storage offers `claim_code`), compute the session claims; map outcomes as above;
  then consume and build `token_data` from the precomputed claims.
- `_handle_refresh_token`: compute the session claims right after the scope-narrowing check (before
  rotation); missing/disabled → `revoke_chain(refresh_token)` once + `invalid_grant`; outage → 503, no revocation.
- Tests: append grant tests to `tests/test_oauth2_unknown_resource_owner.py`; replace
  `test_unknown_user_degrades_without_raising` with `test_unknown_user_raises`; stub the owner in the
  device-polling and device-integration fixtures that now reach it.

**NOT in scope**: authorize/consent (TASK-203, done); device verification and login resume (TASK-205);
`tests/test_oauth2_mcp_conformance.py` (it stubs `_token_session_claims` at `:295`, so it is unaffected).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `_token_session_claims`; both grants |
| `navigator_auth/backends/oauth2/code_backend.py` | MODIFY | `claim_code` / `release_claim` |
| `tests/test_oauth2_unknown_resource_owner.py` | MODIFY | Grant + outage + concurrency tests |
| `tests/test_oauth2_3lo_session_binding.py` | MODIFY | `test_unknown_user_raises`, `test_session_storage_unavailable_still_returns_empty` |
| `tests/test_device_token_polling.py` | MODIFY | Stub `user_from_id` in `_make_provider` |
| `tests/test_oauth2_introspection_device_integration.py` | MODIFY | Stub `user_from_id` in `_make_provider` |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11).
> **FEAT-106 overlap**: its review-fix tasks TASK-185 (credential generation enforced at code exchange and
> refresh, under the user lock) and TASK-186 (`_token_session_claims(..., extra=)`, `amr` in `token_data`)
> rewrite this region before FEAT-108 starts. Keep their additions: pass `extra` through, keep their
> generation checks, and place the FEAT-108 owner check inside the same flow. Re-run every `grep -c`.

### Verified Imports
```python
# backend.py, after TASK-203: from typing import Any, NoReturn, Optional; IdentityStoreUnavailable imported
from navigator_auth.exceptions import FailedAuth, IdentityStoreUnavailable, UserNotFound
import asyncio                                          # stdlib (concurrency test)
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
async def _resolve_resource_owner(self, user_id: Any) -> Any:        # TASK-203
def _owner_store_unavailable(self) -> web.StreamResponse:             # TASK-203 (generic 503 server_error)
async def _create_user_session(self, request, user, response=None):   # :632 (returns None when no storage / no identity)
async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:   # :688 (FEAT-106 adds extra=)
    #   :697-701  try: user = await self._idp.user_from_id(user_id)
    #             except Exception as exc:
    #                 self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")   # :700
    #                 return {}
async def _handle_authorization_code(self, payload, request):         # :1743
    #   :1760  auth_code = await self.code_storage.get_code(code)
    #   :1765  if auth_code.used: delete; invalid_grant "Authorization code already used."
    #   :1797-1809 PKCE checks
    #   :1811  # B5: mark code as used + delete from storage.
    #   :1812  await self.code_storage.mark_used(code)
    #   :1813  await self.code_storage.delete_code(code)
    #   :1816  user_id = auth_code.user_id
    #   :1829  **await self._token_session_claims(request, user_id),   (1st of 2 occurrences — after `"jti": jti,` + "Bind the token to a session…" comment)
async def _handle_refresh_token(self, payload, request):              # :1973
    #   :2005, :2015  await self.refresh_token_storage.revoke_chain(refresh_token)   (reuse / gate)
    #   :2032  # TASK-024: user_id always from the refresh token.
    #   :2033  user_id = rt.user_id
    #   :2036-2037 scope narrowing → invalid_scope
    #   :2046  **await self._token_session_claims(request, user_id),   (2nd occurrence — after "Same session binding as the authorization_code grant.")
    #   :2080-2094 rotation (save_token new_rt, revoke_token(refresh_token, "rotated"))

# navigator_auth/backends/oauth2/code_backend.py
class AuthorizationCodeStorage:                    # :45 — self.redis (redis.asyncio, decode_responses=True), self.prefix = "oauth2:code:"
    async def get_code(self, code: str):           # :73
    async def mark_used(self, code: str) -> bool:  # :88 (get + set, NOT atomic)
    async def delete_code(self, code: str):        # :104
class RefreshTokenStorage:                         # :114
    async def revoke_chain(self, refresh_token: str) -> None:   # :194

# tests
tests/test_device_token_polling.py:168                    provider._idp = MagicMock()   (inside _make_provider :144)
tests/test_oauth2_introspection_device_integration.py:204 provider._idp = MagicMock()   (inside _make_provider :170)
tests/test_oauth2_3lo_session_binding.py:81-100           provider fixture + make_request(storage)
tests/test_oauth2_3lo_session_binding.py:128              async def test_unknown_user_degrades_without_raising(self, provider):
tests/test_oauth2_access_gate.py:683-737                  refresh_provider / _refresh helpers (reusable pattern)
```

### Measured at task time (fail-closed `_token_session_claims` simulated on dev)
New failures: `test_device_token_polling.py::test_device_poll_success_single_use`,
`::test_device_no_offline_access_no_refresh`, `test_oauth2_introspection_device_integration.py::test_full_device_flow`,
and the replaced `test_unknown_user_degrades_without_raising`. Pre-existing local failures unrelated to this
task (6-byte `AUTH_SECRET_KEY` in `env/.env` + `filterwarnings=error`): the three
`TestDecodeTokenAudience` tests in `test_oauth2_3lo_session_binding.py` and three in `test_oauth2_mcp_conformance.py`.

### Does NOT Exist
- ~~`AuthorizationCodeStorage.claim_code`~~, ~~`release_claim`~~, ~~`consume_code`~~, ~~`getdel`~~ usage — new here.
- The in-memory fakes (`tests/conftest.py::MemoryAuthCodeStorage` :126, `_MemCodeStorage` in device tests) have no claim API — hence the capability check below.
- No refresh-chain revocation exists for an unknown owner today.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/oauth2/code_backend.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_unknown_resource_owner.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_3lo_session_binding.py", "action": "MODIFY"},
    {"path": "tests/test_device_token_polling.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_introspection_device_integration.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_authorization_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_refresh_token",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._create_user_session",
    "sym:navigator_auth/backends/oauth2/code_backend.py#AuthorizationCodeStorage",
    "sym:navigator_auth/backends/oauth2/code_backend.py#RefreshTokenStorage.revoke_chain"
  ]
}
```

---

## Implementation Notes

### Decisions fixed for this task
- **One owner check per grant, inside `_token_session_claims`.** The grants compute the claims early
  (before consumption / rotation) and reuse them in `token_data` — no second IdP lookup.
- **Atomic claim, storage capability.** `claim_code` uses Redis `SET <prefix>claim:<code> 1 NX EX 30`;
  the provider calls it only when the storage defines it (`getattr`). The production storage
  (`AuthorizationCodeStorage`, `backend.py:416`) always does, so concurrent redemption is single-use in
  production; test fakes without it keep today's semantics. A losing concurrent redeemer gets
  `invalid_grant` "Authorization code already used.". `release_claim` runs only on an outage, so the
  client can retry; the confirmed-missing path consumes the code instead.
- Error texts (D7): `invalid_grant` / "The resource owner of this grant cannot be resolved.".

---

## Implementation Blueprint

### Steps (in order)
1. `_token_session_claims` stops swallowing — *why*: AC16.
2. Add `claim_code` / `release_claim` — *why*: AC16a single-use with a pre-consumption lookup.
3. Code grant: claim → claims → consume — *why*: AC14, AC16a.
4. Refresh grant: claims before rotation; revoke only when confirmed — *why*: AC15, D6.
5. Tests + fixture stubs; run the Validation Commands.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — `_token_session_claims`
```python
# occurrences: 1 (verified: grep -c 'self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")' navigator_auth/backends/oauth2/backend.py)
# REPLACE the try/except around `user = await self._idp.user_from_id(user_id)` (verified: :697-701) WITH:
        # FEAT-108: an unresolvable or disabled owner must not get a token. Raises
        # UserNotFound / FailedAuth / IdentityStoreUnavailable (callers map them).
        user = await self._resolve_resource_owner(user_id)
# Update the docstring: it now raises instead of returning {} for an unresolvable owner; it still returns
# {} when the session cannot be created. Keep FEAT-106's `extra` parameter and its pass-through.
```

### `navigator_auth/backends/oauth2/code_backend.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^class RefreshTokenStorage:' navigator_auth/backends/oauth2/code_backend.py)
# Insert as the last methods of AuthorizationCodeStorage, i.e. directly after `delete_code` (verified: :104-107)
    async def claim_code(self, code: str, ttl: int = 30) -> bool:
        """Atomically claim the right to redeem ``code`` (FEAT-108).

        ``SET NX EX``: exactly one concurrent redeemer gets True. The claim outlives the
        code's deletion for ``ttl`` seconds, so a late concurrent redeemer also loses.
        """
        return bool(await self.redis.set(f"{self.prefix}claim:{code}", "1", nx=True, ex=ttl))

    async def release_claim(self, code: str) -> None:
        """Drop the claim so the client can retry after a transient outage (FEAT-108)."""
        await self.redis.delete(f"{self.prefix}claim:{code}")
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — code grant
```python
# occurrences: 1 (verified: grep -c '# B5: mark code as used + delete from storage.' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `# B5: mark code as used + delete from storage.` (verified: :1811)
        # FEAT-108: claim the code atomically, then resolve the owner BEFORE consuming it,
        # so an identity-store outage leaves the code redeemable.
        claim = getattr(self.code_storage, "claim_code", None)
        if claim is not None and not await claim(code):
            return self._error_response("invalid_grant", "Authorization code already used.")
        try:
            session_claims = await self._token_session_claims(request, auth_code.user_id)
        except (UserNotFound, FailedAuth):
            await self.code_storage.mark_used(code)
            await self.code_storage.delete_code(code)
            return self._error_response(
                "invalid_grant", "The resource owner of this grant cannot be resolved."
            )
        except IdentityStoreUnavailable:
            release = getattr(self.code_storage, "release_claim", None)
            if release is not None:
                await release(code)
            return self._owner_store_unavailable()

# occurrences: 2 (verified: grep -c '\*\*await self._token_session_claims(request, user_id),' navigator_auth/backends/oauth2/backend.py)
# FILL IN: disambiguate — in the FIRST occurrence (inside `_handle_authorization_code`, after `"jti": jti,` and
# the comment "Bind the token to a session…", verified :1826-1829) replace the line WITH:
            **session_claims,
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — refresh grant
```python
# occurrences: 1 (verified: grep -c '# TASK-024: user_id always from the refresh token.' navigator_auth/backends/oauth2/backend.py)
# AFTER the scope-narrowing `return self._error_response("invalid_scope", "Cannot widen scope during refresh.")`
# that follows that comment (verified: :2032-2037), insert:
        # FEAT-108 (D6): owner check before rotation. Revoke only for a confirmed
        # missing/disabled owner; an outage keeps the chain for a retry.
        try:
            session_claims = await self._token_session_claims(request, user_id)
        except (UserNotFound, FailedAuth):
            await self.refresh_token_storage.revoke_chain(refresh_token)
            return self._error_response(
                "invalid_grant", "The resource owner of this grant cannot be resolved."
            )
        except IdentityStoreUnavailable:
            return self._owner_store_unavailable()

# FILL IN: disambiguate — in the SECOND occurrence of `**await self._token_session_claims(request, user_id),`
# (inside `_handle_refresh_token`, after "Same session binding as the authorization_code grant.", verified :2045-2046)
# replace the line WITH `**session_claims,`.
```

### `tests/test_oauth2_unknown_resource_owner.py` (MODIFY) — append
```python
# --- TASK-204: token grants ------------------------------------------------------------------
class TestCodeGrantOwner:
    # FILL IN: unknown owner ⇒ 400 invalid_grant (D7 text), no access_token, code consumed (AC14);
    #          outage ⇒ 503 server_error, code NOT consumed and claim released; a retry after recovery
    #          succeeds (AC16a); a fake storage implementing claim_code + get/mark/delete with an
    #          `await asyncio.sleep(0)` inside get_code, two redemptions via asyncio.gather ⇒ exactly one
    #          access_token (AC16a single-use).
    pass


class TestRefreshGrantOwner:
    # FILL IN: unknown/disabled owner ⇒ invalid_grant and revoke_chain(<presented token>) awaited once (AC15);
    #          outage ⇒ 503, revoke_chain NOT awaited, no new refresh token saved (AC16a).
    #          Pattern: tests/test_oauth2_access_gate.py:683-737 (refresh_provider, _refresh).
    pass


class TestCodeStorageClaim:
    # FILL IN: AuthorizationCodeStorage.claim_code calls redis.set(f"{prefix}claim:{code}", "1", nx=True, ex=30)
    #          and returns its truthiness; release_claim deletes that key (AsyncMock redis).
    pass
```

### `tests/test_oauth2_3lo_session_binding.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'async def test_unknown_user_degrades_without_raising(self, provider):' tests/test_oauth2_3lo_session_binding.py)
# REPLACE the whole test (verified: :127-131) WITH:
    @pytest.mark.asyncio
    async def test_unknown_user_raises(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=UserNotFound("no such user"))
        request = make_request(MagicMock())
        with pytest.raises(UserNotFound):
            await provider._token_session_claims(request, 404)

    @pytest.mark.asyncio
    async def test_session_storage_unavailable_still_returns_empty(self, provider):
        provider._idp.user_from_id = AsyncMock(return_value=DummyUser(user_id=11, username="demo"))
        # FILL IN: a request whose _session_storage(...) resolves to None ⇒ `== {}` — AC16 (second clause).
# Add `from navigator_auth.exceptions import UserNotFound` to the imports (:18-25).
```

### `tests/test_device_token_polling.py` and `tests/test_oauth2_introspection_device_integration.py` (MODIFY)
```python
# occurrences: 1 each (verified: grep -c 'provider._idp = MagicMock()' <file>; :168 and :204)
# AFTER — insert below `provider._idp = MagicMock()`:
    # FEAT-108: the grants now resolve the resource owner; a bare MagicMock is not awaitable.
    provider._idp.user_from_id = AsyncMock(return_value=_owner(<the user id the file uses>))
# FILL IN: add a tiny `_owner(user_id)` helper returning an object with user_id, username and is_active=True
#          (the username feeds _create_user_session); import AsyncMock if missing. Change nothing else.
```

### FILL IN checklist
- [ ] Both `**session_claims,` replacements at the disambiguated anchors (+ FEAT-106 `extra=` kept).
- [ ] `TestCodeGrantOwner`, `TestRefreshGrantOwner`, `TestCodeStorageClaim`; AC14–AC16a.
- [ ] `test_session_storage_unavailable_still_returns_empty`; AC16.
- [ ] Fixture stubs in the two device test files; their suites pass.

---

## Acceptance Criteria

- [ ] AC14: the code grant answers 400 `invalid_grant` "The resource owner of this grant cannot be resolved." for an unresolvable owner; no access token; the code stays consumed.
- [ ] AC15: the refresh grant answers the same and awaits `refresh_token_storage.revoke_chain(<presented token>)` once.
- [ ] AC16: `_token_session_claims` raises `UserNotFound` / `FailedAuth` for an unresolvable owner and still returns `{}` when the session cannot be created; `test_unknown_user_degrades_without_raising` is replaced by `test_unknown_user_raises`.
- [ ] AC16a (grants): an outage gives a generic 503 with no issuance and no revocation; a validated code stays redeemable after recovery; a confirmed missing/disabled owner consumes it; concurrent redemption is single-use.
- [ ] `tests/test_oauth2_refresh.py`, `tests/test_oauth2_pkce.py`, `tests/test_device_token_polling.py`, `tests/test_oauth2_introspection_device_integration.py` pass.
- [ ] `ruff check` clean on the six files.

---

## Validation Commands

- `pytest tests/test_oauth2_unknown_resource_owner.py -q`
- `pytest tests/test_oauth2_3lo_session_binding.py -q`
- `pytest tests/test_oauth2_refresh.py tests/test_oauth2_pkce.py -q`
- `pytest tests/test_device_token_polling.py tests/test_oauth2_introspection_device_integration.py -q`

---

## Test Specification

Spec §4, M6: `test_code_grant_unknown_owner_invalid_grant`, `test_refresh_grant_unknown_owner_revokes_chain`,
`test_owner_store_outage` (grant half), `test_code_owner_lookup_outage_retry`, `test_unknown_user_raises`,
`test_session_storage_unavailable_still_returns_empty`.

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` in the blueprint before editing; a changed
   count means the anchor moved (re-locate it), a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-204 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none

## Completion Note

Delivered by gpt-5.6-terra (1 attempt), engine task-tier validation passed, merged. 1 residual lint style item left to /sdd-done.
