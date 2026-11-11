# TASK-226: Re-check the resource owner on userinfo and introspection

**Feature**: FEAT-108 — OAuth2 3LO issues
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-225
**Assigned-to**: unassigned
**Discovered-from**: `issue:3ae0de8a2704`

---

## Context

FEAT-108 refuses unknown or disabled owners at authorize, consent and every token
grant, but a bearer minted *before* the owner was disabled or deleted keeps working
on `/oauth2/userinfo` and `/oauth2/introspect` (ledger `issue:3ae0de8a2704`): userinfo
swallows a failed owner lookup and still answers, and introspection reports the token
`active: true`. Only `@is_authenticated` blocks it, once the session is gone.

---

## Scope

- `userinfo`: for an OAuth user token (`is_oauth_user_token(payload)`), resolve the
  owner with `_resolve_resource_owner`. `UserNotFound`/`FailedAuth` → 401
  `invalid_token` "Token is no longer valid."; `IdentityStoreUnavailable` → 503
  `temporarily_unavailable` "Userinfo temporarily unavailable." (the existing outage
  answer). Reuse the resolved owner for the profile claims. Tokens that are not OAuth
  user tokens keep today's tolerant lookup.
- `introspect`: after the same-client check, for an active token that carries a user
  (an OAuth user access token, or a refresh token record with `user_id`), resolve the
  owner; any of the three exceptions → `{"active": false}` (fail closed, as the
  generation check already does). Reuse the resolved owner for the `username` claim.
- Tests: new `tests/test_oauth2_owner_recheck.py`; make the introspection harness's
  default owner an active user so existing active-token tests keep meaning "owner ok".

**NOT in scope**: `@is_authenticated` / middleware bearer handling; the revocation endpoint.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Owner re-check in `userinfo` and `introspect` |
| `tests/test_oauth2_owner_recheck.py` | CREATE | Owner gone/disabled/outage on both endpoints |
| `tests/test_oauth2_introspection.py` | MODIFY | `_make_provider` default owner is an active user |

---

## Codebase Contract (Anti-Hallucination)

Verified on `feat-FEAT-108-oauth2-3lo-issues` @ `30dee03`.

### Verified Imports
```python
from navigator_auth.backends.oauth2.models import is_oauth_user_token  # models.py:287 (already imported in backend.py)
from navigator_auth.exceptions import UserNotFound, FailedAuth, IdentityStoreUnavailable  # backend.py:106-111
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
async def _resolve_resource_owner(self, user_id: Any) -> Any: ...   # line 549
async def userinfo(self, request): ...                              # line 2718
#   generation check + 503 "Userinfo temporarily unavailable." lines 2743-2748
#   tolerant lookup `user = await self._idp.user_from_id(user_id)` line 2761
async def introspect(self, request: web.Request): ...               # line 2899
#   same-client check `if not hmac.compare_digest(str(caller.client_id), str(token_client_id)):` line 2998
#   username lookup `user = await self._idp.user_from_id(user_id)` line 3036

# tests/test_oauth2_introspection.py:56
def _make_provider(caller_client, access_token_storage=None, refresh_token_storage=None, user=None): ...
```

### Does NOT Exist
- ~~`Oauth2Provider._owner_ok`~~ — no helper; call `_resolve_resource_owner` directly
- ~~an introspection error response for outages~~ — RFC 7662 has none; answer inactive

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_owner_recheck.py", "action": "CREATE"},
    {"path": "tests/test_oauth2_introspection.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._resolve_resource_owner",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.userinfo",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.introspect"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. userinfo: resolve the owner for OAuth user tokens — *why*: a disabled/deleted owner's bearer must stop working.
2. introspect: resolve the owner after the same-client check — *why*: report such tokens inactive without leaking to foreign clients.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY)
```python
# userinfo, after the generation check:
user = None
if is_oauth_user_token(payload):
    try:
        user = await self._resolve_resource_owner(payload["user_id"])
    except (UserNotFound, FailedAuth):
        return self._error_response("invalid_token", "Token is no longer valid.", status=401)
    except IdentityStoreUnavailable:
        return self._error_response("temporarily_unavailable", "Userinfo temporarily unavailable.", status=503)
elif user_id and ("profile" in scopes or "email" in scopes):
    # FILL IN: today's tolerant lookup, unchanged

# introspect, after the same-client check:
owner = None
owner_id = token_payload.get("user_id") if ... else (rt.user_id if rt else None)
if owner_id is not None (user token / refresh record):
    try:
        owner = await self._resolve_resource_owner(owner_id)
    except (UserNotFound, FailedAuth, IdentityStoreUnavailable):
        return JSONResponse({"active": False}, status=200)
# FILL IN: username claim from `owner`
```

### FILL IN checklist
- [ ] Which introspected tokens carry an owner: `is_oauth_user_token(token_payload)` for access; `rt.user_id` for refresh.
- [ ] `_make_provider(user=None)` → default active owner `SimpleNamespace(user_id=42, username="owner", is_active=True)`.

---

## Acceptance Criteria

- [ ] userinfo: owner unknown → 401; disabled → 401; outage → 503; active → 200 with claims.
- [ ] introspect: owner unknown/disabled/outage → `{"active": false}`; active → `active: true` + `username`.
- [ ] A foreign client's introspection never triggers an owner lookup.
- [ ] Non-OAuth tokens on userinfo keep today's behaviour (`tests/test_oauth2_userinfo_claims.py` unchanged and green).
- [ ] All validation commands pass; `ruff check` and `black --check` clean on changed files.

---

## Validation Commands

- `pytest tests/test_oauth2_owner_recheck.py -q`
- `pytest tests/test_oauth2_introspection.py -q`
- `pytest tests/test_oauth2_userinfo_claims.py -q`
- `pytest tests/test_oauth2_introspection_device_integration.py tests/test_device_token_polling.py -q`

---

## Test Specification

```python
# tests/test_oauth2_owner_recheck.py
class TestUserinfoOwner:
    async def test_unknown_owner_is_401(self): ...
    async def test_disabled_owner_is_401(self): ...
    async def test_outage_is_503(self): ...

class TestIntrospectOwner:
    async def test_unknown_or_disabled_owner_is_inactive(self): ...
    async def test_outage_is_inactive(self): ...
    async def test_foreign_client_skips_owner_lookup(self): ...
```

---

## Agent Instructions

Work in `.claude/worktrees/feat-FEAT-108-oauth2-3lo-issues` after TASK-225; implement from the
blueprint, run the Validation Commands, commit only the listed files, then
`parrot sdd task close TASK-226 oauth2-3lo-issues verified`.

---

## Completion Note

*(Agent fills this in when done)*
