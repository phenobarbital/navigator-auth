# TASK-203: Resource-owner resolver; `/oauth2/authorize` and consent fail closed on unknown owners

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-200, TASK-201
**Assigned-to**: unassigned

---

## Context

Spec §1 S5 / G6, §2 OAuth2 provider paragraph, decisions **D3** (redirect to login, session kept),
**D4** (`is_active` enforced with existence), **D7** (error texts), §3 Module 6, AC11–AC12, AC16a.
`/oauth2/authorize` took the resource owner from an existing browser session (user 35, created by
another Navigator app on the same host + Redis) that the IdP cannot resolve, and issued codes for it.
This task adds the shared resolver and login-redirect helper, and wires the first two call paths.
TASK-204 wires the token grants, TASK-205 device verification + login resume.

---

## Scope

- Add `Oauth2Provider._resolve_resource_owner(user_id)`: return the IdP user; raise `UserNotFound` for
  `UserNotFound`/`ValidationError`; `FailedAuth` when `user_is_active(user)` is False; re-raise
  `IdentityStoreUnavailable`; turn **any other** exception into `IdentityStoreUnavailable` (logged).
- Add `Oauth2Provider._redirect_to_login(request, data) -> NoReturn`, extracted from `authorize`'s
  no-session block (`backend.py:1425-1428`), and use it there.
- Add `Oauth2Provider._owner_store_unavailable()` → generic 503 `server_error` response.
- **authorize**: after the session check, decode the owner; `None` / `UserNotFound` / `FailedAuth` →
  `_redirect_to_login(request, data)` (no session invalidation, D3); `IdentityStoreUnavailable` → 503.
- **consent POST**: after the `user_obj` checks → `UserNotFound`/`FailedAuth` → 401 `access_denied`
  "Unknown or disabled resource owner."; `IdentityStoreUnavailable` → 503; no code stored either way.
- Append provider tests to `tests/test_oauth2_unknown_resource_owner.py`; stub the owner in the
  consent fixtures of `tests/test_oauth2_access_gate.py` that now reach the resolver.

**NOT in scope**: `_token_session_claims` and the grants (TASK-204); `device_verification`, `auth_login`
and `templates/oauth/login.html` (TASK-205); `userinfo` (TASK-201, done).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Resolver, redirect + 503 helpers, authorize + consent call sites |
| `tests/test_oauth2_unknown_resource_owner.py` | MODIFY | Resolver / authorize / consent tests |
| `tests/test_oauth2_access_gate.py` | MODIFY | Stub `user_from_id` where consent/authorize now resolve the owner |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11):
> identical in this file today. FEAT-106's pending review-fix tasks TASK-184/185 change `auth_login`,
> `_create_user_session` and the code exchange, not the lines below — still re-run every `grep -c`.

### Verified Imports
```python
from typing import Optional, Any                       # backend.py:29 — add NoReturn here
from datamodel.exceptions import ValidationError        # backend.py:41
from ...exceptions import (FailedAuth, UserNotFound, InvalidAuth,)   # backend.py:102-106 — add IdentityStoreUnavailable (TASK-200)
from ..abstract import BaseAuthBackend, user_is_active  # backend.py:108; user_is_active at abstract.py:43
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
class Oauth2Provider(BaseAuthBackend):                                   # :258
    self._idp                                                            # IdentityProvider (abstract.py:134)
    def redirect(self, uri: str, location: bool = False):                # :489 — always raises HTTPFound
    def _error_response(self, error: str, description: str, status: int = 400):  # :495
    async def check_session(self, request):                              # :523 → encoded user blob or None
    def _decode_session_user(self, encoded_user) -> Optional[OauthUser]: # :538 → .user_id
    async def authorize(self, request: web.Request):                     # :1343
        #   :1422  # Check user session.
        #   :1423  session = await self.check_session(request)
        #   :1424  if not session:
        #   :1425      location = request.app.router["nav_oauth2_login"].url_for()   (also at :2688, device)
        #   :1426      payload = {"action_url": str(location), **data}
        #   :1427      url = location.with_query(**payload)
        #   :1428      self.redirect(url, location=True)
        #   :1433  gate_user = self._decode_session_user(session)
        #   :1434  if gate_user is not None: denied = await self._enforce_access_gate(request, client, gate_user.user_id, redirect_uri, data.get("state", ""))
    async def consent(self, request: web.Request):                       # :1516
        #   :1541  session_user = await self.check_session(request)
        #   :1543  user_obj = self._decode_session_user(session_user)
        #   :1545  return self._error_response("access_denied", "Cannot resolve user from session.", status=401)
        #   :1547  client = await self.client_storage.get_client(client_id, request=request)

# navigator_auth/exceptions.py — from TASK-200
class IdentityStoreUnavailable(AuthException):   # status 503, generic message

# tests/test_oauth2_access_gate.py
def provider(storage):                            # :45-51 — Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
def _consent_provider(provider, gated=True):      # :316 — mocks check_session/_decode_session_user(user.user_id = USER_ID)
```

### Test fixtures affected (measured at task time by simulating the owner check)
- `tests/test_oauth2_access_gate.py::TestConsentEndpointIsGated` (4 tests, through `_consent_provider`) and
  `::TestGateLifecycle::test_gate_lifecycle`: `identity=MagicMock()` makes `await user_from_id(...)` a
  `TypeError` → 503 after this change. Fix the fixture: `provider._idp.user_from_id = AsyncMock(return_value=user)`.
- `TestGateEnforcement` calls `_enforce_access_gate` directly — **not** affected; do not touch it.
- `TestDeviceFlowGate::test_device_denial_renders_not_redirects` belongs to TASK-205.

### Does NOT Exist
- ~~`Oauth2Provider._resolve_resource_owner`~~, ~~`_validate_session_user`~~, ~~`_session_owner`~~, ~~`_redirect_to_login`~~, ~~`_owner_store_unavailable`~~ — new here.
- ~~`forget_session`~~, ~~`invalidate_session`~~, ~~`_drop_session`~~ — and D3 needs none: never invalidate the session.
- ~~`OAUTH_REQUIRE_KNOWN_OWNER`~~ or any config flag; ~~`UnknownResourceOwner`~~ exception.
- `is_active` is checked today only in `auth_login` (`:1644`).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_unknown_resource_owner.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_access_gate.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.authorize",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.consent",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.redirect",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._error_response",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.check_session",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._decode_session_user",
    "sym:navigator_auth/backends/abstract.py#user_is_active",
    "sym:navigator_auth/exceptions.py#IdentityStoreUnavailable"
  ]
}
```

---

## Implementation Notes

### Decisions fixed for this task
- **Unknown exceptions are outages, not missing users.** Only `UserNotFound`/`ValidationError` mean
  "confirmed missing" (spec §2 custom-IdP contract). Anything else becomes `IdentityStoreUnavailable`
  → 503 with no issuance — the fail-closed side that never revokes (D6) and never sends a user to login.
- **503 body**: `_error_response("server_error", "The identity service is temporarily unavailable.", status=503)` —
  generic, no DB text.
- **D3**: the unknown-owner redirect is the same `nav_oauth2_login` redirect with the full authorization
  request; never call any session `invalidate`.

### Key Constraints
- `self.logger` only; never log a token, code or `Authorization` header.
- Keep `gate_user` as the variable name after the owner check so the access-gate block below it is untouched.

---

## Implementation Blueprint

### Steps (in order)
1. Imports: `NoReturn`, `IdentityStoreUnavailable` — *why*: helper signature, outage mapping.
2. Add the three helpers after `_error_response` (`:495-500`) — *why*: one resolver, one redirect, one 503.
3. authorize: use `_redirect_to_login` in the no-session branch; add the owner check — *why*: AC11, D3.
4. consent POST: add the owner check — *why*: AC12.
5. Tests; stub the affected access-gate fixtures; run the Validation Commands.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — imports
```python
# occurrences: 1 (verified: grep -c '^from typing import Optional, Any' navigator_auth/backends/oauth2/backend.py)
# REPLACE `from typing import Optional, Any` (verified: :29) WITH:
from typing import Any, NoReturn, Optional

# occurrences: 1 (verified: grep -c '^    InvalidAuth,$' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `    InvalidAuth,` inside `from ...exceptions import (` (verified: :105)
    IdentityStoreUnavailable,
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — helpers
```python
# occurrences: 1 (verified: grep -c 'def _error_response(self, error: str, description: str, status: int = 400):' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below the whole `_error_response` method (verified: :495-500)
    def _owner_store_unavailable(self) -> web.StreamResponse:
        """Generic 503 for an identity-store outage (FEAT-108 D6) — no database detail."""
        return self._error_response(
            "server_error", "The identity service is temporarily unavailable.", status=503
        )

    def _redirect_to_login(self, request: web.Request, data: dict) -> NoReturn:
        """Raise HTTPFound to nav_oauth2_login carrying the authorization request (FEAT-108).

        Extracted from ``authorize``'s no-session branch so the no-session and the
        unknown-owner paths share it. The session is never invalidated here (D3).
        """
        location = request.app.router["nav_oauth2_login"].url_for()
        payload = {"action_url": str(location), **data}
        url = location.with_query(**payload)
        self.redirect(url, location=True)

    async def _resolve_resource_owner(self, user_id: Any) -> Any:
        """Return the IdP user for ``user_id`` (FEAT-108).

        Raises:
            UserNotFound: the IdP raised UserNotFound or a datamodel ValidationError.
            FailedAuth: ``user_is_active(user)`` is False (D4).
            IdentityStoreUnavailable: the store failed, or the IdP raised anything else.
        """
        try:
            user = await self._idp.user_from_id(user_id)
        except (UserNotFound, ValidationError) as exc:
            raise UserNotFound("Unknown resource owner.") from exc
        except IdentityStoreUnavailable:
            raise
        except Exception as exc:  # pylint: disable=W0703
            self.logger.error(f"Oauth2: resource-owner lookup failed for user_id={user_id}: {exc!s}")
            raise IdentityStoreUnavailable() from exc
        if not user_is_active(user):
            raise FailedAuth("Disabled resource owner.")
        return user
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — authorize
```python
# occurrences: 1 (verified: grep -c 'payload = {"action_url": str(location), \*\*data}' navigator_auth/backends/oauth2/backend.py)
# REPLACE the 4-line body of `if not session:` (verified: :1425-1428) WITH:
            self._redirect_to_login(request, data)

# occurrences: 1 (verified: grep -c 'gate_user = self._decode_session_user(session)' navigator_auth/backends/oauth2/backend.py)
# REPLACE `gate_user = self._decode_session_user(session)` (verified: :1433) WITH:
        gate_user = self._decode_session_user(session)
        if gate_user is None:
            self._redirect_to_login(request, data)
        try:
            await self._resolve_resource_owner(gate_user.user_id)
        except (UserNotFound, FailedAuth):
            # FEAT-108 D3: re-authenticate THIS authorization; the shared session is kept.
            self._redirect_to_login(request, data)
        except IdentityStoreUnavailable:
            return self._owner_store_unavailable()
# The following `if gate_user is not None:` access-gate block stays as is (now always true).
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — consent POST
```python
# occurrences: 1 (verified: grep -c 'return self._error_response("access_denied", "Cannot resolve user from session.", status=401)' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: :1545), same indentation as the `if not user_obj:` above it
                try:
                    await self._resolve_resource_owner(user_obj.user_id)
                except (UserNotFound, FailedAuth):
                    return self._error_response(
                        "access_denied", "Unknown or disabled resource owner.", status=401
                    )
                except IdentityStoreUnavailable:
                    return self._owner_store_unavailable()
```

### `tests/test_oauth2_unknown_resource_owner.py` (MODIFY) — append
```python
# --- TASK-203: resolver, authorize, consent ---------------------------------------------------
from aiohttp import web  # noqa: E402  (keep imports at the top when you merge — shown here for clarity)
from navigator_auth.backends.oauth2.backend import Oauth2Provider  # noqa: E402
from navigator_auth.exceptions import FailedAuth  # noqa: E402


@pytest.fixture
def provider():
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.logger = MagicMock()
    return prov


class TestResolveResourceOwner:
    # FILL IN: found & active ⇒ user; UserNotFound / ValidationError ⇒ UserNotFound; is_active=False ⇒ FailedAuth;
    #          IdentityStoreUnavailable passes through; RuntimeError ⇒ IdentityStoreUnavailable — spec §4 test_resolve_resource_owner_*.
    pass


class TestAuthorizeUnknownOwner:
    # FILL IN: drive provider.authorize with a valid public client + PKCE request (reuse the client/request
    #          builders of tests/test_oauth2_access_gate.py or tests/test_oauth2_3lo_session_binding.py),
    #          check_session → blob, _decode_session_user → user(user_id=35), user_from_id raising UserNotFound:
    #          expect web.HTTPFound whose Location targets nav_oauth2_login and keeps client_id, redirect_uri,
    #          state, scope, code_challenge, code_challenge_method; no code saved; no storage invalidate
    #          awaited — AC11. Same for is_active=False (AC11) and for an outage ⇒ 503 server_error (AC16a).
    pass


class TestConsentUnknownOwner:
    # FILL IN: consent POST action=approve with an unknown owner ⇒ 401 access_denied
    #          "Unknown or disabled resource owner.", code storage empty — AC12; outage ⇒ 503, no code — AC16a.
    pass
```

### `tests/test_oauth2_access_gate.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'def _consent_provider(provider, gated=True):' tests/test_oauth2_access_gate.py)
# FILL IN: inside `_consent_provider` (verified: :316), after `user.user_id = USER_ID`, add
#          `provider._idp.user_from_id = AsyncMock(return_value=user)`; do the same in
#          TestGateLifecycle::test_gate_lifecycle where it drives authorize/consent. Change nothing else —
#          bounded by "existing assertions unchanged".
```

### FILL IN checklist
- [ ] Three test classes; AC11, AC12, AC16a.
- [ ] Access-gate fixture stubs; all 45 tests in that file pass.

---

## Acceptance Criteria

- [ ] AC11: authorize with an unknown (`UserNotFound`/`ValidationError`) or disabled session owner → 302 to `nav_oauth2_login` carrying `client_id`, `redirect_uri`, `state`, `scope`, `code_challenge`, `code_challenge_method`; no code issued; session not invalidated.
- [ ] AC12: consent POST (`action=approve`) for such a session → 401 `access_denied` "Unknown or disabled resource owner.", no code stored.
- [ ] AC16a (this task's call sites): an identity-store outage at authorize or consent → generic 503 `server_error`, no redirect, no code.
- [ ] `tests/test_oauth2_access_gate.py` passes (45 tests at task time).
- [ ] `ruff check` clean on the three files.

---

## Validation Commands

- `pytest tests/test_oauth2_unknown_resource_owner.py -q`
- `pytest tests/test_oauth2_access_gate.py -q`

---

## Test Specification

Spec §4, M6: `test_resolve_resource_owner_*`, `test_authorize_unknown_owner_redirects_to_login`,
`test_authorize_disabled_owner_redirects_to_login`, `test_consent_unknown_owner_401`, and the
authorize/consent part of `test_owner_store_outage`.

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
9. **Close the task** with `parrot sdd task close TASK-203 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none

## Completion Note

Native sonnet delivery merged. Coder ran test_oauth2_unknown_resource_owner.py (21 passed) and test_oauth2_access_gate.py (45 passed). Deviation: no user_from_id stub added to TestGateLifecycle (test never reaches the resolver).
