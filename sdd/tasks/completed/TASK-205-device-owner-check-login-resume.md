# TASK-205: Device verification checks the owner; device login resumes the verification form

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-204
**Assigned-to**: unassigned

---

## Context

Spec §2 (device-login paragraph), decision **D5**, §3 Module 6, §7 "Device login resume", AC13.
`device_verification` is the third consumer of the session user (`backend.py:2685-2697`): an approved
device code yields tokens for that `user_id`, so it needs the same owner check as authorize. Its
no-session branch already redirects to login with `device_user_code`, but nothing carries the code
through the login form, and a successful login always goes to `/oauth2/authorize` — so device login
never resumes. After login the user must land on the **pre-filled** device verification form and
approve it explicitly; login alone never approves a device.

FEAT-106 (merged first) adds a second-factor hop to the OAuth2 login: `auth_login` → `oauth/mfa.html` →
`auth_login_mfa`, both ending in its `_authorize_redirect(request, data)` helper. The device resume must
work through that hop too (spec §7: "Exercise the complete flow with FEAT-106 changes present").

---

## Scope

- `device_verification` POST: after the `user_obj` checks, `_resolve_resource_owner(user_obj.user_id)`;
  `UserNotFound`/`FailedAuth` → `_redirect_to_login(request, {"device_user_code": raw_user_code})`
  (device code stays pending); `IdentityStoreUnavailable` → 503. Use the same helper for the existing
  no-session branch (`:2686-2692`).
- Login resume: when the login data carries `device_user_code`, the post-login redirect goes to the
  named route `nav_oauth2_device` with `?user_code=<code>` instead of `nav_oauth2_authorize`. Implement it
  in FEAT-106's `_authorize_redirect` so `auth_login` and `auth_login_mfa` both get it. Accept only a
  code matching `^[A-Za-z0-9 -]{1,32}$`, never a URL; otherwise 400.
- `auth_login` GET: ignore `provider=` when `device_user_code` is present (upstream login has no device return path).
- Templates: `oauth/login.html` and `oauth/mfa.html` carry `device_user_code` as a hidden field;
  `login.html` hides the passkey button/script and the upstream providers when `device_user_code` is set.
- Tests in `tests/test_device_verification.py`; stub the owner in `TestDeviceFlowGate` of
  `tests/test_oauth2_access_gate.py`.

**NOT in scope**: the device-code token grant (TASK-204 — it delegates to the code grant);
supporting passkey/upstream login for device flows (spec: hidden until they support the same path).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Owner check + resume redirect + `provider=` guard |
| `templates/oauth/login.html` | MODIFY | Hidden `device_user_code`; hide passkey/upstream for device login |
| `templates/oauth/mfa.html` | MODIFY | Hidden `device_user_code` (file created by FEAT-106) |
| `tests/test_device_verification.py` | MODIFY | AC13 tests; stub the owner in `_make_provider` |
| `tests/test_oauth2_access_gate.py` | MODIFY | Stub `user_from_id` in `TestDeviceFlowGate` |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11).
> `_authorize_redirect`, `auth_login_mfa` and `templates/oauth/mfa.html` are **FEAT-106 review-fix
> deliverables** (spec `basicauth-otp-2fa-review-fixes` M6, TASK-184) — they exist once FEAT-106 merges;
> if they do not, STOP: the spec requires FEAT-106 merged first.

### Verified Imports
```python
import re                                            # stdlib (device code check)
# backend.py already imports FailedAuth, UserNotFound, IdentityStoreUnavailable (TASK-203), web, escape
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
router.add_route("*", self.device_uri, self.device_verification, name="nav_oauth2_device")   # :372
router.add_route("*", self.login_uri, self.auth_login, name="nav_oauth2_login")              # :328
async def auth_login(self, request: web.Request):                    # :1616
    #   GET: data = dict(request.query); provider = data.pop("provider", None) → _start_upstream_login (:1627-1629)
    #        data["upstream_providers"] = self._upstream_providers()   (:1631); view("oauth/login.html", params=data)
    #   POST: get_login_form → authenticate_credentials → user_is_active → (dev) payload for nav_oauth2_authorize
    #         (:1648-1670) → web.HTTPFound → _create_user_session(request, user, response=response)
def _authorize_redirect(self, request: web.Request, data: dict) -> web.HTTPFound:   # FEAT-106 (extracted from :1648-1670)
async def auth_login_mfa(self, request: web.Request) -> web.StreamResponse:         # FEAT-106, ends in _authorize_redirect
async def device_verification(self, request: web.Request):           # :2604
    #   GET (:2614-2631): renders oauth/device.html with params=query (user_code pre-filled) or an inline form
    #   POST: data = await self.get_payload(request); action = data.get("action", "approve")       (:2634-2635)
    #         raw_user_code = data.get("user_code", "").upper().replace("-", "").replace(" ", "")  (:2636)
    #   :2685  session_user = await self.check_session(request)
    #   :2686-2692 if not session_user: location = …["nav_oauth2_login"].url_for();
    #              raise web.HTTPFound(location.with_query(action_url=str(location), device_user_code=raw_user_code))
    #   :2695  user_obj = self._decode_session_user(session_user)
    #   :2697  return self._error_response("access_denied", "Cannot resolve session user.", status=401)
    #   :2699  if action == "deny": …
async def _approve_device_code(...):                                  # :2757
# from TASK-203:
def _redirect_to_login(self, request, data: dict) -> NoReturn         # query = action_url + **data
async def _resolve_resource_owner(self, user_id) -> Any
def _owner_store_unavailable(self) -> web.StreamResponse

# templates/oauth/login.html (dev)
#   :22  <form name="authForm" action="{{ action_url }}" onsubmit="return validateForm()" method="post">
#   :29-37 hidden authorize fields; :37 <input type="hidden" name="prompt" value="{{ prompt }}">
#   :39  <button type="button" id="passkey-signin" hidden>Sign in with a passkey</button>
#   :40  <div id="passkey-error" role="alert" hidden></div>
#   :43  {% if upstream_providers %} … {% endif %} (:57)
#   :58  <script> (passkey IIFE, button.hidden = false at :172) … </script> (:184)

# tests
tests/test_device_verification.py:100   def _make_provider(...)   ; :328 test_device_verification_no_session_redirects
tests/test_oauth2_access_gate.py:464    TestDeviceFlowGate.test_device_denial_renders_not_redirects
```

### Measured at task time (owner check simulated at the device call site on dev)
New failures: `test_device_verification.py::test_device_approval_binds_user`,
`::test_device_consent_skip_with_grant`, `test_oauth2_access_gate.py::TestDeviceFlowGate::test_device_denial_renders_not_redirects`,
`test_oauth2_introspection_device_integration.py::test_device_user_id_survives` (that file's `_make_provider`
stub is added by TASK-204 and covers it — verify).

### Does NOT Exist
- ~~`next=`~~, ~~`return_to=`~~, ~~`redirect_after_login`~~ — no return-URL parameter exists, and none may be added (spec §2: "never an arbitrary return URL").
- No `device_user_code` field in `oauth/login.html` today; `auth_login` POST never reads it.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "templates/oauth/login.html", "action": "MODIFY"},
    {"path": "templates/oauth/mfa.html", "action": "MODIFY"},
    {"path": "tests/test_device_verification.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_access_gate.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.device_verification",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.auth_login",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._approve_device_code"
  ]
}
```

---

## Implementation Notes

### Decisions fixed for this task
- The owner check runs **before** `if action == "deny"`: an unknown owner neither approves nor denies.
- Resume target: `request.app.router["nav_oauth2_device"].url_for().with_query(user_code=<code>)` — a GET,
  which renders the pre-filled form; approval needs the user's explicit POST.
- `device_user_code` is data: validate `^[A-Za-z0-9 -]{1,32}$`; on mismatch `web.HTTPBadRequest(reason="Invalid device code.")`.
- `{% if not device_user_code %}` around the passkey button, error box and script, and
  `{% if upstream_providers and not device_user_code %}` for the upstream block.

---

## Implementation Blueprint

### Steps (in order)
1. Confirm FEAT-106 is in the base: `grep -c '_authorize_redirect' navigator_auth/backends/oauth2/backend.py` ≥ 2 and `templates/oauth/mfa.html` exists. Otherwise STOP.
2. Device verification: no-session branch → `_redirect_to_login`; owner check after `user_obj` — *why*: D5, AC13.
3. `_authorize_redirect`: device branch — *why*: one place serves `auth_login` and `auth_login_mfa`.
4. `auth_login` GET: drop `provider` when `device_user_code` is present.
5. Templates. 6. Tests + fixture stubs.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — device verification
```python
# occurrences: 1 (verified: grep -c 'device_user_code=raw_user_code,' navigator_auth/backends/oauth2/backend.py)
# REPLACE the body of `if not session_user:` that contains it (verified: :2687-2692) WITH:
            self._redirect_to_login(request, {"device_user_code": raw_user_code})

# occurrences: 1 (verified: grep -c 'return self._error_response("access_denied", "Cannot resolve session user.", status=401)' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: :2697)
        try:
            await self._resolve_resource_owner(user_obj.user_id)
        except (UserNotFound, FailedAuth):
            # FEAT-108 D5: re-authenticate; the device code stays pending.
            self._redirect_to_login(request, {"device_user_code": raw_user_code})
        except IdentityStoreUnavailable:
            return self._owner_store_unavailable()
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — resume redirect
```python
# FILL IN: anchor on FEAT-106's `def _authorize_redirect(self, request: web.Request, data: dict) -> web.HTTPFound:`
#          (verify count 1 after the merge). At the top of its body insert:
        device_user_code = data.get("device_user_code")
        if device_user_code:
            # FEAT-108: device login resumes the verification form; the code is data, never a URL.
            if not _DEVICE_USER_CODE_RE.fullmatch(str(device_user_code)):
                raise web.HTTPBadRequest(reason="Invalid device code.")
            location = request.app.router["nav_oauth2_device"].url_for()
            return web.HTTPFound(location.with_query(user_code=str(device_user_code)))
# and at module level, next to the other module constants:
_DEVICE_USER_CODE_RE = re.compile(r"[A-Za-z0-9 -]{1,32}")
# Bounded by AC13: auth_login and auth_login_mfa must both reach this branch through the helper; keep the
# helper's authorize key list unchanged for every non-device login (FEAT-106 AC5).
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — `auth_login` GET
```python
# occurrences: 1 (verified: grep -c 'data\["upstream_providers"\] = self._upstream_providers()' navigator_auth/backends/oauth2/backend.py)
# FILL IN: in the GET branch, before `provider = data.pop("provider", None)` (verified :1628), make the
#          pop unconditional but only start the upstream login when "device_user_code" is NOT in data —
#          bounded by AC13 ("upstream choices are hidden for device login").
```

### `templates/oauth/login.html` (MODIFY)
```html
<!-- occurrences: 1 (verified: grep -c '<input type="hidden" name="prompt" value="{{ prompt }}">' templates/oauth/login.html) -->
<!-- AFTER — insert below the prompt hidden input (verified: :37) -->
        <input type="hidden" name="device_user_code" value="{{ device_user_code }}">
<!-- occurrences: 1 (verified: grep -c '{% if upstream_providers %}' templates/oauth/login.html)
     REPLACE `{% if upstream_providers %}` (verified: :43) WITH `{% if upstream_providers and not device_user_code %}` -->
<!-- FILL IN: wrap the passkey button + error box (:39-40) and the passkey <script>…</script> (:58-184; the
     second of the two `<script` occurrences) in `{% if not device_user_code %}…{% endif %}` — bounded by AC13. -->
```

### `templates/oauth/mfa.html` (MODIFY)
```html
<!-- FILL IN: next to the other authorize hidden fields FEAT-106 renders, add
     <input type="hidden" name="device_user_code" value="{{ device_user_code }}"> (escaped like its siblings),
     and make sure auth_login passes device_user_code into this template's params — bounded by AC13. -->
```

### `tests/test_device_verification.py` (MODIFY)
```python
# FILL IN: in `_make_provider` (verified :100) stub `provider._idp.user_from_id = AsyncMock(return_value=<active owner>)`
#          so the existing approval tests keep passing. Then add:
#   - test_device_verification_unknown_owner_redirects: user_from_id raises UserNotFound ⇒ HTTPFound to
#     nav_oauth2_login with device_user_code; dc status unchanged (pending) — AC13.
#   - test_device_verification_owner_outage_503: IdentityStoreUnavailable ⇒ 503, dc pending — AC16a.
#   - test_device_login_resumes_verification (spec §4 integration): no-session and unknown-owner branches redirect
#     to login; POST the real login form (auth_login with device_user_code) ⇒ HTTPFound to nav_oauth2_device
#     ?user_code=…, NOT nav_oauth2_authorize; the device code is still pending (login alone approves nothing);
#     GET the device route ⇒ pre-filled form; explicit POST approve ⇒ approved; redeeming it issues a token.
#     Build an aiohttp app registering the provider's named routes (nav_oauth2_login, nav_oauth2_device,
#     nav_oauth2_authorize) so url_for works. Also cover the FEAT-106 2FA hop if its test helpers allow it.
#   - test_device_login_rejects_url_like_code: device_user_code="https://evil" ⇒ 400.
#   - test_device_login_hides_passkey_and_upstream: render oauth/login.html with device_user_code set ⇒
#     no "passkey-signin" and no "Continue with" — AC13.
```

### `tests/test_oauth2_access_gate.py` (MODIFY)
```python
# FILL IN: in TestDeviceFlowGate.test_device_denial_renders_not_redirects (verified :464) stub
#          provider._idp.user_from_id = AsyncMock(return_value=<active owner with the test's USER_ID>); nothing else.
```

### FILL IN checklist
- [ ] `_authorize_redirect` device branch (+ `_DEVICE_USER_CODE_RE`); AC13.
- [ ] `auth_login` GET `provider` guard; AC13.
- [ ] Template conditionals (login + mfa); AC13.
- [ ] Device tests incl. the end-to-end resume; fixture stubs; AC13, AC16a.

---

## Acceptance Criteria

- [ ] AC13: `device_verification` for an unknown/disabled session owner redirects to login with `device_user_code` and leaves the device code pending; both this path and no-session login return to the pre-filled device verification form after login (also through FEAT-106's second-factor hop); only an explicit subsequent approval permits redemption; passkey and upstream choices are hidden for device login.
- [ ] AC16a (device): an identity-store outage gives a generic 503 and approves nothing.
- [ ] A `device_user_code` that is not a plain code is refused with 400; no return URL is accepted.
- [ ] `tests/test_device_verification.py`, `tests/test_oauth2_access_gate.py`, `tests/test_oauth2_introspection_device_integration.py` pass.
- [ ] `ruff check navigator_auth/backends/oauth2/backend.py tests/test_device_verification.py tests/test_oauth2_access_gate.py` clean.

---

## Validation Commands

- `pytest tests/test_device_verification.py -q`
- `pytest tests/test_oauth2_access_gate.py tests/test_oauth2_introspection_device_integration.py -q`

---

## Test Specification

Spec §4: `test_device_verification_unknown_owner_redirects` (M6), `test_device_login_resumes_verification`
(integration), plus the outage and URL-rejection cases above.

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
9. **Close the task** with `parrot sdd task close TASK-205 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none

## Completion Note

Native sonnet delivery merged. Coder ran test_device_verification.py (12 passed) and access_gate + introspection_device_integration (49 passed). Limit: the FEAT-106 second-factor hop is covered only via the shared _authorize_redirect helper, not an end-to-end auth_login_mfa run.
