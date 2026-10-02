# TASK-97: OAuth2 login page — username-first passkey sign-in and conditional UI

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 8, §2 Overview item 10, §7 R5, AC13)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-95
**Assigned-to**: unassigned

---

## Context

This is P2 and C6: the OAuth2 resource-owner login page (`templates/oauth/login.html`, rendered by
`Oauth2Provider.auth_login` GET) gains passkey sign-in.

No server route is added. The page script runs these steps:
1. call `login/options`;
2. call `navigator.credentials.get`;
3. post to `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth`, which sets the session cookie;
4. navigate to `/oauth2/authorize` with the hidden authorize parameters already on the page.

**Risk R5 comes first.** It is not verified that the session `"user"` blob written by
`BasicAuth.remember()` decodes in `Oauth2Provider._decode_session_user`. The authorize hop depends
on it, so test it before writing any JS.

---

## Scope

1. **R5 check first.** Write `test_passkey_session_decodes_for_oauth2`:
   - open a session through `BasicAuth.open_session`, as `PasskeyAuth` does;
   - call `Oauth2Provider.check_session` or `_decode_session_user` against it;
   - assert that a user is resolved.
   
   If it fails, add the **thinnest** compatibility path and record it in the Completion Note. The
   authorize, consent and token code must not change (AC13). The path is one of:
   - make `_decode_session_user` also accept the `remember()` envelope; or
   - make `PasskeyAuth` also write the OAuth2 envelope after `open_session`.
2. **Template.**
   - The existing username input gets `autocomplete="username webauthn"`. Keep `name="username"`
     unchanged, because the password POST reads it.
   - Add a `#passkey-signin` button.
   - Add an inline script with `passkeySignIn(username?)`, plus a conditional-UI call:
     `navigator.credentials.get({mediation: "conditional", ...})` when
     `PublicKeyCredential.isConditionalMediationAvailable()` resolves true.
   - Feature-detect `window.PublicKeyCredential`, and hide the button when it is unsupported.
3. The script:
   - JSON-encodes the credential with `credential.toJSON()` when available, otherwise a small
     base64url encoder;
   - builds the authorize URL from the hidden inputs (`response_type`, `client_id`,
     `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`,
     `prompt`), skipping empty values; dropping PKCE fields breaks public clients (see `auth_login` POST);
   - sends **no** CSRF header: `login/options` and `/api/v1/login` are public, pre-session calls.
4. Optional e2e test `test_oauth2_login_page_passkey`:
   - Playwright with a CDP virtual authenticator;
   - marked `e2e`, and skipped when Playwright is not importable.

**NOT in scope**: changes to `auth_login`. The Q-F1 `is_active` check is TASK-91; this task does not touch the Python handler.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `templates/oauth/login.html` | MODIFY | Passkey UI and script |
| `tests/test_oauth2_passkey_session.py` | CREATE | R5 decode test |
| `tests/test_oauth2_login_page_passkey.py` | CREATE | Optional Playwright e2e (skipped when unavailable) |
| `navigator_auth/backends/oauth2/backend.py` or `navigator_auth/backends/passkey.py` | MODIFY (only if R5 fails) | Thin session-envelope compatibility |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Existing Signatures to Use
```python
# backends/oauth2/backend.py
async def check_session(self, request)                    # :561 — reads session["user"]
async def auth_login(self, request)                       # :1696 — GET renders "oauth/login.html" (:1712)
#   with params = query args + upstream_providers; POST (:1713+) password flow, redirect to
#   router["nav_oauth2_authorize"] carrying state/scope/code_challenge/code_challenge_method/nonce/prompt.
def _decode_session_user(self, encoded_user) -> Optional[OauthUser]   # :576 — parses the jsonpickle envelope (R5); read it first
async def _create_user_session(self, request, user, response=None)   # :670
# backends/abstract.py
async def remember(self, request, identity, userdata, user)   # :268 — new_session; session.save_encoded_data(request, "user", user)
```
```html
<!-- templates/oauth/login.html (57 lines) -->
<form name="authForm" action="{{ action_url }}" onsubmit="return validateForm()" method="post">  <!-- :22 -->
<input type="text" name="username">                      <!-- :24 -->
<input type="hidden" name="response_type" ...> … <input type="hidden" name="prompt" ...>  <!-- :29-37 -->
<input type="submit" value="Submit">                     <!-- :38 -->
</body>                                                    <!-- :56 -->
```
- Templates live at the repo root `templates/oauth/`, not `navigator_auth/templates/`.
- An existing test for R5-adjacent decoding is `tests/test_oauth2_session_user_decoding.py`. Copy its setup.

### Does NOT Exist
- A passkey route under `/oauth2/`. The page uses `/api/v1/auth/passkey/login/options` and `/api/v1/login`.
- Playwright in the project dependencies. The e2e test must `pytest.importorskip("playwright")`.
- `PublicKeyCredential.parseRequestOptionsFromJSON` in all browsers. Feature-detect it, and fall
  back to manual base64url decoding of `challenge` and `allowCredentials[].id`.

---

## Implementation Blueprint

### Steps (in order)
1. Do the R5 test, and the compatibility shim if needed. Stop and record the outcome before
   touching the template.
2. Template edits: add the attribute and the button, then the script before `</body>`.
3. Test manually in a browser if one is available, then the optional e2e.

### `templates/oauth/login.html` — MODIFY
```html
<!-- REPLACE `<input type="text" name="username">` (verified: login.html:24; occurrences: 1) -->
        <input type="text" name="username" id="username" autocomplete="username webauthn">

<!-- AFTER `<input type="submit" value="Submit">` (verified: login.html:38; occurrences: 1) -->
        <button type="button" id="passkey-signin" hidden>Sign in with a passkey</button>

<!-- BEFORE `</body>` (verified: login.html:56; occurrences: 1) -->
  <script>
  (function () {
    const OPTIONS_URL = "/api/v1/auth/passkey/login/options";
    const LOGIN_URL = "/api/v1/login";
    const AUTHORIZE_URL = "/oauth2/authorize";
    const PARAMS = ["response_type", "client_id", "redirect_uri", "scope", "state",
                    "code_challenge", "code_challenge_method", "nonce", "prompt"];

    function authorizeUrl() {
      // FILL IN: read each hidden input by name from document.forms.authForm; skip empty;
      //          return AUTHORIZE_URL + "?" + URLSearchParams.
    }
    function toRequestOptions(publicKey) {
      // FILL IN: PublicKeyCredential.parseRequestOptionsFromJSON when available, else
      //          base64url → ArrayBuffer for challenge and allowCredentials[].id.
    }
    function credentialToJSON(cred) {
      // FILL IN: cred.toJSON() when available, else manual base64url of rawId/response fields.
    }
    async function passkeySignIn(username, mediation) {
      // FILL IN: POST OPTIONS_URL {username?} (credentials: "same-origin") → {challenge_id, publicKey};
      //          navigator.credentials.get({publicKey: toRequestOptions(publicKey), mediation});
      //          POST LOGIN_URL with headers {"Content-Type": "application/json",
      //          "X-Auth-Method": "PasskeyAuth"} and body {challenge_id, credential};
      //          on 2xx → window.location.assign(authorizeUrl()); else show a generic error.
    }
    // FILL IN: if (!window.PublicKeyCredential) return; unhide #passkey-signin; click handler →
    //          passkeySignIn(username field value || undefined); conditional UI when
    //          PublicKeyCredential.isConditionalMediationAvailable?.() resolves true →
    //          passkeySignIn(undefined, "conditional").
  })();
  </script>
```
**Why**: A username-first click (Q9) sends the typed username for `allowCredentials`. Conditional
UI covers the usernameless path. The page is still a plain form, so the password flow is untouched.

### `tests/test_oauth2_passkey_session.py` — CREATE
```python
"""FEAT-101 TASK-97 — R5: a BasicAuth.open_session session is readable by the OAuth2 provider."""
import pytest


async def test_passkey_session_decodes_for_oauth2():
    # FILL IN: follow tests/test_oauth2_session_user_decoding.py; build the session through
    #          BasicAuth.remember/open_session; assert Oauth2Provider resolves the same user_id.
    ...
```

### FILL IN checklist
- [ ] R5 test, and the compatibility shim only if it fails, recorded in the Completion Note.
- [ ] Four JS helpers and the bootstrap.
- [ ] Optional Playwright e2e, skipped when unavailable.

---

## Acceptance Criteria

- [ ] AC13: the login page offers username-first passkey sign-in and conditional UI, and completes authorize → consent. The authorize, consent and token code is unchanged (`git diff` shows no edits to those methods).
- [ ] The R5 test passes.
- [ ] Password login on the page still works: `pytest tests/test_oauth2_upstream_idp.py tests/test_oauth2_auth_login_inactive.py -v`.
- [ ] `ruff` shows no new findings on any touched Python file.

---

## Test Specification

See above (spec §4: `test_oauth2_login_page_passkey`, plus the R5 test).

---

## Agent Instructions

1. Read the spec (Module 8, §2.10, R5).
2. Confirm TASK-95 is in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**R5 outcome**: compatible as is | shim added in <file>
**Deviations from spec**: none
