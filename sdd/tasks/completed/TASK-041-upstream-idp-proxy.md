# TASK-041: Upstream IdP proxy login (Google / Azure)

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 4, decision D2)
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-038
**Assigned-to**: unassigned

---

## Context

`Oauth2Provider.auth_login` (`oauth2/backend.py:684`) authenticates only via local
username/password. Corporate users sign in with Google/Microsoft. D2: delegate to the
existing `ExternalAuth` backends, parking the pending authorize request in
`IdentityFlowStore` and resuming into consent on callback. Upstream tokens go to the
Identity Vault exactly as the identity-link flow does.

---

## Scope

- `auth_login` renders provider buttons for `OAUTH_UPSTREAM_IDP_BACKENDS` (empty list ⇒
  current behavior byte-identical). Template: `templates/oauth/login.html`.
- Park-and-resume: on provider selection generate `flow_id`; persist the **complete**
  pending authorize request (client_uid, redirect_uri, scope, state,
  code_challenge+method, resource) under `oauth2_pending_{flow_id}` in
  `IdentityFlowStore` (TTL `OAUTH_UPSTREAM_FLOW_TTL`); redirect into the backend's
  `authenticate()` carrying `{"oauth2_flow": flow_id}` in the backend's own state-keyed
  flow record.
- Resume hook in `ExternalAuth._auth_callback_dispatch` (`external.py:316`): after
  `validate_user_info` creates the session (auto-provisioning per `AUTH_MISSING_ACCOUNT`,
  upstream tokens → `IdentityStore`), detect `oauth2_flow` and 302 to
  `/oauth2/authorize?flow={flow_id}` instead of `home_redirect`.
- `authorize` restores parameters from the flow store (**single-use `getdel`**) and
  proceeds normally (consent → code). Expired/missing flow ⇒ clean `invalid_request`
  restart, never a broken redirect.
- Fix `azure.py:180`: stop mutating `self.redirect_uri` on the shared singleton; use
  `get_redirect_uri()` (`external.py:211`).
- Unit tests: `test_upstream_flow_park_resume`, `test_upstream_flow_expired`,
  `test_upstream_identity_vault`, `test_local_login_unchanged`.

**NOT in scope**: the access-gate check (TASK-042 inserts it into this flow), Okta/ADFS
enablement (config-only once this lands), any change to `GoogleAuth`/`AzureAuth` token
exchange logic.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `auth_login` provider branch; `authorize` flow-resume |
| `navigator_auth/backends/external.py` | MODIFY | Callback resume hook |
| `navigator_auth/backends/azure.py` | MODIFY | `get_redirect_uri()` fix (`:180`) |
| `templates/oauth/login.html` | MODIFY | Provider buttons |
| `tests/test_oauth2_upstream_idp.py` | CREATE | Park/resume/expiry/vault tests (mocked backend) |

---

## Implementation Notes

### Key Constraints
- The authorize request must round-trip **exactly** — losing `state` breaks CSRF
  protection; losing `code_challenge` breaks PKCE. Single-use retrieval is mandatory.
- Backends are process-wide singletons: all flow state lives in `IdentityFlowStore`
  (Redis), never on `self`.
- Reuse `AuthHandler.get_external_backend(service)` (`auth.py:341`) for backend lookup —
  `Oauth2Provider` inherits `BaseAuthBackend`, not `ExternalAuth` (class-boundary note in
  research).

### References in Codebase
- `navigator_auth/identity/flow_store.py` — `IdentityFlowStore` (`start_link`, `set`,
  `getdel`).
- `navigator_auth/backends/external.py:316` — `_auth_callback_dispatch` (identity-link
  dispatch is the pattern to extend); `:531` `validate_user_info`.
- `navigator_auth/backends/google.py:84` — flow-store usage (`google_auth_{state}`).

---

## Acceptance Criteria

- [ ] With `OAUTH_UPSTREAM_IDP_BACKENDS=["google","azure"]`, an unauthenticated authorize
      offers both providers; the full round-trip resumes into consent with all parameters
      intact
- [ ] Upstream tokens land ciphered in `auth.user_identities`
- [ ] Empty setting ⇒ existing local login flow byte-identical (regression test)
- [ ] Expired flow ⇒ clean `invalid_request`, no broken redirect
- [ ] `azure.py` no longer mutates the singleton `redirect_uri`
- [ ] Tests pass: `pytest tests/test_oauth2_upstream_idp.py -v`

---

## Test Specification

```python
# tests/test_oauth2_upstream_idp.py
# fixture mock_external_backend: fakes GoogleAuth authenticate()/auth_callback()
#   without network; drives the resume hook
# test_upstream_flow_park_resume, test_upstream_flow_expired,
# test_upstream_identity_vault, test_local_login_unchanged
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-038 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (Claude Opus 5)
**Date**: 2026-08-31
**Notes**: `auth_login` GET now renders `upstream_providers` and handles `provider=` by parking the pending authorize request and redirecting to `/auth/{provider}/login`. `PENDING_AUTHORIZE_FIELDS` covers client_id, redirect_uri, response_type, scope, state, code_challenge(+method), nonce, prompt and resource; a test asserts every one survives the hop. Parked under `oauth2_pending_{flow_id}` in `IdentityFlowStore` with `OAUTH_UPSTREAM_FLOW_TTL`. `Oauth2Provider` extends `BaseAuthBackend`, not `ExternalAuth`, so it builds its own flow store lazily via a `flow_store` property over `REDIS_AUTH_URL` — never on `self`. `authorize` resumes via single-use `getdel`; parked values deliberately override anything on the resume URL, so a tampered resume cannot swap `state`, `code_challenge` or `redirect_uri` (covered by `test_parked_values_win_over_url`). Missing/expired flow ⇒ 400 `invalid_request`, explicitly asserted not to be a redirect. `ExternalAuth._auth_callback_dispatch` reads the marker *before* `auth_callback` (backends consume their own state record inside it), then rewrites `Location` in place — the response object is edited rather than rebuilt so the session cookie and any backend headers survive. Identity-link dispatch still wins; a failed provider login (non-3xx) is passed through untouched instead of becoming a consent redirect. `_vault_upstream_token` ciphers the upstream credential into `auth.user_identities` through the same `IdentityStore.save_linked_identity` path the identity-link flow uses, best-effort so a vault failure cannot break login. `azure.py` no longer mutates the singleton `self.redirect_uri` — it uses `get_redirect_uri(request)`; the old code was doubly broken (it destroyed the `{domain}` template on first use, pinning every later login to the first caller's host). 23 new tests; 276 pass across the non-DB OAuth2 suites.

**Deviations from spec**: one mechanism change. The task specified carrying `{"oauth2_flow": flow_id}` "through the backend's own state-keyed flow record", but each backend generates its own `state` *inside* `authenticate()` and writes its own record (`google_auth_{state}`, `azure_auth_{state}`, okta/odoo/github variants) with no injection point — the AS cannot know that state in advance, and implementing it that way would require editing six backend files that are not in this task's scope. Instead the opaque flow id travels in a short-lived HttpOnly/SameSite=Lax cookie (`nav_oauth2_flow`) set on the redirect into the provider and read back at the callback; the authorize request itself never leaves the server, staying in `IdentityFlowStore` exactly as specified. `_pending_oauth2_flow` still prefers `request['oauth2_flow']` when present, so the specified per-backend mechanism works if a backend later supplies it. Also note: the normal login path never persisted upstream tokens (only the identity-link path did), so `_vault_upstream_token` is new code rather than a reuse of an existing hook.
