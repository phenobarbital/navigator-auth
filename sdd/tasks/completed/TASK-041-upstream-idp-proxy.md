# TASK-041: Upstream IdP proxy login (Google / Azure)

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 4, decision D2)
**Status**: pending
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

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none
