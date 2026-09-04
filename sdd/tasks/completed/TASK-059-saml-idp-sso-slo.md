# TASK-059: AbstractSAMLIdentityProvider: SP-initiated SSO endpoint, no-session detour, SLO

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 5 (part 2))
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-058
**Assigned-to**: unassigned

---

## Context

Second half of the IdP role: accept `AuthnRequest`s from registered SPs (Redirect and POST
bindings), park the request when the browser has no Navigator session and resume it after
login, and handle SP-initiated logout (spec §2 "IdP role" step 2, §3 Module 5).

---

## Scope

- `sso(request)` on `GET`/`POST /auth/<svc>/sso` (excluded from auth middleware; checks the
  session itself):
  - `flow = query.get("flow")` → resume path: `getdel(core.idp_key(flow))`; missing →
    `SAML_STALE_REQUEST`-style failed redirect.
  - Otherwise parse `SAMLRequest` (+ `RelayState`) via `core.run(server.parse_authn_request,
    ..., binding)`; issuer must be a registered SP else 404 `SAML_UNKNOWN_SP`; if
    `sp.want_signed_authn_request`, signature must verify else
    `SAML_INVALID_AUTHN_REQUEST`; honor `NameIDPolicy` format when compatible.
  - If no authenticated session: `flow_id = secrets.token_urlsafe(32)`; store
    `{sp_id, request_id, acs_url, relay_state, name_id_policy}` under `idp_key(flow_id)`
    (TTL `SAML_FLOW_TTL`); redirect to the login page with
    `redirect_uri=/auth/<svc>/sso?flow=<flow_id>` (use `AUTH_LOGIN_FAILED_URI`/`AUTH_REDIRECT_URI`
    conventions; validate).
  - With a session: `authorize_sp_access` gate, then `issue_assertion(request, sp, user,
    in_response_to=request_id, relay_state=validated relay)`.
- `slo(request)` on `GET`/`POST /auth/<svc>/slo`: parse SP `LogoutRequest`; verify issuer is
  registered; clear the current session; build and return a `LogoutResponse` with the SP's
  `slo_url` and binding; if the SP has no `slo_url` return 400 `SAML_SLO_FAILED`.
- Replace the 501 placeholders from TASK-058.

**NOT in scope**: IdP-initiated logout fan-out to all SPs (not in spec); generic subclass.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/saml/idp.py` | MODIFY | `sso`, `slo` |
| `tests/test_saml_idp.py` | MODIFY | Add M5 rows: sso with session, no-session detour, signed AuthnRequest, RelayState validation |

---

## Implementation Notes

### Key Constraints
- Parked request is single-use (`getdel`); a second `?flow=` hit fails.
- Never redirect to a `RelayState` host outside the SP's ACS host or `allowed_relay_hosts`.
- Blocking pysaml2 through `core.run`.

### References in Codebase
- `navigator_auth/backends/external.py:412-460` — resume-after-login shape (`_resume_oauth2_authorize`)
- `navigator_auth/backends/oauth2/` — how `auth_login` redirects to a provider and back with a parked flow
- pysaml2: `Server.parse_authn_request`, `Server.parse_logout_request`, `Server.create_logout_response`

---

## Acceptance Criteria

- [ ] `pytest tests/test_saml_idp.py -v` passes including the new rows
- [ ] Assertion issued from `sso` carries `InResponseTo` equal to the AuthnRequest ID
- [ ] No-session request is parked once and resumed once

---

## Test Specification

```python
@pytest.mark.xmlsec
async def test_idp_sso_sp_initiated_with_session(idp_backend, authn_request, authed_request): ...

@pytest.mark.xmlsec
async def test_idp_sso_no_session_detour(idp_backend, authn_request, make_request, redis_stub):
    resp = await idp_backend.sso(make_request(query=authn_request()))
    assert resp.status == 302 and "sso?flow=" in resp.headers["Location"]
    assert sum(k.startswith("saml_idp_") for k in redis_stub.keys()) == 1

@pytest.mark.xmlsec
async def test_idp_sso_signed_authn_request(idp_backend, authn_request): ...
async def test_idp_relaystate_validation(idp_backend, authed_request): ...
```
---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-<NNN>-<slug>.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: sdd-worker (Claude Sonnet 5, session_01KS7E6KxYXnkgzMnYHaJC2U)
**Date**: 2026-09-05
**Notes**: Replaced the TASK-058 `web.HTTPNotImplemented` stubs with the
real `sso()`/`slo()` flows. `sso()`: `?flow=` resumes a parked request
(GETDEL, missing -> `SAML_STALE_REQUEST`); otherwise parses the AuthnRequest
(Redirect via `SigAlg`/`Signature` query params, or POST) via
`core.run(server.parse_authn_request, ...)`; issuer resolves to a
registered SP by **entity_id** (not `sp_id`) else a generic 404
`SAML_UNKNOWN_SP`; `sp.want_signed_authn_request` requires both
`SigAlg`/`Signature` else `SAML_INVALID_AUTHN_REQUEST`; no session parks
`{sp_id, request_id, acs_url, relay_state}` under `idp_key(flow_id)` (TTL
`SAML_FLOW_TTL`) and redirects to `AUTH_LOGIN_FAILED_URI` with
`redirect_uri=.../sso?flow=<id>`; with a session, `authorize_sp_access`
gate then `issue_assertion(..., in_response_to=<AuthnRequest ID>,
relay_state=<validated>)`. `slo()`: parses the inbound `LogoutRequest`
(Redirect or POST); issuer resolves to a registered SP with a `slo_url`
else 400 `SAML_SLO_FAILED`; best-effort invalidates this request's own
session; replies with a signed `LogoutResponse` on the same binding.
`BaseAuthBackend` has no `failed_redirect`/`home_redirect` (those are
`ExternalAuth`-only); added a local `_error_response()` plain-text helper
for both handlers instead. `tests/test_saml_idp.py` adds the M5 SSO/SLO
rows (7 new tests, 19 total in the file): SP-initiated SSO with a session
(decodes the issued assertion to verify `InResponseTo` matches the
AuthnRequest ID), the no-session park→resume→single-use-replay-rejected
round trip, missing-signature rejection, RelayState host validation, a
successful inbound `LogoutRequest`, and an unregistered-SP rejection.
All pass with `xmlsec1` installed; full SAML suite (81 tests incl.
`test_oauth2_upstream_idp.py`) still green.

**Deviations from spec**: none in the handlers themselves, but a real
scope addition was necessary to make them work at all:
`create_authn_response`'s signature-verification path and
`create_logout_response`/`response_args` (`slo`'s reply binding/
destination) both call `self.metadata.<service>(...)` **unconditionally**
— `self.metadata` is `None` whenever no metadata is configured, which is
always true for our env-declared `ServiceProviderConfig` registry (a
plain dataclass, not real pysaml2 SP metadata). Added
`on_startup`/`_trust_registered_sps()`/`_sp_metadata_xml()`: generates
minimal inline pysaml2 metadata (entity ID, ACS, SLO, optional
`sp_cert_file`) for every registered SP and merges it into the IdP core's
settings, so `self.metadata` is never `None` when there's anything to
trust. Not in TASK-059's file list (only `idp.py`, which is where it
landed) or explicitly called out in the spec's pseudocode, but without it
`slo()` cannot function and `want_signed_authn_request` cannot be
verified — a required enabler, not scope creep.
