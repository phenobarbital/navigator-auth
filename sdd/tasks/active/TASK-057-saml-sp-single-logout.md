# TASK-057: AbstractSAMLBackend: Single Logout (SP-initiated and inbound)

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 4)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-056
**Assigned-to**: unassigned

---

## Context

Completes the SP role with SAML Single Logout in both directions using the
`SAMLSessionInfo` persisted by TASK-056 (spec §2 "SP logout", §3 Module 4).

---

## Scope

- `logout(request)`: read session `"saml"` block. If it has `session_index`: build
  `LogoutRequest` via `core.run(client.global_logout / create_logout_request, ...)`, store
  `{session_index, return_to}` under `core.slo_key(request_id)` (TTL `SAML_FLOW_TTL`), clear
  the local session (`forgot`), redirect to the IdP SLO endpoint (Redirect binding; POST
  form when the IdP metadata only offers POST). If no `session_index`: clear the local
  session and `home_redirect` to `/`.
- `finish_logout(request)` on `GET`/`POST /auth/<svc>/logout`:
  - `SAMLResponse` present → `LogoutResponse`: `getdel(slo_key(in_response_to))`; on
    success redirect to `return_to` (validated) else to `/`; log status failures as
    `SAML_SLO_FAILED` but still redirect (local session already cleared).
  - `SAMLRequest` present → inbound IdP-initiated `LogoutRequest`: parse via
    `client.parse_logout_request`; find the session by `session_index` (best-effort: the
    current browser session if its `saml.session_index` matches); clear it; build a signed
    `LogoutResponse` and return it using the IdP's binding.
- Register `POST` for `/auth/<svc>/logout` in `configure` (inherited route is `GET` only).

**NOT in scope**: IdP-side SLO endpoint (TASK-059); cross-session lookup by `SessionIndex`
in a shared store (follow-up; document as limitation).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/saml/sp.py` | MODIFY | `logout`, `finish_logout`, route |
| `tests/test_saml_slo.py` | CREATE | Unit tests (spec §4 M4 rows) |

---

## Implementation Notes

### Key Constraints
- Local session is **always** cleared, even if building the IdP request fails.
- Never trust `return_to` without `validate_redirect_host`.
- Blocking pysaml2 calls through `core.run`.

### References in Codebase
- `navigator_auth/backends/adfs.py:299-306` — logout redirect shape
- `navigator_auth/auth.py` `forgot_session` — session clearing entry point
- pysaml2: `Saml2Client.create_logout_request`, `parse_logout_request`,
  `create_logout_response`, `parse_logout_request_response`

---

## Acceptance Criteria

- [ ] `pytest tests/test_saml_slo.py -v` passes
- [ ] `test_saml_sp.py` still passes
- [ ] Logout with a `session_index` redirects to the IdP and clears the session; without one, only local logout happens

---

## Test Specification

```python
# tests/test_saml_slo.py
import pytest

@pytest.mark.xmlsec
async def test_slo_sp_initiated(sp_backend, session_with_saml, redis_stub):
    resp = await sp_backend.logout(session_with_saml(session_index="idx-1"))
    assert resp.status == 302 and "SAMLRequest=" in resp.headers["Location"]
    assert any(k.startswith("saml_slo_") for k in redis_stub.keys())

async def test_slo_no_session_index(sp_backend, session_with_saml):
    resp = await sp_backend.logout(session_with_saml(session_index=None))
    assert "SAMLRequest" not in resp.headers.get("Location", "")

@pytest.mark.xmlsec
async def test_slo_logout_response(sp_backend, logout_response, redis_stub): ...

@pytest.mark.xmlsec
async def test_slo_inbound_logout_request(sp_backend, logout_request): ...
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

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
