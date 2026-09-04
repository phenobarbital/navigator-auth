# TASK-058: AbstractSAMLIdentityProvider: SP registry, metadata, IdP-initiated SSO, audit

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 5 (part 1))
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-055
**Assigned-to**: unassigned

---

## Context

The IdP role, first half: registry of relying SPs, IdP metadata, and the IdP-initiated
flow (`/initiate/{sp_id}`) that lets a logged-in Navigator user land in an SP such as
Verizon Connect with a signed assertion (spec §2 "IdP role" steps 1, 3, 4; §3 Module 5).

**Parallelizable**: only `saml/idp.py` and a `hidden` flag in `auth.py`. No contention
with TASK-056/057. If run in a separate worktree, branch it after TASK-055 is merged.

---

## Scope

- `navigator_auth/backends/saml/idp.py`: `AbstractSAMLIdentityProvider(BaseAuthBackend, ABC)`
  with `_service_name = "saml-idp"`, `_external_auth = False`, `config_prefix = "SAML_IDP"`,
  `hidden = True`, `_description = "SAML 2.0 Identity Provider"`.
  - `__init__`: `SAMLCore(role="idp", ...)`; **no** `auth_middleware` attribute.
  - `configure(app)`: routes `GET /auth/<svc>/initiate/{sp_id}` → `initiate` (not
    excluded: session required), `GET /auth/<svc>/metadata` → `metadata` (excluded);
    placeholders for `sso`/`slo` raising 501 until TASK-059.
  - `on_startup`: `core.check_xmlsec()`; `core.load_keypair(self.get_keypair())`; parse and
    validate `get_service_providers()` (duplicate `sp_id`, missing fields → `ConfigError`);
    Redis pool + `IdentityFlowStore` like `ExternalAuth.on_startup`; `AuditLog` instance.
  - Inert auth surface: `authenticate` returns `None`, `check_credentials` returns `False`,
    `get_payload` returns `None`.
  - `metadata(request)`: `core.idp_metadata(domain)` as `text/xml`.
  - `initiate(request)`: require `request.user` authenticated (else 401 via
    `self.Unauthorized`); `sp = registry.get(sp_id)` else 404 `SAML_UNKNOWN_SP` (generic
    body); if `SAML_IDP_REQUIRE_AUTH_METHODS` set and session `auth_method` not listed →
    `SAML_SP_FORBIDDEN`; `if not await self.authorize_sp_access(request, user, sp)` →
    `SAML_SP_FORBIDDEN` + audit `saml.sp.forbidden`; `relay = validate_redirect(query
    RelayState, extra_hosts=[acs host, *sp.allowed_relay_hosts])`; `return await
    self.issue_assertion(request, sp, user, relay_state=relay)`.
  - `issue_assertion(request, sp, user, in_response_to=None, relay_state=None)`:
    `attrs = await self.build_attributes(user, sp)`; `name_id = await self.get_nameid(user,
    sp)`; `server = await core.idp_server(domain)`; `xml = await core.run(
    server.create_authn_response, identity=attrs, in_response_to=in_response_to,
    destination=sp.acs_url, sp_entity_id=sp.entity_id, name_id=NameID(format=
    sp.name_id_format, text=name_id), sign_assertion=sp.sign_assertion,
    sign_response=sp.sign_response, authn={...}, ...)` with `NotOnOrAfter = now +
    sp.assertion_ttl`; audit `saml.assertion.issued`; render the auto-submit HTML form
    (`server.apply_binding(BINDING_HTTP_POST, ...)`) with CSP-safe inline script and a
    `<noscript>` submit button; return `web.Response(text=html, content_type="text/html")`
    with `Cache-Control: no-store`.
  - Hooks per spec: abstract `get_service_providers`, `build_attributes`; defaults
    `get_nameid` (email for the emailAddress format, username otherwise),
    `authorize_sp_access` (True), `get_keypair` (from `<prefix>_KEY_FILE`/`_CERT_FILE`/
    `_KEY_PASSPHRASE`), `get_settings`.
- `navigator_auth/auth.py` `auth_methods`: skip backends with `getattr(backend, "hidden",
  False)`.
- `navigator_auth/identities.py` `AuthBackend`: no change needed (hidden backends are simply
  omitted).

**NOT in scope**: `sso` (SP-initiated) and `slo` (TASK-059); generic
`SAMLIdentityProvider` subclass reading `SAML_IDP_SERVICE_PROVIDERS` (TASK-060).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/saml/idp.py` | CREATE | `AbstractSAMLIdentityProvider` |
| `navigator_auth/backends/saml/__init__.py` | MODIFY | Export |
| `navigator_auth/auth.py` | MODIFY | `hidden` flag in `auth_methods` |
| `tests/test_saml_idp.py` | CREATE | Unit tests (spec §4 M5 rows for registry/metadata/initiate/hidden/nameid) |

---

## Implementation Notes

### Pattern to Follow
```python
# ExternalAuth.on_startup — Redis pool + flow store (external.py:161-168)
self._pool = aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
self._flow_store = IdentityFlowStore(self._pool)
```

### Key Constraints
- The IdP class must never set `request["authenticated"]` or `request.user`.
- 404 for unknown SP must not reveal which SPs exist.
- Audit events use the same field style as existing auth audit events in `abac/audit.py`.
- Signing through `core.run` only.

### References in Codebase
- `navigator_auth/auth.py:537-560` — `auth_methods`
- `navigator_auth/backends/abstract.py` — `Unauthorized`, `ForbiddenAccess`, `_background_tasks`
- `navigator_auth/abac/audit.py` — `AuditLog`
- pysaml2: `saml2.server.Server.create_authn_response`, `apply_binding`, `saml2.saml.NameID`

---

## Acceptance Criteria

- [ ] `pytest tests/test_saml_idp.py -v` passes
- [ ] `/api/v1/auth/methods` output omits the IdP backend (test)
- [ ] A minimal subclass implementing only `get_service_providers` and `build_attributes` serves metadata and IdP-initiated SSO
- [ ] Every issued assertion produces `saml.assertion.issued`; forbidden access produces `saml.sp.forbidden` and renders nothing

---

## Test Specification

```python
# tests/test_saml_idp.py
import pytest
from navigator_auth.backends.saml import AbstractSAMLIdentityProvider, ServiceProviderConfig


class MinimalIdP(AbstractSAMLIdentityProvider):
    def get_service_providers(self):
        return {"acme": ServiceProviderConfig(sp_id="acme", entity_id="urn:acme",
                                              acs_url="https://acme.test/acs")}
    async def build_attributes(self, user, sp):
        return {"mail": [user.email]}


def test_idp_registry_parse_and_validate(): ...

@pytest.mark.xmlsec
async def test_idp_initiate_ok(idp_backend, authed_request, audit_spy):
    resp = await idp_backend.initiate(authed_request(sp_id="acme"))
    assert resp.status == 200 and 'name="SAMLResponse"' in resp.text
    assert audit_spy.last.event == "saml.assertion.issued"

async def test_idp_initiate_unknown_sp(idp_backend, authed_request):
    resp = await idp_backend.initiate(authed_request(sp_id="nope"))
    assert resp.status == 404 and "acme" not in resp.text

async def test_idp_initiate_forbidden(idp_backend, authed_request, audit_spy): ...
async def test_idp_initiate_unauthenticated(idp_backend, make_request): ...
async def test_idp_hidden_from_auth_methods(auth_handler_with_idp): ...
async def test_idp_nameid_default(idp_backend, user_stub): ...
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
**Notes**: Implemented `AbstractSAMLIdentityProvider(BaseAuthBackend, ABC)`
in `navigator_auth/backends/saml/idp.py` per spec: inert auth surface
(`authenticate`->None, `check_credentials`->False, `get_payload`->None, no
`auth_middleware`, never touches `request.user`/`request["authenticated"]`);
`on_startup` validates `xmlsec1`, loads/validates the IdP key pair
(`get_keypair()`), parses/validates `get_service_providers()` into the
registry (`ConfigError` on a duplicate `sp_id` or a config that fails
`ServiceProviderConfig` validation), and owns its own Redis pool +
`IdentityFlowStore` (mirrors `ExternalAuth.on_startup` since this class
does not extend `ExternalAuth`); `metadata()`; `initiate()` (401 unless
`request.user.is_authenticated`, generic 404 for an unknown `sp_id`,
optional `SAML_IDP_REQUIRE_AUTH_METHODS` gate, `authorize_sp_access` hook
-> 403 + `saml.sp.forbidden` audit on denial, `RelayState` validated
against the ACS host + `sp.allowed_relay_hosts`); `issue_assertion()`
(signed `AuthnResponse`, `saml.assertion.issued` audit, pysaml2's own
POST-binding auto-submit HTML form, `Cache-Control: no-store`); `sso`/`slo`
501 placeholders (TASK-059); hooks per spec. `auth.py`'s `auth_methods`
(both GET/POST branches) now skips `hidden=True` backends. Two real
pysaml2 API details needed for a *parseable* assertion, not mentioned in
the spec's pseudocode: (1) `create_authn_response` without an `authn=`
argument produces an assertion with zero `AuthnStatement` elements, which
a real SP's `parse_authn_request_response` then rejects
("Invalid number of AuthnStatement found in Response: 0") — so `authn=
{"class_ref": AUTHN_PASSWORD, "authn_auth": <this IdP's entity_id>}` is
required; (2) `session_not_on_or_after` must be a `saml2.time_util.instant`
string, not a `datetime` or a raw epoch int (both raise a
`TypeError`/serialization error deep inside `pysaml2`). `tests/
test_saml_idp.py` (13 tests) covers every acceptance criterion, including
exercising the real (modified) `AuthHandler.auth_methods`, not just a
unit-level `hidden` attribute check. All pass with `xmlsec1` installed;
full SAML suite (75 tests incl. `test_oauth2_upstream_idp.py`) still green.

**Deviations from spec**: none functionally; one pre-existing,
unrelated-to-this-task issue surfaced while testing:
`BaseAuthBackend.auth_error()` (used by `self.Unauthorized`/
`self.ForbiddenAccess`, both called here exactly as the spec directs)
passes a deprecated `body=` kwarg to `web.HTTPForbidden`/`HTTPUnauthorized`
on the aiohttp version this project resolves to; under this repo's strict
`filterwarnings=["error", ...]` pytest config exercising a real
`web.Request`, that `DeprecationWarning` becomes a raised exception. Not a
FEAT-097/`abstract.py` change — worked around locally in the two affected
tests with `warnings.catch_warnings()`; flagging here since any other
backend calling those two methods with a real `web.Request` under this
test config would hit the same thing.
