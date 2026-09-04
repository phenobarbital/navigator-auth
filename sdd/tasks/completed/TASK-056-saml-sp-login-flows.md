# TASK-056: AbstractSAMLBackend: SP-initiated and unsolicited login, ACS, metadata

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 3)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-055
**Assigned-to**: unassigned

---

## Context

The SP role. `AbstractSAMLBackend(ExternalAuth)` implements the `ExternalAuth` contract in
terms of `SAMLCore` and a small set of provider hooks, and fixes the security gaps of the
legacy backend: random single-use `RelayState`, `InResponseTo` validation, assertion replay
cache, host-validated redirects, persisted `SAMLSessionInfo` (spec §2 flows, §3 Module 3).

FEAT-096 (merged) added `ExternalAuth.verify_external_token` with a `NotImplementedError`
default; the SP base inherits it and needs no override.

---

## Scope

- `navigator_auth/backends/saml/sp.py`: `AbstractSAMLBackend(ExternalAuth, ABC)` with class
  attrs `_service_name = "saml"`, `config_prefix = "SAML"`, `user_mapping = SAML_MAPPING`,
  `BACKEND_QUERY_PARAMS = frozenset()`.
  - `__init__`: build `SAMLCore(prefix=self.config_prefix, settings=self.get_settings(),
    role="sp", ...)`.
  - `configure(app)`: call `super().configure(app)` then re-register
    `/auth/<svc>/callback/` for `POST` → `_auth_callback_dispatch` (aiohttp: add a second
    route with method `POST`; leave the inherited `GET` but make `auth_callback` return 405
    with hint when `request.method == "GET"`), add `GET /auth/<svc>/metadata` → `metadata`,
    add both to `AUTH_EXCLUDE_LIST_KEY`.
  - `on_startup(app)`: `super().on_startup(app)`; `core.check_xmlsec()`; load optional SP key
    pair; warm `core.sp_client` lazily (not here: base URL is per request); start metadata
    reload task registered in `self._background_tasks`. `on_cleanup`: `core.shutdown()`.
  - `authenticate(request)`: `relay = secrets.token_urlsafe(32)`; validate query
    `redirect_uri` with `validate_redirect_host`; `client = await core.sp_client(domain)`;
    `req_id, info = await core.run(client.prepare_for_authenticate, relay_state=relay,
    binding=<from SAML_BINDING>)`; `flow_store.set(core.req_key(relay), {request_id,
    internal_redirect, acs_url, oauth2_flow: request.cookies.get(OAUTH2_RESUME_COOKIE)},
    ttl=SAML_FLOW_TTL)`; redirect (Redirect binding → `HTTPFound`; POST binding → render
    auto-submit form).
  - `get_callback_state(request) -> Optional[str]`: for `POST`, the `RelayState` form field;
    else query `state`. **Modify `ExternalAuth._auth_callback_dispatch`** to call
    `await self.get_callback_state(request)` (async, reads `request.post()` once and caches
    on `request["_saml_post"]`) instead of `request.rel_url.query.get("state")`; default
    implementation on `ExternalAuth` keeps the query behavior so OIDC backends are unchanged.
  - `auth_callback(request)`: read `SAMLResponse` + `RelayState` from form; `flow = await
    flow_store.getdel(core.req_key(relay))` if relay; parse via
    `core.run(client.parse_authn_request_response, saml_response, BINDING_HTTP_POST,
    outstanding={request_id: "/"} if flow else None)`; rules: flow present → `InResponseTo`
    must equal stored `request_id` else `SAML_INVALID_RESPONSE`; no flow and response carries
    `InResponseTo` → `SAML_STALE_REQUEST`; no flow and no `InResponseTo` → unsolicited path:
    reject if `SAML_ALLOW_UNSOLICITED` is false, else `flow_store.get(assert_key)` must be
    empty → `SAML_REPLAY`, then `flow_store.set(assert_key, {...}, ttl=max(1,
    not_on_or_after-now))`. Build `AssertionResult`; `identifier = await
    self.resolve_user_identifier(result)`; `if not await self.authorize(request, result,
    identifier): SAML_FORBIDDEN`; `userdata, uid = self.build_user_info(flattened,
    token=result.name_id, mapping=self.get_attribute_mapping())`; ensure
    `userdata[self.username_attribute] = identifier`; `data = await
    self.validate_user_info(...)` (map `UserNotFound` → `SAML_USER_NOT_FOUND`); write
    `SAMLSessionInfo` into the session under `"saml"` (via `get_session(request)` after
    `remember()`); `await self.on_assertion(request, result, user)`; if `flow.oauth2_flow`
    set `request["oauth2_flow"]` so `_resume_oauth2_authorize` picks it up; return
    `home_redirect(request, token=data["token"], uri=validated internal_redirect)`. Every
    `SAMLError` → `failed_redirect(request, error=code, message=safe text)` + audit
    `saml.assertion.rejected`.
  - `metadata(request)`: `web.Response(text=core.sp_metadata(domain), content_type="text/xml")`.
  - `check_credentials(request)`: `True` (parity with ADFS/legacy).
  - Hooks per spec: abstract `get_idp_metadata`, `get_attribute_mapping`,
    `resolve_user_identifier`; concrete defaults `authorize` (True), `on_assertion` (no-op),
    `get_settings` (`<prefix>_SETTINGS`).
- Audit: emit `saml.assertion.rejected` through `AuditLog` (fields per spec §2).

**NOT in scope**: `logout` / `finish_logout` (TASK-057 — provide `NotImplementedError`
stubs so the ABC instantiates); generic `SAMLAuth` subclass (TASK-060); IdP role.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/saml/sp.py` | CREATE | `AbstractSAMLBackend` |
| `navigator_auth/backends/external.py` | MODIFY | `get_callback_state` hook used by `_auth_callback_dispatch` |
| `navigator_auth/backends/saml/__init__.py` | MODIFY | Export `AbstractSAMLBackend` |
| `tests/test_saml_sp.py` | CREATE | Unit tests (spec §4 M3 rows) |
| `tests/conftest.py` | MODIFY | `saml_keys`, `redis_stub` (in-memory `IdentityFlowStore` double), `signed_response` factory |

---

## Implementation Notes

### Pattern to Follow
```python
# navigator_auth/backends/adfs.py:150-176 — random single-use flow state
state = secrets.token_urlsafe(32)
await self._flow_store.set(f"adfs_auth_{state}", {...}, ttl=600)
# callback:
flow = await self._flow_store.getdel(f"adfs_auth_{state}")
```

### Key Constraints
- No per-request state on `self`; `redirect_uri`/ACS derived from `get_domain(request)`.
- `pysaml2` parsing runs through `core.run`.
- `failed_redirect` messages must not include XML or IdP-supplied strings.
- The `_auth_callback_dispatch` change must keep `tests/test_oauth2_upstream_idp.py` and
  identity-link tests green.

### References in Codebase
- `navigator_auth/backends/external.py:96-149` (`configure`), `:377-403` (`_auth_callback_dispatch`), `:412-460` (`_resume_oauth2_authorize`)
- `navigator_auth/backends/external.py:620-700` (`build_user_info`, `validate_user_info`)
- `navigator_auth/backends/_legacy_saml.py` — attribute flattening and RelayState handling to preserve
- `navigator_auth/identity/flow_store.py`

---

## Acceptance Criteria

- [ ] `pytest tests/test_saml_sp.py -v` passes (all M3 rows from spec §4)
- [ ] `pytest tests/test_oauth2_upstream_idp.py tests/test_oauth2_3lo_session_binding.py -v` still passes
- [ ] A minimal test subclass implementing only the three abstract hooks completes SP-initiated and unsolicited login
- [ ] Replayed unsolicited response is rejected with `SAML_REPLAY` and an audit event
- [ ] Off-host `RelayState` never becomes a redirect target

---

## Test Specification

```python
# tests/test_saml_sp.py
import pytest
from navigator_auth.backends.saml import AbstractSAMLBackend


class MinimalSP(AbstractSAMLBackend):
    def get_idp_metadata(self): return "tests/fixtures/saml/idp-metadata.xml"
    def get_attribute_mapping(self): return {"email": "mail", "username": "uid"}
    async def resolve_user_identifier(self, result): return result.attributes["email"]


@pytest.mark.xmlsec
async def test_sp_authenticate_sets_flow(sp_backend, make_request, redis_stub):
    resp = await sp_backend.authenticate(make_request(path="/api/v1/auth/saml/"))
    assert resp.status == 302
    assert any(k.startswith("saml_req_") for k in redis_stub.keys())

@pytest.mark.xmlsec
async def test_sp_acs_solicited_ok(sp_backend, signed_response, post_request): ...

@pytest.mark.xmlsec
async def test_sp_acs_unsolicited_ok_then_replay(sp_backend, signed_response, post_request):
    first = await sp_backend.auth_callback(post_request(signed_response(in_response_to=None)))
    second = await sp_backend.auth_callback(post_request(signed_response(in_response_to=None)))
    assert "error=SAML_REPLAY" in second.headers["Location"]

async def test_sp_callback_get_405(sp_backend, make_request):
    resp = await sp_backend.auth_callback(make_request(path="/auth/saml/callback/", method="GET"))
    assert resp.status == 405

async def test_sp_dispatch_reads_post_relaystate(sp_backend, post_request):
    assert await sp_backend.get_callback_state(post_request({"RelayState": "abc"})) == "abc"
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
**Notes**: Implemented `AbstractSAMLBackend(ExternalAuth, ABC)` in
`navigator_auth/backends/saml/sp.py` per spec: SP-initiated `authenticate`
(random RelayState, flow record with request_id/internal_redirect/acs_url/
oauth2_flow, Redirect or POST binding per `SAML_BINDING`), `auth_callback`
(GETDEL flow lookup, InResponseTo validation, `SAML_STALE_REQUEST` for an
unmatched InResponseTo with no flow, unsolicited path gated by
`SAML_ALLOW_UNSOLICITED` with a `saml_assert_{id}` replay cache TTL'd to
`NotOnOrAfter`, `AssertionResult` construction via `core.flatten_attributes`,
`resolve_user_identifier`/`authorize`/`on_assertion` hooks,
`build_user_info`/`validate_user_info` using a *separate* raw-SAML-attribute
flatten — `core.flatten_attributes`'s user-field-keyed output is for the
hooks/`AssertionResult`, not for `build_user_info`, whose `mapping` param
expects source-attribute-keyed data, mirroring every other backend's
`build_user_info(raw_provider_data, mapping=user_field->raw_field)` contract
— session `saml` block, host-validated `internal_redirect`), SP metadata,
`check_credentials`. `logout`/`finish_logout` are `NotImplementedError`
stubs (TASK-057). Every `SAMLError` maps to its stable code on
`failed_redirect`; audit is a structured `self.logger` line (`AuditLog.log()`
expects a PDP policy "answer" object, not a generic event — a real mismatch,
not an oversight). Added `ExternalAuth.get_callback_state()` (default: query
`state`) and switched `_auth_callback_dispatch` to await it, so the SP's
POST-body `RelayState` (cached via a `web.RequestKey`, not a raw string —
avoids aiohttp's `NotAppKeyWarning` under this repo's `filterwarnings=
["error", ...]`) is found by dispatch exactly like every OIDC backend's
query `state`. Added `tests/conftest.py` fixtures (`saml_keys`, `redis_stub`,
`post_request`, `saml_idp_core`/`signed_response`, `sp_backend`); all SAML
fixture URLs are forced to "https" (`force_https_scheme`) to match the
scheme baked into TASK-055's committed metadata fixtures regardless of this
sandbox's own `PREFERRED_AUTH_SCHEME=http`. `tests/test_saml_sp.py` (13
tests) covers every M3 spec §4 row exercisable without a real backing user
DB. Verified `pytest tests/test_saml_sp.py -v` (13 passed) and
`tests/test_oauth2_upstream_idp.py tests/test_oauth2_3lo_session_binding.py
-v` (23 passed; the 3 `test_oauth2_3lo_session_binding.py` failures are
pre-existing/environmental — `InsecureKeyLengthWarning`, reproduced
identically on unmodified `dev`). A full `tests/` run intermittently hangs
after `test_basic_auth.py` in this worktree specifically when a concurrent
session is exercising the same real Postgres/Redis from a different
worktree (confirmed: the same full suite completes in ~7s with only the
already-known pre-existing failures when run from the main `dev` checkout);
this is shared-infrastructure contention, not a regression from this task.

**Deviations from spec**: `resolve_user_identifier`, `authorize`,
`on_assertion` and `build_user_info` are wired as described, but the spec's
own pseudocode reuses the word "flattened" for two different shapes
(`AssertionResult.attributes`, user-field-keyed, vs. the raw-SAML-attribute-
keyed dict `build_user_info` actually needs) — implemented as two distinct
values (`core.flatten_attributes(...)` and a small local `_flatten_raw`
helper) rather than literally passing the same dict through both, since the
literal reading breaks `build_user_info`'s existing `get_user_mapping`
contract (used unchanged by every other backend). `tests/
test_oauth2_upstream_idp.py` was modified (not in TASK-056's file list) to
keep `_FakeBackend` working after the `_auth_callback_dispatch` change —
required by this task's own acceptance criterion that this suite still
passes.
