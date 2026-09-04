# Brainstorm: Abstract SAML 2.0 Backend (SP + IdP roles)

**Date**: 2026-09-04
**Author**: Jesus Lara
**Status**: exploration
**Recommended Option**: A

> **Scope note:** this brainstorm does **not** propose a Verizon Connect backend. It defines the
> abstract SAML surface (authenticate, authorize/callback, logout, metadata, assertion issuing)
> that *any* concrete provider subclass will extend. Verizon Connect is used only as the first
> real-world counterpart to validate the abstraction against.
>
> **Research caveat:** the two Verizon Connect help articles the user linked
> (`fleet-help.verizonconnect.com/.../360010868799` and `.../360010850699`) return HTTP 403 to
> non-browser fetches. Their published summaries (search snippets, and the sibling Reveal article
> `reveal-help.verizonconnect.com/.../50641471986579`) state: *"Verizon Connect provides support
> for SSO using SAML v2.0. Once authenticated by your internal Identity Provider, the user clicks a
> link or button on your IdP site which directs them to the Verizon Connect platform, and your IdP
> generates a SAML v2.0 'bearer' assertion."* The role split below is derived from that. The ACS
> URL, Entity ID, NameID format and required attributes must be confirmed from the articles
> before the Verizon subclass is written (see Open Questions).

---

## Problem Statement

`navigator-auth` today ships one SAML backend, `navigator_auth/backends/saml.py` (`SAMLAuth`,
201 lines), written on `python3-saml` (OneLogin). It works as a minimal **Service Provider**
but is not a base anyone can extend, and it has real gaps:

1. **Not abstract.** Everything is concrete and bound to one global `SAML_PATH` /
   `SAML_SETTINGS` / `SAML_MAPPING`. A second IdP (Okta SAML, Entra ID SAML, a partner IdP)
   requires copy-paste, not subclassing. There is no defined set of extension points.
2. **SP only.** Verizon Connect — the first integration driving this work — is a SAML
   **Service Provider**. It consumes assertions; it does not issue them. To "use Verizon Connect
   SSO" from Navigator, Navigator must either (a) act as a SAML **Identity Provider** and issue
   a signed bearer assertion for the already-logged-in Navigator user, or (b) bounce the user
   through a real IdP's IdP-initiated endpoint. Option (b) exists today only as the ADFS-specific
   `ADFS_SAML_RELAY_RP` hack in `adfs.py:286-297`. There is no IdP role at all.
3. **Security gaps in the current SP.** No `InResponseTo` / request-ID tracking (the
   `redirect_uri` is silently dropped, `saml.py:71-74`); no replay cache for unsolicited
   responses; `RelayState` is trusted as a redirect target with only a self-loop check
   (`saml.py:119-125`) — the same class of open-redirect the ADFS backend just fixed in commit
   `a00875d`; SLO is a stub that never persists `NameID`/`SessionIndex`.
4. **Engine choice.** `python3-saml` cannot act as an IdP. The IdP role needs a library that
   can build and sign `AuthnResponse`/`Assertion` and publish IdP metadata.

**Who is affected:** integrators who must federate Navigator with SAML-only SaaS (Verizon
Connect first; any SAML SP later); operators who want Navigator to accept a corporate SAML IdP
without ADFS/OIDC; the auth maintainers who must keep one coherent SAML surface instead of
per-provider forks.

**Why now:** Verizon Connect integration is expected; the ADFS relay hack is not generalizable;
FEAT-095 has landed and there are no in-flight SDD tasks (`sdd/tasks/active/` is empty), so the
`ExternalAuth` base is stable to build on.

---

## Constraints & Requirements

*(Decisions taken during discovery, rounds 1 and 2.)*

- **Two roles, two abstract classes, one shared core.** `AbstractSAMLBackend` (SP role,
  extends `ExternalAuth`) and `AbstractSAMLIdentityProvider` (IdP role, reads the existing
  Navigator session, issues assertions). Both share a SAML core for keys, metadata, attribute
  mapping and engine wrapping.
- **Flows in scope for the SP role:** SP-initiated login, IdP-initiated (unsolicited) login,
  Single Logout (SP-initiated and inbound IdP `LogoutRequest`), SP metadata publishing.
- **Flows in scope for the IdP role:** IdP-initiated SSO (user clicks "Open Verizon Connect",
  Navigator posts a signed assertion to the SP's ACS), SP-initiated SSO (SP sends `AuthnRequest`
  to Navigator's SSO endpoint), IdP metadata publishing, SLO where the SP supports it.
- **Engine: `pysaml2`.** Replaces `python3-saml`, `xmlsec` (Python binding). `pysaml2` is the
  only maintained Python library implementing both SP and IdP roles. It shells out to the
  `xmlsec1` **binary** (system package), which becomes a deployment requirement.
- **Migration: reimplement `SAMLAuth` on the new base and drop `python3-saml`.** `SAMLAuth`
  stays exported from `navigator_auth.backends` as the generic reference subclass. This is a
  **breaking change** for anyone with a `python3-saml` `settings.json`; `SAML_PATH` and
  `SAML_SETTINGS` are honored where the shapes map, documented where they do not.
- **Configuration: per-backend env prefix + optional settings dict.** Each subclass declares a
  prefix (e.g. `SAML_*` for the generic one, later `VERIZON_SAML_*`) resolved through
  `navconfig`, plus an optional JSON settings dict, plus a mapping dict following the
  `ADFS_MAPPING` / `SAML_MAPPING` pattern in `conf.py`.
- **IdP registry: env-declared SPs + PEM key paths.** `SAML_IDP_KEY_FILE`, `SAML_IDP_CERT_FILE`
  and a JSON list of relying SPs (entity_id, ACS URL, binding, NameID format, attribute map,
  sign-assertion/sign-response flags). No DB migration.
- **Per-flow state (all four):**
  - AuthnRequest ID + `internal_redirect` in Redis via `IdentityFlowStore`, keyed by a random
    single-use `RelayState`, consumed with `GETDEL` (mirrors the ADFS nonce fix in `a00875d`).
  - Assertion-ID replay cache in Redis with TTL = `NotOnOrAfter` − now, for unsolicited
    responses.
  - `NameID` + `NameID format` + `SessionIndex` stored in the user session for SLO.
  - Issued-assertion audit record (SP entity_id, user, assertion ID, expiry) through the
    existing `AuditLog` (`navigator_auth/abac/audit.py`).
- **No mutation of backend instance state per request.** Backends are process-wide singletons
  (see comment in `adfs.py:151-153`); all per-flow data goes to the flow store or the session.
- **Redirect safety.** Any `RelayState`-derived or `redirect_uri`-derived target must pass an
  `ALLOWED_HOSTS` check, generalizing `ADFSAuth._validate_internal_redirect` (`adfs.py:120-135`)
  into the base.
- **Security posture:** signed responses **or** signed assertions required (configurable
  per IdP/SP, default: require assertion signature); audience restriction validated; clock skew
  tolerance configurable; XML parsing through `pysaml2`'s hardened `defusedxml` path only.
- **Async discipline:** `pysaml2` is synchronous and spawns `xmlsec1`; all signing/validation
  calls run through `BaseAuthBackend.threaded_function` / `run_in_executor` so the aiohttp loop
  is never blocked.
- **Tests:** `pytest` + `pytest-asyncio` with a fake IdP/SP pair (self-signed test keys in
  `tests/fixtures/`), no network. `xmlsec1` must be available in CI.

---

## Options Explored

### Option A: Two abstract classes on `pysaml2` with a shared SAML core

Introduce a `navigator_auth/backends/saml/` package:

- `core.py` — `SAMLCore`: loads keys/certs, builds the `pysaml2` config dict from the
  backend's env prefix + settings dict, wraps the sync engine calls in the executor, exposes
  metadata generation and the attribute-mapping helpers. Owns the flow-store and replay-cache
  key conventions.
- `sp.py` — `AbstractSAMLBackend(ExternalAuth)`: implements the `ExternalAuth` contract
  (`authenticate`, `auth_callback`, `logout`, `finish_logout`, `check_credentials`) in terms of
  a small set of provider hooks that subclasses override: `get_idp_metadata()`,
  `get_attribute_mapping()`, `resolve_user_identifier(nameid, attributes)`,
  `authorize(request, identity, attributes)` (post-assertion access decision, e.g. group
  gating), `on_assertion(...)`. Routes: `/api/v1/auth/<svc>/` (start), `/auth/<svc>/callback/`
  (ACS, **POST**), `/auth/<svc>/metadata`, `/auth/<svc>/slo` (inbound), logout pair.
- `idp.py` — `AbstractSAMLIdentityProvider`: not an auth backend (does not authenticate).
  Reads `request.user` / session, and per registered SP builds and signs an assertion. Routes:
  `/auth/saml/idp/metadata`, `/auth/saml/idp/sso` (SP-initiated: parse `AuthnRequest`),
  `/auth/saml/idp/initiate/<sp_id>` (IdP-initiated: auto-POST form to the SP's ACS),
  `/auth/saml/idp/slo`. Hooks: `get_service_providers()`, `build_attributes(user, sp)`,
  `get_nameid(user, sp)`, `authorize_sp_access(user, sp)`.
- `saml.py` (existing file) becomes the generic `SAMLAuth(AbstractSAMLBackend)` reading
  `SAML_*` settings.

Both classes register through the existing `AUTHENTICATION_BACKENDS` loader in `auth.py`
(`get_backends`, line 228) — the IdP class gets a `configure(app)`/`on_startup` and is a
no-op in the middleware chain (it never claims a request as authenticated).

✅ **Pros:**
- One library covers SP and IdP; metadata, signing, encryption, SLO all handled by `pysaml2`.
- Clear separation of the two roles; a subclass never has to stub the role it does not use.
- Reuses `ExternalAuth` end-to-end (flow store, `build_user_info`, `validate_user_info`,
  `home_redirect`/`failed_redirect`, OAuth2-AS resume detour, identity-link dispatch).
- Fixes the current SP security gaps as part of the base, not per provider.
- The ADFS relay hack can later be re-expressed as "IdP role with SP = Verizon" or as a
  subclass that delegates, without touching `adfs.py` now.

❌ **Cons:**
- `xmlsec1` binary becomes a hard runtime dependency (Dockerfiles, CI, dev machines).
- Breaking change for existing `python3-saml` settings layouts.
- `pysaml2`'s config model is large and its docs are uneven; the core wrapper carries the
  complexity so subclasses do not.
- Largest surface of the three options.

📊 **Effort:** High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `pysaml2` `>=7.5,<8` | SAML 2.0 SP + IdP engine, metadata, SLO | 7.5.4 latest on PyPI; xmlsec 1.3 support since 7.4.2 |
| `xmlsec1` (system binary) | XML-DSig signing/verification used by `pysaml2` | apt/dnf/apk package; path configurable via `xmlsec_binary` |
| `defusedxml` | XXE-safe XML parsing | pulled in by `pysaml2` |
| `cryptography` | Key/cert loading, cert fingerprints | already an indirect dependency |
| `redis` (`redis.asyncio`) | Flow store + replay cache | already used by `ExternalAuth` |
| `pytest`, `pytest-asyncio` | Tests with fake IdP/SP | already in dev deps |

🔗 **Existing Code to Reuse:**
- `navigator_auth/backends/external.py` — `ExternalAuth`: route registration (`configure`),
  `on_startup` Redis pool + `IdentityFlowStore`, `build_user_info`, `validate_user_info`,
  `home_redirect`, `failed_redirect`, `_auth_callback_dispatch` (identity-link + OAuth2 AS
  resume), `threaded_function` from `BaseAuthBackend`.
- `navigator_auth/identity/flow_store.py` — `IdentityFlowStore.set/getdel` for AuthnRequest
  state and for the assertion replay cache.
- `navigator_auth/backends/adfs.py:120-135` — `_validate_internal_redirect` with
  `ALLOWED_HOSTS`; promote to the base.
- `navigator_auth/backends/adfs.py:150-176` — the random single-use `state` pattern.
- `navigator_auth/backends/saml.py` — attribute flattening, `RelayState` handling, metadata
  endpoint shape; keep the behavior, rewrite on the new core.
- `navigator_auth/conf.py:456-484` — `SAML_PATH`, `SAML_SETTINGS`, `SAML_MAPPING` loading
  pattern (orjson + fallback) to replicate per prefix.
- `navigator_auth/abac/audit.py` — `AuditLog` for issued-assertion records.
- `navigator_auth/backends/jwksutils.py:22-24` — already parses SAML metadata namespaces for
  ADFS keys; the IdP-metadata key extraction can be shared.

---

### Option B: Keep `python3-saml` for the SP role, hand-roll the IdP role with `signxml`

Refactor the existing `SAMLAuth` into an abstract SP base on `python3-saml` (engine-agnostic
hooks around `OneLogin_Saml2_Auth`), and build the IdP role separately: generate the
`Response`/`Assertion` XML from templates, sign it with `signxml` + `lxml`, publish IdP
metadata by hand.

✅ **Pros:**
- No breaking change for existing SP deployments; `xmlsec` Python binding already installed.
- Smaller SP refactor; most of `saml.py` survives.
- `signxml` is pure Python + `cryptography`, no `xmlsec1` binary.

❌ **Cons:**
- Two SAML stacks to maintain; IdP-side SAML (AuthnRequest parsing, encryption, SLO,
  conditions, subject confirmation, metadata) reimplemented and reviewed by hand — this is the
  part where SAML implementations historically get signature-wrapping bugs.
- `python3-saml` still cannot parse inbound `AuthnRequest` for the IdP SSO endpoint.
- Diverges from the round-1 decision to standardize on `pysaml2`.

📊 **Effort:** High (IdP side), Medium (SP side)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `python3-saml` `>=1.16` | SP role | already in `pyproject.toml` |
| `xmlsec` `>=1.3.17` | Python binding used by python3-saml | already installed |
| `signxml` `>=4.0` | XML-DSig for issued assertions | pure Python; well maintained |
| `lxml` `>=6.0` | XML building | already installed |

🔗 **Existing Code to Reuse:**
- `navigator_auth/backends/saml.py` — retained almost entirely.
- `navigator_auth/backends/external.py` — as in Option A.
- `navigator_auth/identity/flow_store.py` — as in Option A.

---

### Option C: Single abstract class carrying both roles

One `AbstractSAMLBackend(ExternalAuth)` on `pysaml2` exposing SP methods (`authenticate`,
`auth_callback`, `logout`, `metadata`) **and** IdP methods (`sso`, `initiate`, `idp_metadata`,
`issue_assertion`), with a class attribute `roles = {"sp"}` / `{"idp"}` / both controlling
which routes are registered. Subclasses implement one side and inherit `NotImplementedError`
defaults for the other.

✅ **Pros:**
- One class to document, one loader entry, one config prefix.
- Easy to build a "bridge" subclass that is both SP toward a corporate IdP and IdP toward
  Verizon in one object.

❌ **Cons:**
- Violates the auth-backend contract: the middleware iterates every backend calling
  `authenticate`/`check_credentials`; an IdP-only subclass must stub them to "not me".
- Abstract methods that half the subclasses cannot implement are a smell; ABCs stop being
  useful as contracts.
- Larger blast radius when either role changes.

📊 **Effort:** Medium-High

📦 **Libraries / Tools:** same as Option A.

🔗 **Existing Code to Reuse:** same as Option A.

---

### Option D (unconventional): No IdP role — generalize the relay/bridge instead

Do not issue assertions from Navigator at all. Generalize `ADFS_SAML_RELAY_RP` into an
abstract `SAMLRelayMixin` on `ExternalAuth`: after any successful login, redirect the browser
to the *upstream* IdP's IdP-initiated SSO endpoint for the target SP (ADFS
`IdpInitiatedSignOn.aspx?loginToRp=`, Okta app-embed link, Entra "My Apps" deep link). The
upstream IdP already has the browser session, so it issues the assertion to Verizon Connect.
Keep the SP role as Option A's `AbstractSAMLBackend`.

✅ **Pros:**
- Navigator never holds SAML signing keys; the corporate IdP stays the only assertion issuer
  (often what security teams prefer).
- Works today with ADFS; low effort to abstract.
- No `xmlsec1` needed for the relay itself.

❌ **Cons:**
- Only works when users authenticate to Navigator via an IdP that (a) is also configured as
  Verizon's IdP and (b) offers an IdP-initiated deep link. Local `BasicAuth`, Google, GitHub
  and OAuth2-AS users cannot reach Verizon.
- Not an IdP: Navigator cannot control attributes, NameID, or authorize per SP.
- Contradicts the round-1 decision to support the IdP role.

📊 **Effort:** Low

📦 **Libraries / Tools:** none new.

🔗 **Existing Code to Reuse:**
- `navigator_auth/backends/adfs.py:286-297` — the relay redirect.

---

## Recommendation

**Option A** is recommended because:

- It is the only option that satisfies both discovery decisions — **IdP role** and
  **`pysaml2` engine** — without a second SAML stack (Option B) and without breaking the
  backend contract (Option C).
- `pysaml2` is the single maintained Python implementation of both roles; hand-rolling
  assertion issuing (Option B) is where SAML security bugs concentrate, and reviewing that code
  costs more than adopting `xmlsec1` in the images.
- Two abstract classes keep each ABC honest: every abstract method on `AbstractSAMLBackend`
  is meaningful for every SP subclass, and likewise for the IdP class. The shared `SAMLCore`
  avoids duplicating key/metadata/mapping code.
- The security fixes (single-use `RelayState`, `InResponseTo`, replay cache, host-checked
  redirects, persisted `SessionIndex`) land once in the base and every provider inherits them.

**What we trade off:** a hard `xmlsec1` system dependency, a breaking change for existing
`python3-saml` settings, and the largest implementation effort. Option D remains a cheap
fallback for deployments where the corporate IdP must stay the assertion issuer, and can be
added later as a thin subclass of the IdP class (or a mixin) without reopening this design.

---

## Feature Description

### User-Facing Behavior

**SP role (Navigator consumes a corporate IdP):**
- The login page lists the SAML backend like any other external provider (icon, name from
  `_description`). Clicking it sends the browser to the IdP; after IdP login the browser
  returns to Navigator's ACS and lands on `redirect_uri` (or the default home) with the
  Navigator token, exactly like ADFS/Okta today.
- A user who arrives from the IdP's application portal (IdP-initiated) lands logged in on the
  default home; an unrecognized or replayed assertion lands on the failed-login page with a
  stable `error` code (`SAML_REPLAY`, `SAML_INVALID_SIGNATURE`, `SAML_NOT_AUTHENTICATED`,
  `SAML_USER_NOT_FOUND`, `SAML_FORBIDDEN`).
- Logout from Navigator triggers SP-initiated SLO at the IdP when the session holds a
  `SessionIndex`; an IdP-initiated logout ends the Navigator session and returns a
  `LogoutResponse`.
- Operators fetch `/auth/<svc>/metadata` to register Navigator at the IdP.

**IdP role (Navigator issues assertions to an SP such as Verizon Connect):**
- A logged-in user clicks an "Open <SP>" link (`/auth/saml/idp/initiate/<sp_id>`) and is
  auto-posted into the SP already authenticated. If the SP sends the user to Navigator first
  (SP-initiated), Navigator either has a session and answers immediately, or sends the user
  through the normal Navigator login and then answers.
- A user not authorized for that SP (per `authorize_sp_access`) sees the failed page with
  `SAML_SP_FORBIDDEN`; nothing is posted to the SP.
- Operators fetch `/auth/saml/idp/metadata` (entity ID, SSO/SLO endpoints, signing cert) to
  register Navigator at the SP.

### Internal Behavior

**Shared core (`SAMLCore`):**
- Builds a `pysaml2` configuration from: the subclass's env prefix, the optional JSON settings
  dict, the resolved key/cert files, and the request domain (entity ID and endpoint URLs are
  derived per request from `get_domain`, never cached on the instance, to stay multi-host
  safe).
- Wraps every `pysaml2` call that signs, verifies or parses in the thread executor.
- Provides the attribute mapping (`SAML_MAPPING` shape), attribute flattening (first element
  of multi-valued attributes unless the mapping marks a key as list-valued), and the
  flow-store / replay-cache key helpers (`saml_req_{relay}`, `saml_assertion_{id}`).
- Provides the shared redirect validator (`ALLOWED_HOSTS`).

**SP login (SP-initiated):**
1. `authenticate`: generate a random `RelayState`; build the `AuthnRequest` (binding
   Redirect by default, POST when configured); store `{request_id, internal_redirect,
   acs_url, oauth2_flow?}` in the flow store under the `RelayState` with a 10-minute TTL;
   redirect.
2. `auth_callback` (ACS, POST): read `SAMLResponse` + `RelayState`; `GETDEL` the flow record.
   If found, validate `InResponseTo == request_id`; if not found and the response has no
   `InResponseTo`, treat as **unsolicited** and require the replay cache miss (then set it);
   if not found but the response *has* `InResponseTo`, reject (`SAML_STALE_REQUEST`).
3. Validate signatures, audience, conditions, subject confirmation via `pysaml2`. Flatten
   attributes, call `resolve_user_identifier` then `authorize` (subclass hooks), then
   `build_user_info` → `validate_user_info` (existing user provisioning path, honoring
   `AUTH_MISSING_ACCOUNT`).
4. Store `NameID`, `NameID format`, `SessionIndex`, IdP entity ID in the session under a
   `saml` key. Call `on_assertion` hook. `home_redirect` with the validated
   `internal_redirect`. The existing `_auth_callback_dispatch` wrapper still handles the
   OAuth2-AS resume cookie and identity-link dispatch **but** its `state` lookup must also
   read `RelayState` from POST form data, not only the query string.

**SP logout:** `logout` reads the `saml` session block; if present, builds a `LogoutRequest`
and redirects to the IdP SLO endpoint, storing a flow record keyed by the logout request ID;
otherwise clears the local session. `finish_logout` handles both `LogoutResponse` (complete
local logout) and inbound `LogoutRequest` (IdP-initiated: clear the session matching
`SessionIndex`, reply with `LogoutResponse`).

**IdP role:**
1. `initiate/<sp_id>`: require an authenticated request (normal middleware). Look up the SP
   in `get_service_providers()`; call `authorize_sp_access(user, sp)`; build attributes via
   `build_attributes(user, sp)` and `get_nameid(user, sp)`; create + sign the response with
   `pysaml2`'s `Server.create_authn_response`; render an auto-submit POST form to the SP ACS
   with optional `RelayState` (the SP's own deep link, validated against the SP's declared
   ACS host).
2. `sso`: parse the inbound `AuthnRequest` (Redirect or POST binding), verify the SP is
   registered and the request signature if the SP signs; if no session, store the parsed
   request in the flow store and redirect to Navigator login with a `redirect_uri` back to
   `sso?flow=…`; once authenticated, continue as in step 1 with `InResponseTo` set.
3. Every issued assertion writes an `AuditLog` record: SP entity ID, user ID, assertion ID,
   `NotOnOrAfter`, request IP.
4. `metadata`: IdP metadata with the signing cert, SSO and SLO endpoints for both bindings.

**Registration:** both classes are listed in `AUTHENTICATION_BACKENDS`. The IdP class
implements `check_credentials` and `authenticate` as "not mine" no-ops so the middleware
chain ignores it, and marks its own routes on `AUTH_EXCLUDE_LIST_KEY` only where anonymous
access is required (`metadata`, `sso`, `slo`).

### Edge Cases & Error Handling

- **Clock skew:** configurable tolerance (default 60 s) applied to `NotBefore` /
  `NotOnOrAfter`; failures → `SAML_EXPIRED`.
- **Replay:** assertion ID already in the cache → `SAML_REPLAY`, logged at warning with IdP
  entity ID; cache entry TTL = `NotOnOrAfter` − now (minimum 1 s).
- **Missing `RelayState` on ACS with `InResponseTo` present:** reject; a solicited response
  must carry the relay we issued.
- **`RelayState` pointing off-host:** dropped, default home used (never a failure).
- **Multi-valued attributes** (groups): mapping may declare list-valued keys; otherwise first
  value wins (current behavior preserved).
- **Encrypted assertions:** supported when an SP decryption key is configured; unsupported
  encryption → `SAML_DECRYPT_FAILED`.
- **IdP metadata rotation:** the core reloads IdP metadata from file/URL at startup and on a
  configurable interval; signature verification failure with a stale cert surfaces as
  `SAML_INVALID_SIGNATURE` and logs a hint to refresh metadata.
- **`xmlsec1` missing:** `on_startup` fails fast with a clear error naming the binary and the
  `xmlsec_binary` setting; the backend is not registered half-working.
- **Unknown SP on IdP endpoints:** 404 with `SAML_UNKNOWN_SP`; nothing about registered SPs
  is leaked.
- **SLO partial failure:** local session is always cleared even if the IdP never answers.
- **Executor saturation:** `BaseAuthBackend.executor` has 2 workers; signing under load could
  queue. The core uses its own bounded executor sized by config (default 4).

---

## Capabilities

### New Capabilities
- `saml-core`: shared engine wrapper — config building from env prefix + settings dict,
  key/cert loading, executor-wrapped `pysaml2` calls, attribute mapping, metadata rendering,
  flow-store and replay-cache helpers, host-checked redirect validation.
- `saml-sp-backend`: `AbstractSAMLBackend(ExternalAuth)` with SP-initiated login,
  unsolicited login, SLO, SP metadata, and the provider hooks (`get_idp_metadata`,
  `get_attribute_mapping`, `resolve_user_identifier`, `authorize`, `on_assertion`).
- `saml-idp-provider`: `AbstractSAMLIdentityProvider` with IdP-initiated and SP-initiated
  SSO, IdP metadata, SLO, env-declared SP registry, issued-assertion audit, and the hooks
  (`get_service_providers`, `build_attributes`, `get_nameid`, `authorize_sp_access`).
- `saml-generic-backend`: `SAMLAuth` reimplemented as the reference subclass on
  `saml-sp-backend`, reading `SAML_*` settings.

### Modified Capabilities
- `external-auth-callback-dispatch` (in `external.py`): `_auth_callback_dispatch` must read
  the flow key from POST `RelayState` as well as query `state`, so identity-link and OAuth2-AS
  resume keep working for SAML.
- `adfs-saml-relay` (`ADFS_SAML_RELAY_RP` in `adfs.py`): unchanged now; documented as a
  candidate for reimplementation on top of the IdP class in a follow-up.

---

## Impact & Integration

| Affected Component | Impact Type | Notes |
|---|---|---|
| `navigator_auth/backends/saml.py` | rewritten | Becomes generic `SAMLAuth(AbstractSAMLBackend)`; keeps export name |
| `navigator_auth/backends/saml/` (new pkg) | new | `core.py`, `sp.py`, `idp.py`; `saml.py` may move to `saml/__init__.py` re-exporting |
| `navigator_auth/backends/external.py` | modifies | `_auth_callback_dispatch` reads POST `RelayState`; optional promotion of `_validate_internal_redirect` to the base |
| `navigator_auth/backends/abstract.py` | extends (optional) | Host-checked redirect validator moved here for reuse by ADFS and SAML |
| `navigator_auth/backends/__init__.py` | extends | Export `AbstractSAMLBackend`, `AbstractSAMLIdentityProvider` |
| `navigator_auth/conf.py` | extends | `SAML_IDP_*` settings, SP registry JSON, `SAML_XMLSEC_BINARY`, clock skew, replay TTL; keep `SAML_PATH`/`SAML_SETTINGS`/`SAML_MAPPING` |
| `navigator_auth/identity/flow_store.py` | depends on | Reused as-is for request state and replay cache |
| `navigator_auth/abac/audit.py` | depends on | Issued-assertion audit events |
| `pyproject.toml` | modifies | Remove `python3-saml`, `xmlsec`; add `pysaml2>=7.5,<8`; `lxml` stays (used elsewhere) |
| Docker images / CI | modifies | Install `xmlsec1` system package |
| `docs/settings.rst`, `docs/config.rst` | extends | SAML SP and IdP configuration reference, migration note from python3-saml |
| `tests/` | extends | New `tests/test_saml_sp.py`, `tests/test_saml_idp.py`, fixtures with self-signed keys and fake IdP/SP metadata |
| `navigator_auth/backends/adfs.py` | unchanged | Relay hack remains; follow-up candidate |

**Breaking changes:** `python3-saml` settings layout no longer read; `SAML_SETTINGS` keys are
remapped to `pysaml2` where a 1:1 exists, others rejected at startup with a message.
**Deployment changes:** `xmlsec1` binary required wherever the SAML backend is enabled.

---

## Parallelism Assessment

- **Internal parallelism:** *Moderate.* The natural split is (1) `saml-core` first, then
  (2) `saml-sp-backend` + `saml-generic-backend` and (3) `saml-idp-provider` in parallel,
  since SP and IdP touch different files and only share the core. Tests for each role are
  independent. The `external.py` change is small and belongs with (2).
- **Cross-feature independence:** No in-flight specs (`sdd/tasks/active/` is empty). Shared
  files with recent work: `external.py` (FEAT-095 added `_auth_callback_dispatch` and the
  OAuth2 resume detour) and `conf.py`. Both are merged on `dev`; edits are additive.
- **Recommended isolation:** `mixed` — core in the spec worktree first; SP and IdP tasks may
  run in separate worktrees once the core task is merged.
- **Rationale:** the core defines the config/engine contract both roles depend on, so it must
  land first; after that the two roles are independent enough that a second worker can take
  the IdP role without merge conflicts beyond `__init__.py` exports and `conf.py` additions.

---

## Open Questions

- [ ] Confirm from the Verizon Connect articles (403 to fetch): exact ACS URL, SP Entity ID,
      required `NameID` format (email?), required attributes, and whether they require signed
      assertions, signed responses, or both — *Owner: Jesus Lara*
- [ ] Does Verizon Connect support SP-initiated SSO or only IdP-initiated? Determines whether
      the IdP `sso` endpoint is needed for the first integration or can be a later task —
      *Owner: Jesus Lara*
- [ ] IdP signing key management: PEM files only, or also accept the key from a secret
      manager / env var content? Rotation procedure (dual certs in metadata during rollover)?
      — *Owner: Jesus Lara*
- [ ] Should the IdP role require a specific Navigator auth method or ACR before issuing an
      assertion (e.g. refuse for `NoAuth`/`Troc` token sessions)? — *Owner: Jesus Lara*
- [ ] Executor sizing: shared `BaseAuthBackend.executor` (2 workers) vs a dedicated SAML
      executor; acceptable p95 for signing under load? — *Owner: maintainers*
- [ ] Migration note for existing `SAML_SETTINGS` users: hard fail on unknown keys or
      best-effort with warnings? — *Owner: Jesus Lara*
- [ ] Should the ADFS relay (`ADFS_SAML_RELAY_RP`) be reimplemented on the IdP class in this
      feature or left for a follow-up spec? Brainstorm assumes follow-up. — *Owner: Jesus Lara*
