# Feature Specification: Abstract SAML 2.0 Backend — SP and IdP roles on pysaml2

**Feature ID**: FEAT-097
**Date**: 2026-09-04
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.26.0

> **Input:** `sdd/proposals/saml-backend-abstract.brainstorm.md` (Option A accepted in
> discovery rounds 1–2 on 2026-09-04).
> **Scope reminder:** this feature delivers the *abstract* SAML surface and a generic reference
> subclass. It does **not** deliver a Verizon Connect backend; Verizon Connect (a SAML Service
> Provider) is the first counterpart the IdP role must be able to serve, and is covered by a
> follow-up spec once its ACS/EntityID/NameID details are confirmed (OQ1, OQ2).

---

## 1. Motivation & Business Requirements

### Problem Statement

`navigator-auth` ships a single, concrete SAML backend (`navigator_auth/backends/saml.py`,
`SAMLAuth` on `python3-saml`). It cannot be extended without copy-paste, it only plays the
Service Provider role, and it has security gaps that the OIDC backends have already fixed:

- **Not abstract.** One global `SAML_PATH`/`SAML_SETTINGS`/`SAML_MAPPING`; no defined hooks
  for a second IdP (Okta SAML, Entra ID SAML, a partner IdP).
- **No IdP role.** Verizon Connect and similar SaaS are SAML *Service Providers*: they consume
  a signed bearer assertion from the customer's IdP. For Navigator to "SSO into" them, Navigator
  must issue assertions. Today the only path is the ADFS-specific relay hack
  (`ADFS_SAML_RELAY_RP`, `adfs.py:286-297`), which only works for users who logged in via ADFS.
- **SP security gaps.** No `InResponseTo`/request-ID tracking (`redirect_uri` is dropped,
  `saml.py:71-74`); no replay cache for unsolicited responses; `RelayState` trusted as a
  redirect target with only a self-loop check (`saml.py:119-125`) — the same open-redirect class
  fixed for ADFS in commit `a00875d`; SLO is a stub that never persists `NameID`/`SessionIndex`.
- **Engine limit.** `python3-saml` cannot build or sign assertions or parse `AuthnRequest`;
  the IdP role is impossible on it.

### Goals

- G1. `AbstractSAMLBackend(ExternalAuth)`: an abstract **SP** base implementing SP-initiated
  login, IdP-initiated (unsolicited) login, Single Logout (both directions) and SP metadata,
  with a small, documented set of provider hooks.
- G2. `AbstractSAMLIdentityProvider`: an abstract **IdP** base that issues signed assertions
  for the current Navigator session to env-registered SPs, supporting IdP-initiated and
  SP-initiated SSO, IdP metadata and SLO, with per-SP authorization and attribute hooks.
- G3. `SAMLCore`: one shared engine wrapper (config building, key/cert loading,
  executor-wrapped `pysaml2` calls, attribute mapping, flow-store/replay-cache helpers,
  host-checked redirect validation) used by both bases.
- G4. `SAMLAuth` reimplemented as the generic reference subclass on G1, keeping its export
  name and the `SAML_*` configuration surface where a 1:1 mapping to `pysaml2` exists.
- G5. Security parity with the OIDC backends: single-use random `RelayState`, `InResponseTo`
  validation, assertion-ID replay cache, `ALLOWED_HOSTS`-checked redirects, persisted
  `SessionIndex` for SLO, audit record per issued assertion, XXE-safe parsing.
- G6. Replace `python3-saml` + `xmlsec` (Python binding) with `pysaml2`; document the
  `xmlsec1` binary requirement and the settings migration.

### Non-Goals (explicitly out of scope)

- A concrete Verizon Connect subclass (follow-up spec after OQ1/OQ2).
- Reimplementing `ADFS_SAML_RELAY_RP` on the IdP role (follow-up; `adfs.py` is untouched).
- DB-backed IdP/SP registries or admin UI (decided: env-declared, no migration).
- SAML artifact binding, ECP profile, attribute-query profile, SAML 1.x.
- Encrypted `NameID` issuance from the IdP role (SP-side assertion *decryption* is in scope).
- Secret-manager key loading (PEM files only; OQ3 tracks the follow-up).
- Any change to the ABAC/policy engine; `authorize` hooks are backend-local decisions.

---

## 2. Architectural Design

### Overview

A new package `navigator_auth/backends/saml/` replaces the single `saml.py` module. It holds
three layers: a **core** that owns everything `pysaml2`-specific; an **SP base** that plugs
the core into the existing `ExternalAuth` login/callback/logout/redirect machinery; and an
**IdP base** that plugs the core into the existing session, user model and audit log to issue
assertions. Both bases are process-wide singletons like every other backend; all per-flow data
lives in Redis (`IdentityFlowStore`) or the user session, never on the instance.

The SP base is a normal external auth backend (`_external_auth = True`, listed on the login
page, participates in identity-link and the OAuth2-AS resume detour). The IdP base is loaded
through the same `AUTHENTICATION_BACKENDS` mechanism for lifecycle (`configure`,
`on_startup`, `on_cleanup`) but never authenticates anyone: it defines no `auth_middleware`,
sets `_external_auth = False`, hides itself from the auth-methods listing, and its
`authenticate`/`check_credentials` are inert.

`pysaml2` is synchronous and shells out to `xmlsec1`; every signing, verification and
parsing call runs in a bounded thread executor owned by the core so the event loop is never
blocked.

### Component Diagram

```
                 AUTHENTICATION_BACKENDS (auth.py get_backends)
                          │                          │
        ┌─────────────────┴──────────┐     ┌─────────┴──────────────────┐
        │ AbstractSAMLBackend (SP)   │     │ AbstractSAMLIdentityProvider│
        │  extends ExternalAuth      │     │  (IdP, no auth_middleware)  │
        │  authenticate / acs /      │     │  initiate / sso / slo /     │
        │  logout / slo / metadata   │     │  metadata                   │
        └──────────┬─────────────────┘     └───────────┬─────────────────┘
                   │  hooks: get_idp_metadata,          │ hooks: get_service_providers,
                   │  resolve_user_identifier,          │ build_attributes, get_nameid,
                   │  authorize, on_assertion           │ authorize_sp_access
                   ▼                                    ▼
        ┌───────────────────────────────────────────────────────────────┐
        │ SAMLCore                                                       │
        │  config builder (env prefix + settings dict) · key/cert loader │
        │  executor-wrapped pysaml2 Saml2Client / Server · metadata      │
        │  attribute mapping · redirect validator (ALLOWED_HOSTS)        │
        │  flow-store keys · replay cache · error codes                  │
        └───────┬───────────────────┬───────────────────┬───────────────┘
                │                   │                   │
         pysaml2 + xmlsec1   IdentityFlowStore (Redis)   AuditLog / navigator_session
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `ExternalAuth` (`backends/external.py`) | extends | SP base inherits routes, `on_startup` Redis pool + `IdentityFlowStore`, `build_user_info`, `validate_user_info`, `home_redirect`, `failed_redirect`, `_auth_callback_dispatch`. |
| `ExternalAuth._auth_callback_dispatch` | modifies | Must obtain the flow key from POST form `RelayState` when the callback is a POST, in addition to query `state`; SP base overrides `get_callback_state(request)` and the dispatcher calls it. Small, additive change. |
| `BaseAuthBackend` (`backends/abstract.py`) | extends | `_validate_internal_redirect` (currently `adfs.py:120-135`) promoted to `BaseAuthBackend.validate_redirect_host(uri)`; ADFS keeps its private name delegating to it. |
| `IdentityFlowStore` (`identity/flow_store.py`) | uses | AuthnRequest state (`saml_req_{relay}`), logout state (`saml_slo_{id}`), IdP pending request (`saml_idp_{flow}`), replay cache (`saml_assert_{id}`). |
| `AuditLog` (`abac/audit.py`) | uses | One event per issued assertion and per rejected assertion (replay/signature). |
| `navigator_session` | uses | SP stores `saml` block (`name_id`, `name_id_format`, `session_index`, `idp_entity_id`); IdP reads `request.user` and `AUTH_SESSION_OBJECT`. |
| `AuthHandler.get_backends` / `configure` (`auth.py`) | depends on | IdP class loaded like any backend; excluded from `auth_middleware` chain because it defines none. `get_backend_info` gains a `hidden` flag honored by `api_get_auth_methods`. |
| `conf.py` | extends | New `SAML_*` keys (see §6 Configuration Keys); existing `SAML_PATH`, `SAML_SETTINGS`, `SAML_MAPPING` kept. |
| `backends/__init__.py` | extends | Exports `AbstractSAMLBackend`, `AbstractSAMLIdentityProvider`, `SAMLAuth` (unchanged name). |
| `backends/jwksutils.py` | reuses | Existing SAML-metadata namespace handling for signing-key extraction from IdP metadata. |
| `pyproject.toml` | modifies | `-python3-saml`, `-xmlsec`; `+pysaml2>=7.5,<8`. `lxml` stays. |
| Docker/CI | modifies | `xmlsec1` system package. |
| `adfs.py` | unchanged | Relay hack stays; only the redirect validator is delegated. |

### Data Models

```python
# navigator_auth/backends/saml/types.py — plain dataclasses (no DB)

@dataclass(frozen=True)
class SAMLKeyPair:
    key_file: str            # PEM private key path
    cert_file: str           # PEM certificate path
    passphrase: Optional[str] = None

@dataclass(frozen=True)
class ServiceProviderConfig:
    """One relying SP registered on the IdP role (env-declared)."""
    sp_id: str                       # slug used in /initiate/<sp_id>
    entity_id: str
    acs_url: str
    acs_binding: str = "HTTP-POST"   # only POST supported for ACS
    slo_url: Optional[str] = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    attribute_map: dict[str, str] = field(default_factory=dict)  # saml attr -> user field
    sign_assertion: bool = True
    sign_response: bool = False
    want_signed_authn_request: bool = False
    sp_cert_file: Optional[str] = None   # for AuthnRequest signature check / encryption
    assertion_ttl: int = 300
    allowed_relay_hosts: tuple[str, ...] = ()  # extra RelayState hosts besides acs_url host

@dataclass(frozen=True)
class AssertionResult:
    """Normalized outcome of a validated inbound SAMLResponse (SP role)."""
    name_id: str
    name_id_format: str
    session_index: Optional[str]
    issuer: str
    assertion_id: str
    not_on_or_after: datetime
    attributes: dict[str, Any]       # flattened per mapping
    raw_attributes: dict[str, list]  # as delivered
    in_response_to: Optional[str]
    unsolicited: bool

@dataclass(frozen=True)
class SAMLSessionInfo:
    """Persisted in the user session under key 'saml' for SLO."""
    name_id: str
    name_id_format: str
    session_index: Optional[str]
    idp_entity_id: str
    backend: str                     # _service_name
```

**Session/flow-store records (JSON):**

| Key | Written by | Consumed by | TTL | Payload |
|---|---|---|---|---|
| `saml_req_{relay}` | SP `authenticate` | SP ACS (GETDEL) | `SAML_FLOW_TTL` (600 s) | `request_id`, `internal_redirect`, `acs_url`, `oauth2_flow?` |
| `saml_assert_{assertion_id}` | SP ACS after validation | SP ACS (exists-check) | `NotOnOrAfter − now` (≥1 s) | `issuer`, `consumed_at` |
| `saml_slo_{request_id}` | SP `logout` | SP `finish_logout` (GETDEL) | 600 s | `session_index`, `return_to` |
| `saml_idp_{flow}` | IdP `sso` when no session | IdP `sso?flow=` (GETDEL) | 600 s | parsed `AuthnRequest` essentials: `sp_id`, `request_id`, `acs_url`, `relay_state`, `name_id_policy` |
| session `saml` | SP ACS | SP `logout`, inbound SLO | session lifetime | `SAMLSessionInfo` |

**Audit events** (through `AuditLog`, same shape as existing auth events):
`saml.assertion.issued` (sp_id, entity_id, user_id, assertion_id, not_on_or_after,
in_response_to, remote), `saml.assertion.rejected` (backend, issuer, reason code,
assertion_id?, remote), `saml.sp.forbidden` (sp_id, user_id).

### New Public Interfaces

```python
# navigator_auth/backends/saml/core.py
class SAMLCore:
    def __init__(self, *, prefix: str, settings: Optional[dict], role: Literal["sp", "idp"],
                 logger, executor_workers: int = SAML_EXECUTOR_WORKERS): ...
    def build_config(self, base_url: str) -> dict:
        """pysaml2 config dict for this request's domain (entity_id + endpoints derived)."""
    async def sp_client(self, base_url: str) -> "saml2.client.Saml2Client": ...
    async def idp_server(self, base_url: str) -> "saml2.server.Server": ...
    async def run(self, fn, *args, **kwargs):
        """Run a blocking pysaml2 call in the core's executor."""
    def sp_metadata(self, base_url: str) -> str: ...
    def idp_metadata(self, base_url: str) -> str: ...
    def flatten_attributes(self, attrs: dict[str, list], mapping: dict) -> dict: ...
    def validate_redirect(self, uri: Optional[str], extra_hosts: Iterable[str] = ()) -> Optional[str]: ...
    def load_keypair(self, pair: SAMLKeyPair) -> None: ...
    def check_xmlsec(self) -> None:
        """Raise ConfigError at startup when the xmlsec1 binary is missing."""

# navigator_auth/backends/saml/sp.py
class AbstractSAMLBackend(ExternalAuth, ABC):
    _service_name: str = "saml"
    config_prefix: str = "SAML"          # env prefix resolved through navconfig
    user_mapping: dict = SAML_MAPPING

    # ---- ExternalAuth contract (implemented here, final for subclasses) ----
    async def authenticate(self, request) -> web.Response: ...        # start SP-initiated
    async def auth_callback(self, request) -> web.Response: ...       # ACS (POST)
    async def logout(self, request) -> web.Response: ...              # SP-initiated SLO
    async def finish_logout(self, request) -> web.Response: ...       # LogoutResponse / inbound LogoutRequest
    async def check_credentials(self, request) -> bool: ...
    async def metadata(self, request) -> web.Response: ...
    def get_callback_state(self, request) -> Optional[str]: ...       # RelayState (POST) for dispatcher

    # ---- provider hooks ----
    @abstractmethod
    def get_idp_metadata(self) -> Union[str, dict]:
        """Path/URL to IdP metadata XML, or inline pysaml2 metadata dict."""
    @abstractmethod
    def get_attribute_mapping(self) -> dict: ...
    @abstractmethod
    async def resolve_user_identifier(self, result: AssertionResult) -> str:
        """Return the login identifier used for validate_user_info."""
    async def authorize(self, request, result: AssertionResult, identifier: str) -> bool:
        """Post-validation access decision (default True). False -> SAML_FORBIDDEN."""
    async def on_assertion(self, request, result: AssertionResult, user) -> None:
        """Called after the session is created (default no-op)."""
    def get_settings(self) -> Optional[dict]:
        """Optional pysaml2 overrides (default: <prefix>_SETTINGS JSON)."""

# navigator_auth/backends/saml/idp.py
class AbstractSAMLIdentityProvider(BaseAuthBackend, ABC):
    _service_name: str = "saml-idp"
    _external_auth: bool = False
    config_prefix: str = "SAML_IDP"

    async def initiate(self, request) -> web.Response: ...    # /auth/<svc>/initiate/{sp_id}
    async def sso(self, request) -> web.Response: ...         # /auth/<svc>/sso  (Redirect+POST)
    async def slo(self, request) -> web.Response: ...         # /auth/<svc>/slo
    async def metadata(self, request) -> web.Response: ...    # /auth/<svc>/metadata
    async def issue_assertion(self, request, sp: ServiceProviderConfig, user,
                              in_response_to: Optional[str] = None,
                              relay_state: Optional[str] = None) -> web.Response:
        """Build, sign, audit, and render the auto-POST form to sp.acs_url."""

    # ---- provider hooks ----
    @abstractmethod
    def get_service_providers(self) -> dict[str, ServiceProviderConfig]: ...
    @abstractmethod
    async def build_attributes(self, user, sp: ServiceProviderConfig) -> dict[str, list[str]]: ...
    async def get_nameid(self, user, sp: ServiceProviderConfig) -> str:
        """Default: user.email for emailAddress format, user.username otherwise."""
    async def authorize_sp_access(self, request, user, sp: ServiceProviderConfig) -> bool:
        """Default True. False -> SAML_SP_FORBIDDEN, nothing posted to the SP."""
    def get_keypair(self) -> SAMLKeyPair: ...
    def get_settings(self) -> Optional[dict]: ...

# navigator_auth/backends/saml/__init__.py
class SAMLAuth(AbstractSAMLBackend):
    """Generic reference SP reading SAML_* settings (metadata path/URL, mapping)."""

class SAMLIdentityProvider(AbstractSAMLIdentityProvider):
    """Generic reference IdP reading SAML_IDP_* settings and SAML_IDP_SERVICE_PROVIDERS."""
```

**Routes registered**

| Role | Method | Path | Handler | Excluded from auth |
|---|---|---|---|---|
| SP | `*` | `/api/v1/auth/<svc>/` | `authenticate` | yes (inherited) |
| SP | `GET` | `/auth/<svc>/login` | `authenticate` | yes (inherited) |
| SP | `POST` | `/auth/<svc>/callback/` | `_auth_callback_dispatch` → `auth_callback` | yes |
| SP | `GET` | `/auth/<svc>/metadata` | `metadata` | yes |
| SP | `GET` | `/api/v1/auth/<svc>/logout` | `logout` | no |
| SP | `GET`,`POST` | `/auth/<svc>/logout` | `finish_logout` | yes |
| IdP | `GET` | `/auth/<svc>/initiate/{sp_id}` | `initiate` | no |
| IdP | `GET`,`POST` | `/auth/<svc>/sso` | `sso` | yes (checks session itself) |
| IdP | `GET`,`POST` | `/auth/<svc>/slo` | `slo` | yes |
| IdP | `GET` | `/auth/<svc>/metadata` | `metadata` | yes |

The inherited ExternalAuth callback route is `GET`; the SP base re-registers it as `POST`
(HTTP-POST binding is the only ACS binding supported) and keeps `GET` returning 405 with a
hint.

**Stable error codes** (query `error=` on the failed-redirect page and in audit records):
`SAML_INVALID_RESPONSE`, `SAML_INVALID_SIGNATURE`, `SAML_EXPIRED`, `SAML_REPLAY`,
`SAML_STALE_REQUEST`, `SAML_AUDIENCE_MISMATCH`, `SAML_DECRYPT_FAILED`,
`SAML_NOT_AUTHENTICATED`, `SAML_USER_NOT_FOUND`, `SAML_FORBIDDEN`, `SAML_UNKNOWN_SP`,
`SAML_SP_FORBIDDEN`, `SAML_INVALID_AUTHN_REQUEST`, `SAML_SLO_FAILED`.

---

## 3. Module Breakdown

### Module 1: Dependency swap, configuration keys, redirect validator promotion
- **Path**: `pyproject.toml`, `navigator_auth/conf.py`, `navigator_auth/backends/abstract.py`,
  `navigator_auth/backends/adfs.py` (delegation only), `Dockerfile`/CI config
- **Responsibility**: Replace `python3-saml`/`xmlsec` with `pysaml2`; add `SAML_*` and
  `SAML_IDP_*` keys (§6); add `xmlsec1` to images and CI; move
  `_validate_internal_redirect` into `BaseAuthBackend.validate_redirect_host` with
  `ADFSAuth._validate_internal_redirect` delegating to it (behavior-preserving, existing ADFS
  tests must pass).
- **Depends on**: nothing.

### Module 2: `SAMLCore` and types
- **Path**: `navigator_auth/backends/saml/core.py`, `navigator_auth/backends/saml/types.py`,
  `navigator_auth/backends/saml/errors.py`
- **Responsibility**: Config building from prefix + settings dict + per-request base URL;
  key/cert loading; bounded executor and `run()`; `Saml2Client`/`Server` factories (cached
  per base URL); metadata rendering; attribute flattening with list-valued keys; replay-cache
  and flow-store key helpers; `check_xmlsec()`; error-code constants and `SAMLError`
  hierarchy mapping to the stable codes.
- **Depends on**: Module 1.

### Module 3: `AbstractSAMLBackend` (SP role) — login flows
- **Path**: `navigator_auth/backends/saml/sp.py`, `navigator_auth/backends/external.py`
  (`get_callback_state` hook in `_auth_callback_dispatch`)
- **Responsibility**: `authenticate` (random single-use `RelayState`, flow record,
  `AuthnRequest` via Redirect binding, POST binding when configured); `auth_callback` (ACS:
  GETDEL flow, `InResponseTo` validation, unsolicited path with replay cache, signature/
  audience/conditions validation in executor, `AssertionResult`, hooks, `build_user_info`
  → `validate_user_info`, session `saml` block, `home_redirect` with validated redirect);
  `metadata`; `check_credentials`; hidden-from-dispatcher fix so identity-link and OAuth2-AS
  resume work over a POST callback.
- **Depends on**: Module 2.

### Module 4: `AbstractSAMLBackend` — Single Logout
- **Path**: `navigator_auth/backends/saml/sp.py`
- **Responsibility**: `logout` (SP-initiated `LogoutRequest` when session holds
  `SessionIndex`, flow record, local session always cleared); `finish_logout` handling both
  `LogoutResponse` (complete) and inbound `LogoutRequest` (clear matching session, reply
  `LogoutResponse` via the SP's declared binding). Partial-failure semantics per §2.
- **Depends on**: Module 3.

### Module 5: `AbstractSAMLIdentityProvider` (IdP role)
- **Path**: `navigator_auth/backends/saml/idp.py`, `navigator_auth/auth.py`
  (`hidden` flag in `api_get_auth_methods`)
- **Responsibility**: Env-declared SP registry parsing/validation at startup; `metadata`;
  `initiate/{sp_id}` (session required, `authorize_sp_access`, `build_attributes`,
  `get_nameid`, `issue_assertion`, auto-POST form with validated `RelayState`); `sso`
  (parse `AuthnRequest` for Redirect and POST bindings, optional signature check, unknown-SP
  404, no-session detour via `saml_idp_{flow}` + login redirect + resume, `InResponseTo`
  set); `slo` (SP-initiated logout from an SP: clear local session, respond); audit events;
  inert `authenticate`/`check_credentials`; `_external_auth = False`, `hidden = True`.
- **Depends on**: Module 2. Independent of Modules 3–4.

### Module 6: Generic reference subclasses and legacy settings migration
- **Path**: `navigator_auth/backends/saml/__init__.py`, `navigator_auth/backends/__init__.py`,
  remove `navigator_auth/backends/saml.py`
- **Responsibility**: `SAMLAuth(AbstractSAMLBackend)` reading `SAML_METADATA`
  (path or URL), `SAML_MAPPING`, optional `SAML_SETTINGS`; `SAMLIdentityProvider` reading
  `SAML_IDP_*`; translation of the known `python3-saml` `SAML_SETTINGS` keys (`sp.entityId`,
  `sp.assertionConsumerService.url`, `idp.entityId`, `idp.singleSignOnService.url`,
  `idp.x509cert`, `security.*`) into the `pysaml2` config, with startup rejection of unknown
  keys listing them (OQ6 default: hard fail). Package re-exports so
  `from navigator_auth.backends import SAMLAuth` is unchanged.
- **Depends on**: Modules 3, 4, 5.

### Module 7: Tests, fixtures, documentation
- **Path**: `tests/test_saml_core.py`, `tests/test_saml_sp.py`, `tests/test_saml_slo.py`,
  `tests/test_saml_idp.py`, `tests/test_saml_roundtrip.py`, `tests/fixtures/saml/`,
  `docs/settings.rst`, `docs/config.rst`, `README.md` auth-methods table, `CHANGELOG`
- **Responsibility**: Self-signed test key pairs, fake IdP metadata, fake SP metadata, canned
  signed responses; `xmlsec1` skip-marker when the binary is absent (CI installs it);
  configuration reference for both roles; migration note from `python3-saml`; example
  `AUTHENTICATION_BACKENDS` lines.
- **Depends on**: Modules 1–6 (tests for each module are written alongside it; this module
  closes coverage, the SP↔IdP round-trip test, and docs).

---

## 4. Test Specification

All tests are `pytest` + `pytest-asyncio`, offline, with fixture keys. Tests requiring
`xmlsec1` are marked `@pytest.mark.xmlsec` and skipped with a clear reason when the binary is
missing; CI must install it so they run.

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_core_build_config_sp` | M2 | Config derives entity_id/ACS/SLO URLs from base URL and prefix; no instance mutation between two base URLs |
| `test_core_build_config_idp` | M2 | IdP config includes SSO/SLO endpoints for both bindings and signing cert |
| `test_core_settings_override_precedence` | M2 | settings dict overrides env-derived values, env overrides defaults |
| `test_core_check_xmlsec_missing` | M2 | `ConfigError` names the binary and `SAML_XMLSEC_BINARY` |
| `test_core_flatten_attributes` | M2 | First value by default; list-valued keys preserved; unmapped keys ignored with warning |
| `test_core_validate_redirect` | M2 | Relative kept; allowed host kept; foreign host dropped; extra hosts honored |
| `test_core_run_in_executor` | M2 | Blocking call executes off the loop; executor bounded |
| `test_sp_authenticate_sets_flow` | M3 | Random RelayState; flow record with request_id + internal_redirect; Redirect binding URL well-formed |
| `test_sp_acs_solicited_ok` | M3 | Valid signed response with matching InResponseTo → session, `saml` block, home redirect with validated internal_redirect |
| `test_sp_acs_in_response_to_mismatch` | M3 | InResponseTo ≠ stored request_id → `SAML_INVALID_RESPONSE` |
| `test_sp_acs_stale_request` | M3 | Response with InResponseTo but no flow record → `SAML_STALE_REQUEST` |
| `test_sp_acs_unsolicited_ok_then_replay` | M3 | Unsolicited response accepted once; second identical → `SAML_REPLAY` + audit event |
| `test_sp_acs_bad_signature` | M3 | Tampered assertion → `SAML_INVALID_SIGNATURE` |
| `test_sp_acs_expired_with_skew` | M3 | NotOnOrAfter within skew accepted; beyond → `SAML_EXPIRED` |
| `test_sp_acs_audience_mismatch` | M3 | Wrong audience → `SAML_AUDIENCE_MISMATCH` |
| `test_sp_acs_encrypted_assertion` | M3 | Decrypts with configured key; missing key → `SAML_DECRYPT_FAILED` |
| `test_sp_acs_relaystate_offhost` | M3 | Off-host RelayState dropped, default home used, login still succeeds |
| `test_sp_authorize_hook_denies` | M3 | `authorize` False → `SAML_FORBIDDEN`, no session |
| `test_sp_missing_account_modes` | M3 | `AUTH_MISSING_ACCOUNT=raise` → `SAML_USER_NOT_FOUND`; `create` → user created |
| `test_sp_callback_get_405` | M3 | GET on ACS → 405 |
| `test_sp_dispatch_reads_post_relaystate` | M3 | Identity-link flow record keyed by RelayState found on POST callback |
| `test_sp_metadata_valid` | M3 | SP metadata parses, contains ACS POST endpoint and cert when configured |
| `test_slo_sp_initiated` | M4 | Session with SessionIndex → LogoutRequest redirect + flow record; local session cleared |
| `test_slo_no_session_index` | M4 | Local logout only, no IdP redirect |
| `test_slo_logout_response` | M4 | LogoutResponse consumed via GETDEL; redirect to return_to |
| `test_slo_inbound_logout_request` | M4 | IdP LogoutRequest clears matching session and returns signed LogoutResponse |
| `test_idp_registry_parse_and_validate` | M5 | JSON registry parsed; duplicate sp_id / missing acs_url rejected at startup |
| `test_idp_metadata_valid` | M5 | IdP metadata contains SSO Redirect+POST, SLO, signing cert |
| `test_idp_initiate_ok` | M5 | Authenticated user → auto-POST form to ACS with signed assertion; audit `saml.assertion.issued` |
| `test_idp_initiate_unknown_sp` | M5 | 404 `SAML_UNKNOWN_SP`, no SP details leaked |
| `test_idp_initiate_forbidden` | M5 | `authorize_sp_access` False → `SAML_SP_FORBIDDEN`, audit `saml.sp.forbidden`, nothing rendered |
| `test_idp_initiate_unauthenticated` | M5 | No session → redirected to login (middleware) |
| `test_idp_sso_sp_initiated_with_session` | M5 | AuthnRequest (Redirect binding) parsed; assertion has InResponseTo; RelayState echoed |
| `test_idp_sso_no_session_detour` | M5 | Request parked in `saml_idp_{flow}`; after login `sso?flow=` resumes once (GETDEL) |
| `test_idp_sso_signed_authn_request` | M5 | SP with `want_signed_authn_request`: bad signature → `SAML_INVALID_AUTHN_REQUEST` |
| `test_idp_relaystate_validation` | M5 | RelayState must match ACS host or `allowed_relay_hosts` |
| `test_idp_hidden_from_auth_methods` | M5 | `api_get_auth_methods` omits the IdP backend |
| `test_idp_nameid_default` | M5 | email for emailAddress format, username otherwise |
| `test_generic_samlauth_config` | M6 | `SAML_METADATA` path and URL forms; `SAML_MAPPING` honored |
| `test_legacy_settings_translation` | M6 | Known python3-saml keys mapped; unknown keys → startup `ConfigError` listing them |
| `test_backend_exports` | M6 | `navigator_auth.backends.SAMLAuth` importable; abstract classes exported |

### Integration Tests
| Test | Description |
|---|---|
| `test_saml_roundtrip_sp_initiated` | `SAMLIdentityProvider` and `SAMLAuth` in one aiohttp app: SP `authenticate` → IdP `sso` (session present) → IdP posts to SP ACS → SP session created; `InResponseTo` chain verified end to end |
| `test_saml_roundtrip_idp_initiated` | IdP `initiate` → SP ACS (unsolicited) → session; replay of the same POST rejected |
| `test_saml_roundtrip_slo` | SP-initiated logout reaches IdP `slo`, IdP responds, both sessions cleared |
| `test_saml_oauth2_resume_detour` | Login started by the OAuth2 AS (`nav_oauth2_flow` cookie) through the SAML SP resumes `/oauth2/authorize` after the POST callback (regression for FEAT-095 D2) |
| `test_adfs_redirect_validator_unchanged` | Existing ADFS internal_redirect tests pass after the promotion to the base |

### Test Data / Fixtures
```python
# tests/fixtures/saml/  — generated once, committed:
#   idp.key / idp.crt   (self-signed, 10y, RSA-2048)  -> IdP signing
#   sp.key  / sp.crt                                  -> SP decryption + AuthnRequest signing
#   idp-metadata.xml, sp-metadata.xml                 -> counterpart metadata for each role
#   response-valid.xml.b64, response-tampered.xml.b64, response-encrypted.xml.b64

@pytest.fixture
def saml_keys(tmp_path) -> dict: ...                # paths to the PEM files above

@pytest.fixture
def sp_backend(saml_keys, redis_stub, user_model_stub) -> SAMLAuth:
    """Configured against idp-metadata.xml; flow store backed by an in-memory stub."""

@pytest.fixture
def idp_backend(saml_keys, redis_stub, user_model_stub) -> SAMLIdentityProvider:
    """One registered SP ('acme') whose ACS points at the test app's SP callback."""

@pytest.fixture
async def saml_app(aiohttp_client, sp_backend, idp_backend) -> TestClient:
    """Both backends configured on one aiohttp app for round-trip tests."""

@pytest.fixture
def signed_response(saml_keys):
    """Factory: build a signed SAMLResponse for given (in_response_to, audience, attrs,
    not_on_or_after) using pysaml2 Server, returned base64-encoded for form POST."""
```

The existing `make_request`, tenant and OAuth2 fixtures in `tests/conftest.py` are reused
where request mocks suffice; round-trips use `aiohttp`'s `aiohttp_client`.

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] All new unit and integration tests pass (`pytest tests/test_saml_*.py -v`) with
      `xmlsec1` installed; none are skipped in CI.
- [ ] Full existing suite passes (`pytest tests/ -v`), including ADFS, OAuth2 3LO/MCP and
      identity-link tests, after the `external.py` dispatcher change and the redirect-validator
      promotion.
- [ ] `python3-saml` and `xmlsec` are gone from `pyproject.toml`; `pysaml2>=7.5,<8` present;
      `uv pip install` of the project succeeds in a clean venv.
- [ ] `from navigator_auth.backends import SAMLAuth, AbstractSAMLBackend,
      AbstractSAMLIdentityProvider, SAMLIdentityProvider` works.
- [ ] A subclass of `AbstractSAMLBackend` implementing only `get_idp_metadata`,
      `get_attribute_mapping`, `resolve_user_identifier` runs the full SP-initiated and
      unsolicited login and SLO without overriding anything else (verified by the reference
      subclass and a minimal test subclass).
- [ ] A subclass of `AbstractSAMLIdentityProvider` implementing only `get_service_providers`
      and `build_attributes` serves metadata, IdP-initiated and SP-initiated SSO (verified the
      same way).
- [ ] Every `RelayState` issued by the SP role is random and single-use; every ACS response
      with `InResponseTo` is checked against the stored request ID; every unsolicited response
      is checked against the replay cache; every redirect target derived from `RelayState` or
      `redirect_uri` is host-validated. Each is covered by a named test above.
- [ ] `NameID`, `NameID format`, `SessionIndex` and IdP entity ID are present in the session
      after SP login, and SP-initiated SLO uses them.
- [ ] Every issued assertion produces an audit event; every rejected assertion produces one
      with the stable error code.
- [ ] The IdP backend never authenticates a request, never appears in
      `/api/v1/auth/methods` output, and registers no middleware.
- [ ] No blocking `pysaml2` call executes on the event loop (asserted by a test that patches
      the executor and by review).
- [ ] Startup fails fast with an actionable message when `xmlsec1` is missing, when the IdP
      key pair is unreadable, when the SP registry is invalid, or when legacy `SAML_SETTINGS`
      contains untranslatable keys.
- [ ] `docs/settings.rst` and `docs/config.rst` document both roles' configuration keys, the
      `xmlsec1` requirement, the `AUTHENTICATION_BACKENDS` entries, and the migration from
      `python3-saml`; README auth-methods table updated; CHANGELOG entry marks the breaking
      change.
- [ ] No breaking change to the public API other than the documented `python3-saml`
      settings-layout change (`SAMLAuth` name, routes and `SAML_MAPPING` semantics preserved).
- [ ] Performance: SP ACS validation and IdP assertion issuance each complete in < 150 ms p95
      on the CI runner with the fixture keys, with the default 4-worker executor.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- **Backends are singletons.** Never store per-flow or per-request data on `self`; use
  `IdentityFlowStore` or the session (see `adfs.py:151-153`, `external.py:161-168`).
- **Random single-use state.** Copy the ADFS nonce pattern (`secrets.token_urlsafe(32)`,
  `flow_store.set(..., ttl=600)`, `flow_store.getdel(...)`) for `RelayState` and logout IDs.
- **Per-request domain.** Derive entity ID and endpoint URLs from `get_domain(request)`;
  cache `pysaml2` clients per base URL, not globally.
- **Existing user path.** Always go through `build_user_info` → `validate_user_info` so
  `AUTH_MISSING_ACCOUNT`, success callbacks, `remember()` and token issuance behave exactly
  as for OIDC backends.
- **Redirect helpers.** Use `home_redirect` / `failed_redirect`; never build `HTTPFound`
  with an unvalidated target.
- **Error surfacing.** Map every `SAMLError` to a stable code; never echo raw XML or IdP
  error text into the redirect URL (log it instead).
- **Async discipline.** All `pysaml2` calls through `SAMLCore.run`; `xmlsec1` is a
  subprocess and must not run on the loop thread.
- **Config through `navconfig`** in `conf.py`; JSON blobs parsed with `orjson` and the
  existing `logging.exception` fallback style.
- **Logging** with `self.logger` at debug for flow steps, warning for rejected assertions
  (with issuer and code, never the assertion body), error for configuration problems.
- **Tests offline.** Fixture keys only; no network fetch of metadata in tests (URL form is
  tested with a mocked `ClientSession`).

### Known Risks / Gotchas
- **`xmlsec1` binary dependency.** Missing in slim images → startup failure. Mitigation:
  `check_xmlsec()` at `on_startup`, `SAML_XMLSEC_BINARY` override, Dockerfile/CI updated in
  M1, documented prominently.
- **`pysaml2` config surface is large and its docs are uneven.** Mitigation: `SAMLCore`
  is the only module that touches the config dict; subclasses see prefix/settings/hook
  APIs only; M2 tests pin the produced config.
- **POST callback vs the GET dispatcher.** `_auth_callback_dispatch` today reads `state`
  from the query string; SAML's `RelayState` arrives in the POST body. The
  `get_callback_state` hook keeps identity-link and the OAuth2-AS resume working; the
  regression test `test_saml_oauth2_resume_detour` guards it.
- **Unsolicited responses are inherently CSRF-shaped.** Mitigation: replay cache keyed by
  assertion ID with TTL to `NotOnOrAfter`, strict `NotBefore`/`NotOnOrAfter` with bounded skew,
  audience check, and `SAML_ALLOW_UNSOLICITED` defaulting to `true` only for the SP role
  (operators can disable).
- **Clock skew between IdP and Navigator.** `SAML_CLOCK_SKEW` (default 60 s); documented.
- **Metadata/cert rotation.** IdP metadata reloaded at startup and every
  `SAML_METADATA_RELOAD` seconds (default 3600) in a background task tracked in
  `_background_tasks`; signature failure logs a "refresh metadata" hint. Dual signing certs in
  IdP metadata during rollover are out of scope (OQ3).
- **Executor saturation.** Dedicated bounded executor (`SAML_EXECUTOR_WORKERS`, default 4)
  instead of `BaseAuthBackend.executor` (2 workers shared) — OQ5.
- **Breaking settings change.** Users of `python3-saml` `settings.json` layouts must migrate;
  the translator covers the common keys and fails loudly on the rest (OQ6).
- **FEAT-096 (`external-token-exchange`) also edits `external.py` and `conf.py`.** Both
  changes are additive (new abstract method vs new dispatcher hook; new keys); rebase order
  matters, see Worktree Strategy.

### Configuration Keys (navigator_auth.conf)

| Key | Role | Default | Purpose |
|---|---|---|---|
| `SAML_METADATA` | SP | — | Path or URL to IdP metadata XML (generic `SAMLAuth`) |
| `SAML_SETTINGS` | SP | `None` | Optional JSON overrides (legacy python3-saml keys translated) |
| `SAML_MAPPING` | SP | existing dict | SAML attribute → user field (existing) |
| `SAML_PATH` | SP | `None` | Kept for legacy cert/settings directory lookup |
| `SAML_SP_KEY_FILE` / `SAML_SP_CERT_FILE` | SP | `None` | Optional SP key pair (AuthnRequest signing, assertion decryption) |
| `SAML_BINDING` | SP | `redirect` | AuthnRequest binding: `redirect` or `post` |
| `SAML_ALLOW_UNSOLICITED` | SP | `true` | Accept IdP-initiated responses |
| `SAML_WANT_ASSERTIONS_SIGNED` / `SAML_WANT_RESPONSE_SIGNED` | SP | `true` / `false` | Signature requirements |
| `SAML_IDP_KEY_FILE` / `SAML_IDP_CERT_FILE` / `SAML_IDP_KEY_PASSPHRASE` | IdP | — | Signing key pair (required for IdP) |
| `SAML_IDP_ENTITY_ID` | IdP | `{domain}/auth/saml-idp/metadata` | Override entity ID |
| `SAML_IDP_SERVICE_PROVIDERS` | IdP | `[]` | JSON list of `ServiceProviderConfig` |
| `SAML_IDP_SETTINGS` | IdP | `None` | Optional JSON pysaml2 overrides |
| `SAML_IDP_REQUIRE_AUTH_METHODS` | IdP | `[]` | If set, only sessions whose `auth_method` is listed may receive assertions (OQ4) |
| `SAML_XMLSEC_BINARY` | both | auto-detect | Path to `xmlsec1` |
| `SAML_CLOCK_SKEW` | both | `60` | Seconds of tolerance on conditions |
| `SAML_FLOW_TTL` | both | `600` | Flow-store TTL for request/logout/pending records |
| `SAML_METADATA_RELOAD` | SP | `3600` | Seconds between IdP metadata reloads (`0` disables) |
| `SAML_EXECUTOR_WORKERS` | both | `4` | Bounded executor size for pysaml2 calls |

Subclasses may change `config_prefix` (e.g. `VERIZON_SAML`) and every key above is
resolved under that prefix first, falling back to `SAML_*`.

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| `pysaml2` | `>=7.5,<8` | SAML 2.0 SP + IdP engine, metadata, SLO, encryption; xmlsec 1.3 support since 7.4.2 |
| `xmlsec1` (system) | `>=1.2.37` (1.3.x supported) | XML-DSig used by pysaml2 via subprocess |
| `defusedxml` | (via pysaml2) | XXE-safe parsing |
| `cryptography` | existing | Key loading, cert fingerprints |
| `redis` | existing | `IdentityFlowStore`, replay cache |
| Removed: `python3-saml`, `xmlsec` (Python binding) | — | Replaced by pysaml2 |

---

## 7. Open Questions

> Carried from the brainstorm. None blocks the abstract bases; OQ1–OQ2 block the follow-up
> Verizon subclass only.

- [ ] OQ1. Verizon Connect: exact ACS URL, SP Entity ID, required `NameID` format, required
      attributes, and whether they require signed assertions, signed responses, or both. The
      help articles return 403 to non-browser fetches; confirm in a browser. — *Owner: Jesus Lara*
- [ ] OQ2. Does Verizon Connect support SP-initiated SSO or IdP-initiated only? Only affects
      whether the follow-up subclass needs `sso`. — *Owner: Jesus Lara*
- [ ] OQ3. IdP key management beyond PEM files (secret manager, env-content keys) and
      certificate rollover with dual certs in metadata. Default for this feature: PEM files,
      single cert. — *Owner: Jesus Lara*
- [ ] OQ4. Should the IdP refuse to issue assertions for sessions authenticated by weak or
      service methods (`NoAuth`, `TrocToken`, API keys)? Default: `SAML_IDP_REQUIRE_AUTH_METHODS`
      empty (no restriction), operators opt in. — *Owner: Jesus Lara*
- [ ] OQ5. Executor sizing and p95 target under load. Default: dedicated 4-worker executor,
      150 ms p95 acceptance on CI fixtures. — *Owner: maintainers*
- [ ] OQ6. Legacy `SAML_SETTINGS`: hard fail on unknown keys (default in this spec) vs
      best-effort with warnings. — *Owner: Jesus Lara*
- [ ] OQ7. Reimplement `ADFS_SAML_RELAY_RP` on the IdP role? Default: follow-up spec; `adfs.py`
      untouched here except the redirect-validator delegation. — *Owner: Jesus Lara*

---

## Worktree Strategy

- **Isolation unit:** `mixed`.
  - **Sequential in the feature worktree:** M1 → M2 (foundation), then M3 → M4 (SP role),
    then M6 → M7.
  - **Parallelizable:** **M5 (IdP role)** may run in a second worktree branched after M2 is
    merged. It touches only `backends/saml/idp.py` and one small `auth.py` change (`hidden`
    flag in `api_get_auth_methods`); no contention with M3/M4 (`sp.py`, `external.py`).
    M6 waits for both.
- **Rationale:** the core defines the config/engine contract both roles depend on, so it
  must land first. After that the two roles share only `saml/__init__.py` exports and
  `conf.py` additions, which M1 front-loads to avoid conflicts. Running the FEAT-093/094/095
  OAuth2 suites and the ADFS tests at each module boundary is the regression gate, since M3
  edits `external.py` and M1 edits `abstract.py`.
- **Cross-feature dependencies:** FEAT-095 is merged (all tasks in `sdd/tasks/completed/`).
  **FEAT-096 (`external-token-exchange`, approved, not started)** also edits
  `backends/external.py` (new abstract `verify_external_token`) and `conf.py`. If FEAT-096
  starts first, M3 must rebase onto it and the SP base must implement or inherit a default for
  `verify_external_token`; if this feature starts first, FEAT-096 rebases onto the
  `get_callback_state` hook. Coordinate the order before `/sdd-start` on either.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-09-04 | Jesus Lara | Initial draft from `saml-backend-abstract.brainstorm.md` (Option A: two abstract classes on pysaml2 with shared core; all four flows; env-prefix config; env-declared SP registry; four per-flow state stores). OQ1–OQ7 carried. |
