# Feature Specification: OAuth2 Token Introspection (RFC 7662) + Device Authorization Grant (RFC 8628)

**Feature ID**: FEAT-094
**Date**: 2026-06-22
**Author**: Jesus Lara
**Status**: draft
**Target version**: 1.3.0

> **Inputs:** `sdd/proposals/oauth2-introspection-device-grant.brainstorm.md`
> (Recommended **Option A** — incremental in-place extension, tactically adopting Option D's two
> shortcuts). **Hard prerequisite:** FEAT-093 (`sdd/specs/oauth2-3lo-implementation.spec.md`)
> must be merged first — this feature builds directly on its `client_uid`, `AccessTokenStorage`
> (`jti`), `RefreshTokenStorage` (rotation/reuse), `GrantStorage` (consent-skip), owner-binding,
> and the `OAUTH2_CLIENT_STORAGE` storage factory.

---

## 1. Motivation & Business Requirements

> Why does this feature exist? What problem does it solve?

### Problem Statement

FEAT-093 turns the `navigator-auth` OAuth2 surface (`Oauth2Provider`,
`navigator_auth/backends/oauth2/backend.py`) into a real 3LO server, but deliberately deferred
two RFC surfaces (its Non-Goals §1, lines 61–62) that production deployments expect:

- **Token Introspection (RFC 7662) is missing.** The only token-validation path is each resource
  server decoding the JWT itself (`APIKeyAuth.decode_token`) plus a per-request `jti` revocation
  check. There is **no standard, language-agnostic `POST /oauth2/introspect`** that a third-party
  or non-Python resource server / gateway can call to ask *"is this token active, and what does
  it authorize?"*. Polyglot resource servers therefore cannot participate in revocation, and
  there is no canonical introspection contract.
- **Device Authorization Grant (RFC 8628) is missing.** Input-constrained clients (CLI, IoT,
  smart-TV, headless agents) cannot run a browser redirect flow. Today they are forced into
  `client_credentials` (a *service principal* under FEAT-093, not a real user) or into embedding
  browser flows they cannot host. There is no `device_authorization` → `user_code` →
  poll-`/token` path.

**Who is affected:** resource-server authors and gateway/platform operators (introspection);
CLI/IoT/TV integrators and their end users (device grant).

**Why now:** FEAT-093 establishes precisely the primitives both features need (`client_uid`,
`AccessTokenStorage`+`jti`, `RefreshTokenStorage` with rotation/reuse/`revoke_chain`,
`GrantStorage` for consent-skip, owner-binding, the storage factory). Building these now, on that
foundation, is cheap and consistent; building them before/around it would mean rework.

### Goals

- Implement **RFC 7662** `POST /oauth2/introspect`: caller authenticated as a **confidential
  client** (`client_id`+`client_secret`); supports **access and refresh** tokens; a client may
  only introspect tokens **issued to itself**; returns `200 {"active": false}` (and nothing else)
  for any invalid/expired/revoked/foreign token; revocation truth read **real-time** from
  `AccessTokenStorage`/`RefreshTokenStorage` (no cache — this endpoint *is* the authority).
- Implement **RFC 8628** device flow: `POST /oauth2/device_authorization` (issues
  `device_code`/`user_code`/`verification_uri`/`verification_uri_complete`/`expires_in`/`interval`),
  a `/oauth2/device` verification surface (login + consent), and the
  `urn:ietf:params:oauth:grant-type:device_code` polling branch on `/oauth2/token`.
- Preserve **owner-binding**: device-issued tokens bind to the user who authenticated and
  consented at `verification_uri`, with the same `user_id` discipline as the auth-code flow —
  **never** `client.user`.
- Device flow goes through **full login + consent** (reusing `GrantStorage` consent-skip) and
  issues a refresh token **only if `offline_access`** was granted (consistent with FEAT-093 D5).
- **Anti-brute-force device hardening:** RFC defaults (`device_code` TTL 600s, `interval` 5s,
  `slow_down`), human-legible `user_code` from an unambiguous alphabet, and rate-limit + lockout
  on `user_code` entry.
- Add one new storage (`DeviceCodeStorage`) following the existing ABC + memory/redis/postgres
  factory pattern. **No new runtime dependency** (stdlib `secrets`/`hashlib`/`hmac`/`uuid`).

### Non-Goals (explicitly out of scope)

- OpenID Connect, DPoP/mTLS, Dynamic Client Registration, Token Exchange, CIBA (still deferred).
- Re-litigating FEAT-093 mechanics (owner-binding, PKCE, rotation, ABAC composition) — consumed
  as-is.
- A bearer-token (service-token) auth mode for `/introspect` beyond client_credentials, unless
  Open Question OQ1 is resolved to add it.
- Surfacing FEAT-093 ABAC *effective* scopes in introspection responses, unless OQ5 resolves to
  include them (default: strict RFC 7662 claims only).
- `POST /oauth2/revoke` (RFC 7009) — already owned by FEAT-093 Module 5.

---

## 2. Architectural Design

### Overview

Recommended **Option A** (brainstorm): extend `Oauth2Provider` in place with the two endpoints,
adding **one** new storage (`DeviceCodeStorage`), and tactically adopt **Option D's two
shortcuts** to minimize new flow code:

- **D-1 — Introspection as a thin read path.** Authenticate the caller (reuse FEAT-093's
  confidential-client check) → `IdentityProvider.decode_token` → for access tokens, real-time
  `jti` check via `AccessTokenStorage`; for refresh tokens, `RefreshTokenStorage` lookup
  (rotated/revoked ⇒ inactive) → enforce caller `client_uid` == token `client_id` → project
  RFC 7662 claims or `{"active": false}`. No new validation engine.
- **D-2 — Device token issuance reuses the auth-code path.** On user approval at
  `verification_uri`, mint an internal **owner-bound `OauthAuthorizationCode`** carrier keyed by
  the `device_code`; the polling `device_code` token request **delegates to the existing
  `authorization_code` exchange verbatim** (single-use, owner-binding, refresh-iff-`offline_access`,
  rotation). A dedicated `DeviceCodeStorage`/`OauthDeviceCode` still holds the *pending/polling*
  state (`user_code`, `interval`, `slow_down`, lockout) that auth-code has no equivalent for.

This mirrors FEAT-093's own Option A (incremental, stdlib-only, isolate pure helpers) and keeps
the two new surfaces consistent with the code they depend on.

### Component Diagram

```
  ┌──────────────── Token Introspection (RFC 7662) ────────────────┐
  Resource Server ─(client_id+client_secret)─▶ POST /oauth2/introspect
                                                     │
                       authenticate confidential client (FEAT-093 check)
                                                     │
                                IdentityProvider.decode_token(token)
                                       │                       │
                            access token                 refresh token
                                       │                       │
                       AccessTokenStorage.is_revoked(jti)  RefreshTokenStorage.get_token
                                       │                       │ (rotated/revoked? ⇒ inactive)
                                       ▼                       ▼
                       caller.client_uid == token.client_id ?  ── no ─▶ {"active": false}
                                       │ yes
                                       ▼
                       {"active": true, scope, client_id(uid), username, exp, iat, sub, aud, token_type}


  ┌──────────────── Device Authorization Grant (RFC 8628) ─────────┐
  Device(CLI/IoT/TV) ─▶ POST /oauth2/device_authorization (client_id, scope)
        │                         │
        │            DeviceCodeStorage.save(OauthDeviceCode{status=pending, scopes, expires_at, interval})
        │                         ▼
        │   { device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval }
        │
   show user_code + URL/QR ──▶ User (2nd device) ─▶ GET/POST /oauth2/device  (rate-limit/lockout)
        │                                                   │
        │                                  reuse /oauth2/login  +  /oauth2/consent (GrantStorage skip)
        │                                                   ▼
        │                          DeviceCodeStorage: status=approved, user_id, granted_scopes
        │                          (+ mint internal owner-bound OauthAuthorizationCode carrier)  ← D-2
        ▼
   poll: POST /oauth2/token (grant_type=device_code, device_code, client_id)
        │
        ├─ too soon ───────────────▶ slow_down  (bump interval, update last_polled_at)
        ├─ status=pending ─────────▶ authorization_pending
        ├─ status=denied ──────────▶ access_denied
        ├─ expired ────────────────▶ expired_token
        └─ status=approved ────────▶ delegate to authorization_code exchange  ← D-2
                                      (owner-bound access JWT + refresh iff offline_access),
                                      mark device_code consumed (single-use)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `Oauth2Provider` (`backends/oauth2/backend.py`) | modifies | New routes in `configure()` (`/oauth2/introspect`, `/oauth2/device_authorization`, `/oauth2/device`); new `device_code` branch in `token_request`; reuse `consent`/`auth_login`/`get_payload`/`auth_error`/`prepare_url`; add the three excluded paths to `AUTH_EXCLUDE_LIST_KEY` as appropriate |
| `oauth2/models.py` | modifies | New `OauthDeviceCode` (Pydantic v2); reuse `OauthAccessTokenRecord`/`OauthRefreshToken`/`OauthGrant`/`OauthAuthorizationCode` (the latter as the D-2 carrier) |
| `oauth2/code_backend.py` | extends | New `DeviceCodeStorage` ABC + memory/redis/postgres tiers; register in the `get_token_storages(backend)` factory (FEAT-093) |
| `IdentityProvider` (`backends/idp/__init__.py`) | depends on | `decode_token` (introspection); `create_token` 4-tuple with `jti`/`audience` (device issuance, via the reused auth-code path) — **no signature change** |
| `ClientStorage` trio (`oauth2/client_backend.py`) | depends on | `get_client(client_uid)` for caller + device-client resolution; confidential-client secret check |
| `AccessTokenStorage` / `RefreshTokenStorage` (`oauth2/code_backend.py`) | depends on | Introspection active/inactive truth; device refresh issuance via reused path |
| `GrantStorage` (`oauth2/code_backend.py`) | depends on | Consent-skip during device verification |
| `Client` model (`navigator_auth/models.py`) + `oauth2/ddl.sql` | extends | New `auth.oauth_device_codes` table |
| `conf.py` | extends | New `OAUTH_DEVICE_*` keys + optional introspection toggles |
| `examples/oauth2_server.py` | modifies | Demonstrate device flow + introspection with the test client |
| `documentation/oauth.md` | modifies | Document `/introspect` + device grant |

### Data Models

```python
# oauth2/models.py — new model (Pydantic v2). Reuses FEAT-093 conventions.

class DeviceCodeStatus(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    DENIED   = "denied"
    CONSUMED = "consumed"          # single-use guard after successful token issuance

class OauthDeviceCode(BaseModel):
    device_code: str                       # high-entropy opaque (secrets.token_urlsafe)
    user_code: str                         # short, human-legible (unambiguous alphabet)
    client_id: str                         # public client_uid (FEAT-093)
    client_pk: Optional[int] = None        # internal surrogate PK (FK target on the DB row)
    scopes: list[str] = []                 # requested, filtered to client allow-list
    status: DeviceCodeStatus = DeviceCodeStatus.PENDING
    user_id: Optional[int] = None          # set ONLY at approval, from the authenticated session
    granted_scopes: list[str] = []         # set at approval (consent result)
    auth_code: Optional[str] = None        # D-2: internal owner-bound auth-code carrier ref
    interval: int = 5                      # current required poll interval (seconds)
    last_polled_at: Optional[datetime] = None
    issued_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime                   # issued_at + OAUTH_DEVICE_CODE_TTL
```

### New Public Interfaces

```python
# oauth2/code_backend.py — storage ABC + factory registration (mirror ClientStorage/GrantStorage)
class DeviceCodeStorage(ABC):
    async def save(self, dc: OauthDeviceCode) -> bool: ...
    async def get_by_device_code(self, device_code: str) -> Optional[OauthDeviceCode]: ...
    async def get_by_user_code(self, user_code: str) -> Optional[OauthDeviceCode]: ...
    async def update(self, dc: OauthDeviceCode) -> bool: ...          # status/user_id/interval/poll
    async def delete(self, device_code: str) -> bool: ...

# get_token_storages(backend) extended to also return a DeviceCodeStorage (memory/redis/postgres)

# oauth2/devicecode.py — pure, unit-testable helpers (no server/redis/db)
def generate_user_code(length: int, alphabet: str) -> str: ...        # secrets-based
def poll_decision(dc: OauthDeviceCode, now: datetime) -> str: ...     # 'slow_down'|'authorization_pending'|'access_denied'|'expired_token'|'approved'

# New endpoints on Oauth2Provider
#   POST /oauth2/introspect                 (RFC 7662; confidential-client auth; same-client-only)
#   POST /oauth2/device_authorization       (RFC 8628 §3.1/§3.2)
#   GET/POST /oauth2/device                 (RFC 8628 §3.3 verification: user_code entry → login → consent)
#   POST /oauth2/token (grant_type=urn:ietf:params:oauth:grant-type:device_code)  (RFC 8628 §3.4/§3.5)
```

---

## 3. Module Breakdown

> Modules are dependency-ordered. M1 is foundational; introspection (M2) is independent and
> low-risk (do first); the device grant (M3→M5) builds the model/storage then the two flow halves.

### Module 1: Device storage + model + pure helpers (foundational)
- **Path**: `oauth2/models.py`, `oauth2/code_backend.py`, `oauth2/devicecode.py`, `oauth2/ddl.sql`,
  `navigator_auth/models.py`
- **Responsibility**: Add `OauthDeviceCode` + `DeviceCodeStatus`. Add `DeviceCodeStorage` ABC with
  memory/redis/postgres tiers; register in `get_token_storages`. Add pure helpers
  `generate_user_code` (unambiguous alphabet `BCDFGHJKLMNPQRSTVWXZ`, configurable length) and
  `poll_decision` (interval/slow_down/status/expiry state machine). DDL: `auth.oauth_device_codes`
  (`device_code` unique, `user_code` unique, `client_id INTEGER` FK→PK, `user_id`, `scopes` JSONB,
  `status`, `interval`, `last_polled_at`, `issued_at`, `expires_at`).
- **Depends on**: FEAT-093 (storage factory, `client_uid`/`client_pk`, models conventions).

### Module 2: Token Introspection endpoint (RFC 7662)
- **Path**: `oauth2/backend.py`, `conf.py`
- **Responsibility**: `POST /oauth2/introspect` route in `configure()` (+ exclude-list). Authenticate
  caller as a confidential client (reuse FEAT-093 secret check); `400 invalid_request` on
  missing/duplicate `token`; `401 invalid_client` (`WWW-Authenticate`) on bad creds. Decode via
  `decode_token`; branch by token type using `token_type_hint` then fallback. Access: real-time
  `AccessTokenStorage.is_revoked(jti)`. Refresh: `RefreshTokenStorage.get_token` (rotated/revoked
  ⇒ inactive). Enforce caller `client_uid` == token `client_id`; otherwise `{"active": false}`.
  Project RFC 7662 claims for active tokens; `200 {"active": false}` for everything else; never log
  the raw token; constant-time secret comparison.
- **Depends on**: FEAT-093 (`AccessTokenStorage`, `RefreshTokenStorage`, `client_uid`,
  confidential-client check, `decode_token`).

### Module 3: Device authorization request endpoint (RFC 8628 §3.1–§3.2)
- **Path**: `oauth2/backend.py`, `conf.py`
- **Responsibility**: `POST /oauth2/device_authorization` (+ exclude-list). Validate `client_id`
  (resolve `client_uid`); filter `scope` to the client allow-list (`invalid_scope` on unknown).
  Generate `device_code` (`secrets.token_urlsafe`) and `user_code` (M1 helper, regenerate on
  collision). Persist a `pending` `OauthDeviceCode` (TTL from `OAUTH_DEVICE_CODE_TTL`). Return the
  RFC 8628 payload: `device_code`, `user_code`, `verification_uri` (`OAUTH_DEVICE_VERIFICATION_URI`
  or derived), `verification_uri_complete` (`?user_code=…`), `expires_in`, `interval`.
- **Depends on**: Module 1.

### Module 4: Device verification surface (RFC 8628 §3.3)
- **Path**: `oauth2/backend.py`
- **Responsibility**: `GET/POST /oauth2/device` accepts/normalizes `user_code` (case-insensitive,
  hyphen-stripped) under rate-limit + lockout (anti-brute-force; generic error on bad/locked).
  Require an authenticated session (reuse `/oauth2/login`); reuse `/oauth2/consent` with
  `GrantStorage` consent-skip. On approval: stamp the device record `status=approved`, `user_id`
  (from session — owner-binding), `granted_scopes`; **D-2:** mint an internal owner-bound
  `OauthAuthorizationCode` carrier and store its ref on `auth_code`. On denial: `status=denied`.
- **Depends on**: Modules 1, 3.

### Module 5: Device token polling branch (RFC 8628 §3.4–§3.5)
- **Path**: `oauth2/backend.py`
- **Responsibility**: Add the `grant_type=urn:ietf:params:oauth:grant-type:device_code` branch to
  `token_request`. Resolve `device_code`; enforce client match. Run the M1 `poll_decision` state
  machine: too-soon ⇒ `slow_down` (bump interval, update `last_polled_at`); `pending` ⇒
  `authorization_pending`; `denied` ⇒ `access_denied`; expired/unknown ⇒ `expired_token`;
  `approved` ⇒ **delegate to the existing `authorization_code` exchange** via the stored
  `auth_code` carrier (owner-bound token + refresh iff `offline_access`), then mark the
  device_code `consumed` (single-use). Standard OAuth error envelopes throughout.
- **Depends on**: Modules 1, 3, 4.

### Module 6: Tests, docs, example
- **Path**: `tests/`, `documentation/oauth.md`, `examples/oauth2_server.py`
- **Responsibility**: Full async pytest suite (§4). Update docs for `/introspect` + device grant.
  Update the example server to register a public device client + a confidential introspection
  client and demonstrate both flows.
- **Depends on**: all.

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_user_code_alphabet_entropy` | M1 | `generate_user_code` uses the unambiguous alphabet, configured length, no vowels/look-alikes |
| `test_poll_decision_state_machine` | M1 | pure helper returns slow_down/pending/denied/expired/approved correctly across `now`/`interval` |
| `test_device_storage_roundtrip` | M1 | save/get_by_device_code/get_by_user_code/update/delete across memory tier |
| `test_introspect_active_access_token` | M2 | valid access token (own client) ⇒ `active:true` + RFC 7662 claims |
| `test_introspect_revoked_jti_inactive` | M2 | revoked `jti` ⇒ `{"active": false}` (real-time, no cache) |
| `test_introspect_refresh_token` | M2 | active refresh ⇒ active; rotated/reuse-revoked ⇒ inactive |
| `test_introspect_foreign_client_inactive` | M2 | token issued to client B introspected by client A ⇒ `{"active": false}` |
| `test_introspect_requires_client_auth` | M2 | unauthenticated/bad secret ⇒ `401 invalid_client`; missing token ⇒ `400 invalid_request` |
| `test_device_authorization_response` | M3 | returns device_code/user_code/verification_uri(_complete)/expires_in/interval; scope filtered |
| `test_device_invalid_scope` | M3 | scope outside client allow-list ⇒ `invalid_scope` |
| `test_device_user_code_lockout` | M4 | repeated bad `user_code` entries ⇒ rate-limit + lockout, generic error |
| `test_device_approval_binds_user` | M4 | approval stamps `user_id` from session (never `client.user`) + `granted_scopes` |
| `test_device_consent_skip_with_grant` | M4 | existing unrevoked `OauthGrant` covering scopes skips consent |
| `test_device_poll_slow_down` | M5 | polling faster than `interval` ⇒ `slow_down` + interval bump |
| `test_device_poll_pending_denied_expired` | M5 | status/expiry map to `authorization_pending`/`access_denied`/`expired_token` |
| `test_device_poll_success_single_use` | M5 | approved ⇒ owner-bound token; second poll ⇒ rejected (consumed) |
| `test_device_no_offline_access_no_refresh` | M5 | `offline_access` absent ⇒ access-only, no refresh (FEAT-093 D5) |

### Integration Tests
| Test | Description |
|---|---|
| `test_full_device_flow` | device_authorization → user login+consent at `/oauth2/device` → poll → owner-bound access (+refresh on offline_access) → introspect=active |
| `test_device_user_id_survives` | **Owner-binding regression** — issued token `user_id` is the approving user, not `client.user`, and persists across refresh rotation |
| `test_introspect_reflects_revocation` | revoke token (FEAT-093 `/oauth2/revoke`) ⇒ `/introspect` immediately reports `{"active": false}` |
| `test_device_then_revoke_grant_cascade` | DELETE grant (FEAT-093) ⇒ device-issued refresh chain + access `jti` revoked ⇒ introspect inactive |

### Test Data / Fixtures
```python
@pytest.fixture
def memory_oauth_storages(monkeypatch):
    # OAUTH2_CLIENT_STORAGE=memory ⇒ Memory client/code/refresh/grant/jti + DeviceCode stores
    ...

@pytest.fixture
def public_device_client():     # client_type='public', device grant allowed, offline_access in default_scopes
    ...

@pytest.fixture
def confidential_introspect_client():   # client_secret set; the resource-server caller
    ...
# Reuse FEAT-093 conftest fixtures (storages factory, owner-bound token helpers).
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `POST /oauth2/introspect` requires confidential-client auth; missing/duplicate token ⇒
      `400 invalid_request`; bad creds ⇒ `401 invalid_client`.
- [ ] Introspection supports access **and** refresh tokens; a client can only introspect tokens
      issued to itself; foreign/invalid/expired/revoked ⇒ `200 {"active": false}` (no leakage).
- [ ] Introspection revocation truth is **real-time** (`AccessTokenStorage`/`RefreshTokenStorage`,
      no cache); a revoked token reports inactive immediately.
- [ ] Active introspection responses carry RFC 7662 claims (`scope`, `client_id`=`client_uid`,
      `username`, `token_type`, `exp`, `iat`, `sub`, `aud`).
- [ ] `POST /oauth2/device_authorization` returns RFC 8628 fields including
      `verification_uri_complete`; requested scope filtered to the client allow-list
      (`invalid_scope` on unknown).
- [ ] `user_code` uses the unambiguous alphabet; `/oauth2/device` entry is rate-limited + lockable
      (anti-brute-force); `device_code` is single-use.
- [ ] Device verification reuses existing login + consent (with `GrantStorage` consent-skip);
      approval binds `user_id` from the **authenticated session** (never `client.user`).
- [ ] Device polling implements `authorization_pending` / `slow_down` (interval bump) /
      `access_denied` / `expired_token` per RFC 8628 §3.5.
- [ ] Approved device polling issues an **owner-bound** access token (refresh **iff**
      `offline_access`) by delegating to the existing `authorization_code` exchange (D-2).
- [ ] No new runtime dependency; constant-time comparisons for `device_code`/`user_code`/secret;
      no secrets logged.
- [ ] All unit + integration tests pass (`pytest tests/ -v`); `documentation/oauth.md` and
      `examples/oauth2_server.py` updated.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- Extend FEAT-093's storage ABCs and the `get_token_storages` factory honoring
  `OAUTH2_CLIENT_STORAGE`; add memory/redis/postgres tiers for `DeviceCodeStorage` (tests use
  `memory`, device codes are short-TTL so redis is a natural default).
- Pydantic v2 (`model_dump`/`model_validate`); asyncdb `Model`/`Column` with
  `class Meta: schema = "auth"`.
- Isolate `generate_user_code` and `poll_decision` as **pure functions** in `oauth2/devicecode.py`
  for unit testing without a server/redis/db (mirrors FEAT-093's PKCE/rotation helper discipline).
- Keep the IdP `create_token` **4-tuple** signature stable; device issuance goes through the
  existing auth-code exchange, so it inherits `jti`/`audience`/`expires_in` handling unchanged.
- Async-first; `self.logger`; `uv` + active venv for any commands.

### Known Risks / Gotchas
- **D-2 indirection** ("approved device_code carries an internal auth-code") must be documented
  with a focused docstring + the `test_device_poll_success_single_use` test; the carrier auth-code
  has no `redirect_uri` (slightly leaky) — guard the exchange so device-origin codes don't require
  one.
- **Three meanings of `client_id`** persist (FEAT-093): internal PK (int, FK target), public
  `client_uid` (wire/claim/introspection response), FEAT-092 tenant `client_id` (int). Keep the
  device tables FK'd on the integer PK; emit `client_uid` on the wire.
- **`device_code` vs `user_code` indexing:** both must be uniquely looked up — index both columns;
  regenerate on the (rare) `user_code` collision.
- **Introspection privacy (RFC 7662 §4):** never differentiate *why* a token is inactive; same
  `{"active": false}` for expired, revoked, unknown, and foreign-client.
- **Polling storms:** enforce `interval` server-side via `last_polled_at`; `slow_down` must
  *increase* the required interval, not just warn.
- **FEAT-093 ordering:** this spec assumes FEAT-093 is merged. If introspection storages or the
  factory differ from the FEAT-093 spec at merge time, reconcile in Module 1 before proceeding.

### Configuration Keys (navigator_auth.conf)
| Setting | Default | Meaning |
|---|---|---|
| `OAUTH_DEVICE_CODE_TTL` | `600` | device_code lifetime (s) |
| `OAUTH_DEVICE_POLL_INTERVAL` | `5` | initial poll interval returned to the device (s) |
| `OAUTH_DEVICE_SLOW_DOWN_INCREMENT` | `5` | interval bump applied on `slow_down` (s) |
| `OAUTH_DEVICE_USER_CODE_LENGTH` | `8` | user_code length (excl. formatting hyphen) |
| `OAUTH_DEVICE_USER_CODE_ALPHABET` | `BCDFGHJKLMNPQRSTVWXZ` | unambiguous user_code alphabet |
| `OAUTH_DEVICE_VERIFICATION_URI` | *(derived)* | verification page URL (else derived from request host + `/oauth2/device`) |
| `OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS` | `5` | bad-entry attempts before lockout |
| `OAUTH_DEVICE_LOCKOUT_TTL` | `300` | lockout duration after too many attempts (s) |
| `OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES` | `False` | (OQ5) include FEAT-093 effective ABAC scopes in responses |

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| *(none new)* | — | `secrets`/`hashlib`/`hmac`/`uuid` stdlib; persistence via existing `asyncdb`/`redis`; JWT via existing `pyjwt`. `verification_uri_complete` QR is rendered client-side (a returned string) |

---

## 7. Open Questions

> Carried from the brainstorm; none block starting Module 1/2. Resolve M3–M5 questions before
> those modules.

- [ ] **OQ1** — Should `/introspect` also accept a **bearer** service token (scope `introspect`)
      in addition to client_credentials? Round-1 chose client_credentials; confirm whether a
      bearer fallback is needed. — *Owner: Jesus Lara*
- [ ] **OQ2** — Device verification UI: a **dedicated `/oauth2/device` page** (user_code entry +
      confirm) vs redirect into the existing consent UI with `user_code` pre-filled via
      `verification_uri_complete`? — *Owner: Jesus Lara*
- [ ] **OQ3** — Exact rate-limit/lockout policy and where counters live (Redis vs in-process);
      defaults proposed in §6 (`5` attempts / `300s`). — *Owner: Jesus Lara*
- [ ] **OQ4** — Does the device grant **require PKCE** for public clients (RFC 8628 permits it;
      FEAT-093 mandates S256 on auth-code)? Mirroring it adds rigor at some client-complexity
      cost. — *Owner: Jesus Lara*
- [ ] **OQ5** — Should introspection include FEAT-093 **effective ABAC scopes**, or stay strict
      RFC 7662 (`OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES=False` default)? — *Owner: Jesus Lara*

---

## Worktree Strategy

- **Isolation unit:** `per-spec` (all tasks sequential in one worktree).
- **Rationale:** Both features edit the same hot files (`backend.py` `configure()` + `token_request`,
  `code_backend.py` storage factory, `models.py`, `ddl.sql`, `conf.py`); parallel worktrees would
  collide on route registration and the storage factory, costing more in merge contention than
  they save. Sequence introspection first (M2 — smaller, read-only, low risk) then the device
  grant (M1→M3→M4→M5), committing per module and running the full suite at each boundary; the
  `test_device_user_id_survives` owner-binding regression gates correctness.
- **Cross-feature dependencies:** **FEAT-093 must be merged first** (hard prerequisite — supplies
  `client_uid`/`client_pk`, `AccessTokenStorage`+`jti`, `RefreshTokenStorage`,
  `GrantStorage`/consent-skip, owner-binding, the storage factory, and `/oauth2/revoke` for the
  cascade test). FEAT-092 (per-tenant scoping) is merged and untouched here except for respecting
  the distinct meanings of `client_id`.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-06-22 | Jesus Lara | Initial draft from brainstorm (Option A + Option D shortcuts); FEAT-093 hard prerequisite; 5 open questions carried |
