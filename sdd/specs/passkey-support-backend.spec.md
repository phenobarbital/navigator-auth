---
type: feature
base_branch: dev
projects: [navigator-auth]
tags: [passkey, webauthn, fido2, passwordless, basic-auth, multi-tenant, abac]
---

# Feature Specification: Passkey (WebAuthn) Authentication Backend

**Feature ID**: FEAT-101
**Date**: 2026-10-02
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.29.0
**Source**: `sdd/proposals/passkey-support-backend.proposal.md` (research state `sdd/state/FEAT-101/`), built on the brainstorm `sdd/proposals/Passkey (WebAuthn) Authentication Backend.md`.

---

## 1. Motivation & Business Requirements

### Problem Statement

Every first-party login today ends in one of two places:

- a shared secret, which `BasicAuth.validate_user` checks through `IdentityProvider.check_password`;
- a redirect to an external IdP.

No first-party credential resists phishing. A user who is already authenticated should be able to enroll one or more WebAuthn passkeys, then sign in with a passkey alone. That login must return the same payload as `BasicAuth` (`token`, `refresh_token`, `expires_in`, `token_type`, user data, session cookie) and must work for each tenant's own site.

### Goals

- **G1. New backend.** A `PasskeyAuth` backend that deployments enable through `AUTHENTICATION_BACKENDS`. Login verification goes through the existing `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth`, and `auth.py` is not changed.
- **G2. Per-tenant relying parties.** The RP is resolved from the request `Origin` against a configured allow-list map. Each entry carries the tenant `(org_id, client_id)`, which goes into the session for ABAC.
- **G3. Username-first login is the default.** The response for an unknown user does not reveal that it is unknown (E5). Usernameless login with conditional UI stays supported.
- **G4. Opaque user handle.** Each user gets a random handle per `(user, RP)`; the WebAuthn `user.id` never contains PII or the internal user id (E15).
- **G5. Passkey counts as MFA.** A passkey login with user verification satisfies MFA. It adds `mfa` and `amr` to the session and JWT, and ABAC sees `auth_method` and `mfa` as first-class `EvalContext` keys.
- **G6. Disabled accounts are rejected.** `BasicAuth.open_session` rejects users whose `is_active` is false. This applies to every login built on `open_session`: Basic, TokenExchange and Passkey.
- **G7. Phased delivery.** P0 covers config, storage and the RP resolver. P1 covers enrollment and sign-in. P2 covers credential management and the OAuth2 login-page integration.

### Non-Goals (explicitly out of scope)

- Attestation verification and authenticator allow-listing. Attestation is always requested as `"none"`.
- MFA step-up flows, and recent re-authentication before enrollment. In v1 any live session can enroll.
- Account recovery. Password and external backends remain the recovery path.
- Self-service sign-up with a passkey.
- Changes to `AuthHandler.api_login`, `navigator_session`, or the OAuth2 token, authorize and consent endpoints.
- Related Origin Requests (one passkey usable across several registrable domains). Each RP entry stands alone (E14).
- Disabling a credential or notifying the user when its sign counter goes backwards (Q4: reject and log only).
- `is_active` enforcement in `Oauth2Provider.auth_login`. That path uses `IdentityProvider.authenticate_credentials`, not `open_session`; see §8 Q-F1.

---

## 2. Architectural Design

### Overview

`PasskeyAuth` subclasses `BasicAuth`, the same way `TokenExchangeAuth` does (`exchange.py:31`). It verifies a WebAuthn assertion, then calls `self.open_session(request, user, extra=...)`. That one call provides session creation, the 4-tuple JWT, recording of the token's `jti` for revocation (FEAT-098), the refresh token, `BASIC_USER_MAPPING` and the success callbacks. The backend adds only what is passkey-specific:

1. **RP resolution (`navigator_auth/passkey/rp.py`).** `PASSKEY_RELYING_PARTIES` maps an exact origin (`https://app.tenant-a.com`) to `{rp_id, rp_name, org_id, client_id}`.
   - Every ceremony endpoint resolves the RP from the request's `Origin` header.
   - It never uses `Host`, `request.url` or `X-Forwarded-*` (E3; the service runs behind an ALB).
   - An unknown or missing `Origin` returns 401.
   - The resolved RP is stored in the challenge state, and verification uses only the stored RP's origin and `rp_id`.
2. **Challenge state.** Challenges live in Redis under `passkey_{kind}_{key}` with `SETEX` and `PASSKEY_CHALLENGE_TTL` (default 300 s). They are consumed with `GETDEL` (production runs Redis ≥ 6.2), so each one is single-use (E1), and a missing key returns 401 "ceremony expired" (E2). The Redis connection pool is created and torn down like the one in `AzureAuth`.
3. **Storage (`navigator_auth/passkey/store.py` + `sql/`).** `PasskeyStore` follows the `IdentityStore` precedent and works over `app["authdb"]`.
   - **Tables.** Two, in `AUTH_DB_SCHEMA`: `user_credentials` (one row per passkey, carrying `rp_id`) and `user_passkey_handles` (one random handle per `(user_id, rp_id)`).
   - **Migration.** The DDL is an idempotent SQL file. `PasskeyAuth.on_startup` runs it through a non-raising wrapper modeled on `setup_identity_columns`, so the tables are created only when the backend is enabled.
4. **Enrollment (C3).** Both `register/*` endpoints check `request.get("authenticated")`; without a session they return 401 (E12). Because these are cookie-session POSTs, the existing CSRF middleware applies and the client must send `X-CSRF-Token`.
   - The registration options carry the user's random handle as `user.id` (E15). They also carry `excludeCredentials` scoped to the resolved RP (E10), `residentKey=required`, `attestation="none"` and `userVerification=PASSKEY_USER_VERIFICATION`.
5. **Sign-in (C4).** `POST login/options` starts the ceremony.
   - **Username-first (body `{username}`).** For a known user, `allowCredentials` lists that user's credentials for the RP, and the challenge state records `expected_user_id`. For an unknown user, or a known user with no credentials for this RP, the response is shaped the same way: one decoy credential id derived from `HMAC(SECRET_KEY, rp_id + "\x00" + username.casefold())` (E5).
   - **Usernameless (empty body).** `allowCredentials` is empty, which allows conditional UI.
   - **Verification.** `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth` and `{challenge_id, credential}` reaches `PasskeyAuth.authenticate`. It runs these steps:
     1. `get_payload` fails fast with no I/O (E11).
     2. Pop the challenge.
     3. Load the credential by `credential_id` and require that its `rp_id` matches the RP in the challenge state (E4).
     4. If the challenge recorded `expected_user_id`, the credential must belong to that user.
     5. If the assertion carries `userHandle`, it must equal the stored handle.
     6. Call `verify_authentication_response`. A sign count of 0 on both sides is accepted (E6); a counter that goes backwards is rejected and logged (E7). With `PASSKEY_USER_VERIFICATION=required`, an assertion without the UV flag is rejected (E8).
     7. Update `sign_count`, `backed_up` and `last_used_at`.
     8. Load the user with `self._idp.user_from_id`.
     9. Run the optional tenant membership check (see below).
     10. Call `open_session(request, user, extra={...})`, which rejects a disabled user (E9).
   - **Tenant membership check.** This runs only when `PASSKEY_TENANT_ATTRIBUTE` is set. If the user record has that attribute and its value differs from the RP's `org_id`, the login gets 401. A missing setting or a missing attribute skips the check (§8 Q-T).
   - **Uniform failures.** Every verification failure returns the same 401 "Passkey: invalid credential", so the response never reveals which credentials exist (E4).
6. **Session `extra`.** The keys are `auth_method="passkey"`, `mfa=<UV flag>`, `amr=["hwk", "user"]` (or `["hwk"]` without UV), `org_id` and `client_id` from the RP, and `passkey_rp_id`. `open_session` already merges `extra` into `AUTH_SESSION_OBJECT`, so `EvalContext` sees `org_id` and `client_id` through `_resolve_tenant` step 3. `BasicAuth._JWT_EXTRA_KEYS` gains `mfa` and `amr`, so both also reach the JWT.
7. **ABAC.** `EvalContext.__init__` adds `store["auth_method"]` and `store["mfa"]`, read from `userinfo` (defaults `None` and `False`), so policies can require a phishing-resistant login (Q5).
8. **`is_active` (G6).** `BasicAuth.open_session` checks the user's `is_active` before `remember()`.
   - **Field missing.** When the field is absent (custom `AUTH_USER_VIEW`), the user is treated as active.
   - **Field false.** It raises `FailedAuth("User account is disabled", status=403)`.
   - **Propagation.** `BasicAuth.authenticate` must let `FailedAuth` and `InvalidAuth` propagate from `open_session` instead of turning them into `False`.
9. **Credential management (C5, P2).**
   - `GET /api/v1/auth/passkey/credentials` lists the caller's credentials.
   - `PATCH .../credentials/{id}` renames the label.
   - `DELETE .../credentials/{id}` removes a credential. Deleting the last one is allowed only when the user has a password set or at least one linked external identity (`IdentityStore.list_for_user`); otherwise it returns 409 (E13).
10. **OAuth2 login page (C6, P2).**
    - **Template.** `templates/oauth/login.html` asks for the username first, then offers "Sign in with a passkey". It also offers conditional UI (`autocomplete="username webauthn"`).
    - **Flow.** The inline script calls `login/options` and then `navigator.credentials.get`. It posts to `/api/v1/login` with `X-Auth-Method: PasskeyAuth`; the session cookie is set on that response. It then navigates to `/oauth2/authorize`, carrying the hidden authorize parameters already on the page.
    - **What stays the same.** No new server route is needed, and `auth_login`'s password POST is unchanged.
    - **Risk.** It is not yet verified that the session `"user"` blob written by `remember()` decodes through `Oauth2Provider._decode_session_user` (§7 R5).

### Component Diagram

```
Browser ──POST /api/v1/auth/passkey/login/options──▶ PasskeyAuth.login_options
   │                                                   ├─ RelyingPartyResolver.resolve(Origin)
   │                                                   ├─ PasskeyStore (allowCredentials / decoy)
   │                                                   └─ Redis SETEX passkey_login_<challenge_id>
   │
   └─POST /api/v1/login (X-Auth-Method: PasskeyAuth)─▶ AuthHandler.api_login (unchanged)
                                                        └─ PasskeyAuth.authenticate
                                                            ├─ Redis GETDEL (single use)
                                                            ├─ PasskeyStore.get_credential / handle
                                                            ├─ webauthn.verify_authentication_response
                                                            ├─ IdentityProvider.user_from_id
                                                            └─ BasicAuth.open_session (is_active, JWT, jti, callbacks)
                                                        └─ session storage load_session (cookie)

Session user ──POST register/options|verify (CSRF)──▶ PasskeyAuth.register_* ─▶ PasskeyStore.save_credential
ABAC request ─▶ EvalContext(userinfo) ─▶ store["auth_method"], store["mfa"], org_id/client_id
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `BasicAuth` (`backends/basic.py:43`) | extends | `PasskeyAuth(BasicAuth)`. Reuses `open_session`, `on_startup` (`access_token_storage`) and `configure`. |
| `BasicAuth.open_session` (`basic.py:171`) | modifies | Adds the `is_active` check. `_JWT_EXTRA_KEYS` (`:154`) gains `mfa` and `amr`. |
| `BasicAuth.authenticate` (`basic.py:292`) | modifies | Lets `FailedAuth`/`InvalidAuth` raised by `open_session` propagate. |
| `IdentityProvider.user_from_id` (`idp/__init__.py:124`) | uses | Loads the user after verification. |
| `AuthHandler.api_login` / `get_auth_backend` (`auth.py:470`, `:343`) | uses (unchanged) | Header-selected backend. The fallback loop requires a fast `InvalidAuth`. |
| `AuthHandler.auth_startup` (`auth.py:174`) | uses (unchanged) | Calls `backend.on_startup(app)`, where the passkey migration runs. |
| `app[AUTH_EXCLUDE_LIST_KEY]` (`conf.py:47`) | uses | `login/options` is public. |
| `csrf_middleware` (`middlewares/csrf.py`) | constraint | Enrollment and management POST/PATCH/DELETE requests need `X-CSRF-Token`. |
| `IdentityStore` / `identity/migrations.py` | pattern | Store class plus idempotent startup SQL. |
| `IdentityStore.list_for_user` (`identity/store.py:199`) | uses | E13: the "has another login method" check. |
| `EvalContext` (`abac/context.py:81`) | modifies | Adds the `auth_method` and `mfa` keys. |
| `templates/oauth/login.html` | modifies | Passkey button, username-first flow, conditional UI. |
| `pyproject.toml` `[project.optional-dependencies]` (`:60`) | modifies | New extra `passkey = ["webauthn>=2.0,<3"]`. |

### Data Models

```sql
-- navigator_auth/passkey/sql/001_passkey_credentials.sql
-- {schema} is replaced with AUTH_DB_SCHEMA by the migration runner.
CREATE TABLE IF NOT EXISTS {schema}.user_passkey_handles (
    user_id      integer NOT NULL REFERENCES {schema}.users(user_id) ON DELETE CASCADE,
    rp_id        varchar(253) NOT NULL,
    user_handle  bytea NOT NULL UNIQUE,          -- 32 random bytes (secrets.token_bytes)
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, rp_id)
);

CREATE TABLE IF NOT EXISTS {schema}.user_credentials (
    credential_id  bytea PRIMARY KEY,
    user_id        integer NOT NULL REFERENCES {schema}.users(user_id) ON DELETE CASCADE,
    rp_id          varchar(253) NOT NULL,
    public_key     bytea NOT NULL,                -- COSE key from py_webauthn
    sign_count     bigint NOT NULL DEFAULT 0,
    transports     text[],
    aaguid         uuid,
    device_type    varchar(32),                   -- single_device | multi_device
    backed_up      boolean NOT NULL DEFAULT false,
    label          varchar(128),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX IF NOT EXISTS user_credentials_user_rp_idx
    ON {schema}.user_credentials (user_id, rp_id);
```

The users table name comes from `AUTH_USERS_TABLE` (`conf.py:33`, default `users`). The runner substitutes both `{schema}` and `{users_table}`; the DDL above shows `users` for readability.

```python
# navigator_auth/passkey/types.py
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class RelyingParty(BaseModel):
    """One allow-listed WebAuthn relying party (one tenant site)."""
    origin: str = Field(..., description="Exact origin, e.g. https://app.tenant-a.com")
    rp_id: str = Field(..., description="Registrable domain, e.g. tenant-a.com")
    rp_name: str = "Navigator"
    org_id: Optional[int] = None
    client_id: Optional[int] = None


class StoredCredential(BaseModel):
    """A row of {schema}.user_credentials."""
    credential_id: bytes
    user_id: int
    rp_id: str
    public_key: bytes
    sign_count: int = 0
    transports: Optional[list[str]] = None
    aaguid: Optional[str] = None
    device_type: Optional[str] = None
    backed_up: bool = False
    label: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class ChallengeState(BaseModel):
    """Redis payload for a pending ceremony."""
    challenge: str                       # base64url
    rp_id: str
    origin: str
    expected_user_id: Optional[int] = None   # username-first, known user
    decoy: bool = False                      # username-first, unknown user
```

The project rules require Pydantic for data structures. The repo's existing persisted models use `asyncdb`/`datamodel` (`models.py`). The DB row mapping in `PasskeyStore` can use raw SQL through `app["authdb"]` and return the Pydantic `StoredCredential`, so no new `asyncdb` `Model` is needed.

### New Public Interfaces

```python
# navigator_auth/backends/passkey.py
class PasskeyAuth(BasicAuth):
    _description: str = "Passkey (WebAuthn) authentication"
    _service_name: str = "passkey"
    async def login_options(self, request: web.Request) -> web.Response: ...
    async def register_options(self, request: web.Request) -> web.Response: ...
    async def register_verify(self, request: web.Request) -> web.Response: ...
    async def list_credentials(self, request: web.Request) -> web.Response: ...      # P2
    async def rename_credential(self, request: web.Request) -> web.Response: ...     # P2
    async def delete_credential(self, request: web.Request) -> web.Response: ...     # P2
    async def authenticate(self, request: web.Request) -> dict: ...
```

| Method and path | Auth | Request | Response |
|---|---|---|---|
| `POST /api/v1/auth/passkey/register/options` | Session + CSRF | `{}` | `PublicKeyCredentialCreationOptions` JSON |
| `POST /api/v1/auth/passkey/register/verify` | Session + CSRF | `{credential, label?}` | 201 `{"status": "registered", "id": <b64url>}` |
| `POST /api/v1/auth/passkey/login/options` | Public | `{username?}` | `{challenge_id, publicKey}` |
| `POST /api/v1/login` + `X-Auth-Method: PasskeyAuth` | Public | `{challenge_id, credential}` | `BasicAuth` body plus `auth_method: "passkey"`, `mfa`, `amr`; session cookie |
| `GET /api/v1/auth/passkey/credentials` (P2) | Session | — | `[{id, label, created_at, last_used_at, device_type, backed_up, rp_id}]` |
| `PATCH /api/v1/auth/passkey/credentials/{id}` (P2) | Session + CSRF | `{label}` | 200 |
| `DELETE /api/v1/auth/passkey/credentials/{id}` (P2) | Session + CSRF | — | 204, or 409 (E13) |

---

## 3. Module Breakdown

### Module 1: Configuration & packaging (C1) — P0
- **Path**: `navigator_auth/conf.py`, `pyproject.toml`
- **Responsibility**: Adds the `PASSKEY_*` settings and the optional `passkey` extra.
- **Depends on**: —
- **Interface Skeleton**:
```python
# navigator_auth/conf.py — appended near other backend settings
# PASSKEY_RELYING_PARTIES: JSON list, e.g.
#   [{"origin": "https://app.a.com", "rp_id": "a.com", "rp_name": "A", "org_id": 5, "client_id": 1}]
PASSKEY_RELYING_PARTIES: list[dict]          # parsed with orjson; [] when unset or invalid (logged)
PASSKEY_CHALLENGE_TTL: int                   # config.getint(..., fallback=300)
PASSKEY_USER_VERIFICATION: str               # "required" (default) | "preferred"
PASSKEY_TENANT_ATTRIBUTE: Optional[str]      # e.g. "org_id"; None disables the membership check
PASSKEY_DECOY_CREDENTIALS: int               # fallback=1; decoys for unknown users (E5)
```
```toml
# pyproject.toml [project.optional-dependencies]   verified: pyproject.toml:60
passkey = ["webauthn>=2.0,<3"]
```

### Module 2: Passkey storage & migration (C2) — P0
- **Path**: `navigator_auth/passkey/__init__.py`, `types.py`, `store.py`, `migrations.py`, `sql/001_passkey_credentials.sql`
- **Responsibility**: Provides the DDL, the idempotent startup migration, credential and handle CRUD, and the Pydantic types.
- **Depends on**: Module 1
- **Interface Skeleton**:
```python
# navigator_auth/passkey/migrations.py   pattern: identity/migrations.py (setup_identity_columns)
async def ensure_passkey_tables(db_pool: Any) -> None:
    """Run sql/00N_*.sql in order, substituting {schema}/{users_table}. Idempotent."""

async def setup_passkey_tables(db_pool: Any) -> None:
    """Non-raising startup wrapper: logs errors, never raises."""

# navigator_auth/passkey/store.py   pattern: identity/store.py:52 IdentityStore(db_pool, cipher=None)
class PasskeyStore:
    """CRUD over {schema}.user_credentials and {schema}.user_passkey_handles."""
    def __init__(self, db_pool: Any) -> None: ...
    async def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]: ...
    async def list_credentials(self, user_id: int, rp_id: Optional[str] = None) -> list[StoredCredential]: ...
    async def save_credential(self, credential: StoredCredential) -> None: ...
    async def update_usage(self, credential_id: bytes, *, sign_count: int, backed_up: bool) -> None:
        """Set sign_count, backed_up, last_used_at = now()."""
    async def rename_credential(self, user_id: int, credential_id: bytes, label: str) -> bool: ...
    async def delete_credential(self, user_id: int, credential_id: bytes) -> bool: ...
    async def count_credentials(self, user_id: int) -> int: ...
    async def get_or_create_handle(self, user_id: int, rp_id: str) -> bytes:
        """Return the user's handle for rp_id, creating secrets.token_bytes(32) if absent."""
    async def get_handle(self, user_id: int, rp_id: str) -> Optional[bytes]: ...
```

### Module 3: Relying-party resolver — P0
- **Path**: `navigator_auth/passkey/rp.py`
- **Responsibility**: Maps the request `Origin` to an allow-listed `RelyingParty` (E3, G2).
- **Depends on**: Module 1, Module 2 (types)
- **Interface Skeleton**:
```python
class RelyingPartyResolver:
    """Exact-match Origin → RelyingParty allow-list. Never reads Host / X-Forwarded-*."""
    def __init__(self, parties: list[dict]) -> None:
        """Validate entries into RelyingParty; raise ConfigError if empty or invalid."""   # ConfigError verified: exceptions.py:26
    def resolve(self, request: web.Request) -> RelyingParty:
        """Return the RP for request.headers["Origin"]; raise InvalidAuth(status=401) if absent/unknown."""
    def by_rp_id(self, rp_id: str) -> Optional[RelyingParty]: ...
```

### Module 4: `BasicAuth.open_session` hardening (G5, G6) — P1, serial before Module 5
- **Path**: `navigator_auth/backends/basic.py`
- **Responsibility**: Rejects inactive users, adds `mfa` and `amr` to `_JWT_EXTRA_KEYS`, and lets `FailedAuth`/`InvalidAuth` propagate out of `authenticate`.
- **Depends on**: —
- **Interface Skeleton**:
```python
class BasicAuth(BaseAuthBackend):                                   # verified: basic.py:43
    _JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at",
                       "mfa", "amr")                                 # verified: basic.py:154 (extended)

    def _is_active(self, user) -> bool:
        """True unless the user record carries is_active == False (missing field ⇒ active)."""

    async def open_session(self, request, user, extra=None, expiration=None) -> dict:  # verified: basic.py:171
        """...existing docstring... Raises FailedAuth(status=403) when the user is inactive (before remember())."""

    async def authenticate(self, request):                           # verified: basic.py:292
        """...; FailedAuth/InvalidAuth from open_session now propagate (were swallowed into False)."""
```

### Module 5: `PasskeyAuth` backend — enrollment & sign-in (C3, C4) — P1
- **Path**: `navigator_auth/backends/passkey.py`, `navigator_auth/backends/__init__.py`
- **Responsibility**: Route registration, startup (Redis pool and migration), ceremonies, username-first logic with decoys, the tenant check and the session `extra`. `PasskeyAuth` is exported from `navigator_auth.backends` behind a lazy import (it raises `ConfigError` on startup when the extra is missing).
- **Depends on**: Modules 1–4
- **Interface Skeleton**:
```python
from .basic import BasicAuth                                         # verified: backends/__init__.py:6

class PasskeyUser(AuthUser):                                         # AuthUser verified: identities.py
    """User authenticated with a WebAuthn passkey."""

class PasskeyAuth(BasicAuth):
    _ident: AuthUser = PasskeyUser
    _description: str = "Passkey (WebAuthn) authentication"
    _service_name: str = "passkey"

    def configure(self, app: web.Application) -> None:
        """Register routes under /api/v1/auth/passkey/; append login/options to
        app[AUTH_EXCLUDE_LIST_KEY]; build RelyingPartyResolver (ConfigError if empty);
        call super().configure(app)."""                              # verified: basic.py:52, conf.py:47

    async def on_startup(self, app: web.Application) -> None:
        """super().on_startup(app) (keeps access_token_storage + callbacks); import webauthn
        (ConfigError if missing); open Redis pool from REDIS_AUTH_URL; build PasskeyStore;
        await setup_passkey_tables(app["authdb"])."""                # verified: basic.py:64, azure.py:111

    async def on_cleanup(self, app: web.Application) -> None:
        """Disconnect the Redis pool, then super().on_cleanup(app)."""

    async def _save_challenge(self, kind: str, key: str, state: ChallengeState) -> None: ...
    async def _pop_challenge(self, kind: str, key: str) -> ChallengeState:
        """GETDEL; missing ⇒ InvalidAuth('Passkey: ceremony expired', status=401)."""
    def _decoy_ids(self, rp: RelyingParty, username: str) -> list[bytes]:
        """HMAC-SHA256(SECRET_KEY, rp_id + '\\x00' + username.casefold()) derived ids (E5)."""
    def _session_user(self, request: web.Request):
        """request.get('authenticated') else Unauthorized; returns request.user."""   # verified: auth.py:454-461

    async def register_options(self, request: web.Request) -> web.Response: ...
    async def register_verify(self, request: web.Request) -> web.Response: ...
    async def login_options(self, request: web.Request) -> web.Response: ...

    async def get_payload(self, request: web.Request) -> tuple[str, dict]:
        """(challenge_id, credential); InvalidAuth(401) with no I/O when absent (E11)."""
    async def authenticate(self, request: web.Request) -> dict:
        """Verify assertion, then return await self.open_session(request, user, extra=...)."""

    def _check_tenant(self, user, rp: RelyingParty) -> None:
        """When PASSKEY_TENANT_ATTRIBUTE is set and present on user, require == rp.org_id."""
```

### Module 6: ABAC `EvalContext` exposure (Q5) — P1
- **Path**: `navigator_auth/abac/context.py`
- **Responsibility**: Exposes `auth_method` and `mfa` as first-class keys.
- **Depends on**: —
- **Interface Skeleton**:
```python
class EvalContext(dict, MutableMapping):                             # verified: abac/context.py:81
    def __init__(self, request, user, userinfo, session, *args, org_id=None, client_id=None, **kwargs):
        """...after store['userinfo'] (context.py:124):
        store['auth_method'] = userinfo.get('auth_method') if dict, else getattr(..., None)
        store['mfa'] = bool(userinfo.get('mfa', False)) likewise."""
```

### Module 7: Credential management endpoints (C5) — P2
- **Path**: `navigator_auth/backends/passkey.py`
- **Responsibility**: List, rename and delete endpoints, with the E13 rule.
- **Depends on**: Module 5
- **Interface Skeleton**:
```python
    async def list_credentials(self, request: web.Request) -> web.Response: ...
    async def rename_credential(self, request: web.Request) -> web.Response: ...
    async def delete_credential(self, request: web.Request) -> web.Response:
        """409 when it is the last credential and the user has no password and no
        linked identity (IdentityStore.list_for_user)."""            # verified: identity/store.py:199
    async def _has_other_login_method(self, user_id: int) -> bool: ...
```

### Module 8: OAuth2 login page integration (C6) — P2
- **Path**: `templates/oauth/login.html`
- **Responsibility**: Username-first passkey button, conditional UI, CSRF-free public login calls, and a hop to `/oauth2/authorize` that carries the hidden authorize parameters. `PasskeyAuth` shows up in `auth_methods` with no change.
- **Depends on**: Module 5
- **Interface Skeleton**: The template adds an `<input name="username" autocomplete="username webauthn">`, a `#passkey-signin` button, and an inline script, `passkeySignIn(username?)`. The script:
  1. calls `POST /api/v1/auth/passkey/login/options`;
  2. runs `PublicKeyCredential.parseRequestOptionsFromJSON` and then `navigator.credentials.get`;
  3. posts to `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth`;
  4. on success, sets `location` to `/oauth2/authorize?<hidden params>`.

  The existing hidden inputs are at `templates/oauth/login.html:29-37`.

### Module 9: Tests & docs — spans P0–P2
- **Path**: `tests/test_passkey_*.py`, `tests/fixtures/passkey.py`, `docs/` (backend page)
- **Responsibility**: A software-authenticator fixture (ES256 key, hand-built `authenticatorData` and `clientDataJSON`), unit tests, live tests that mirror `tests/test_basic_open_session.py`, and an operator doc for `PASSKEY_*`.
- **Depends on**: Modules 1–8 (per phase)

### Delegation-eligible modules

| Module | Eligible | Decided patterns / exact contracts |
|---|---|---|
| 1 Config & packaging | yes | Names and defaults as in the skeleton; `orjson` parsing like `USER_MAPPING` (`conf.py:311-319`). |
| 2 Storage & migration | yes | DDL in §2; runner copies `identity/migrations.py`; method set fixed in the skeleton. |
| 3 RP resolver | yes | Exact-match on `Origin`; 401 `InvalidAuth` on miss; `ConfigError` on an empty map. |
| 4 `open_session` hardening | yes | `FailedAuth(status=403)`; missing field ⇒ active; extended `_JWT_EXTRA_KEYS`. |
| 5 `PasskeyAuth` | no | Ceremony ordering, decoy behaviour and error uniformity are security-sensitive; review closely. |
| 6 EvalContext | yes | Two keys and their defaults. |
| 7 Management | yes | E13 rule as specified. |
| 8 Login page | yes | JS flow as specified. |
| 9 Tests | partly | The software-authenticator fixture needs care; the per-case tests are mechanical. |

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_conf_passkey_defaults` | 1 | The TTL is 300, UV is `required`, the RP map is empty when unset, and invalid JSON is logged and yields `[]`. |
| `test_rp_resolver_exact_origin` | 3 | A known `Origin` maps to its RP. Unknown, missing or `null` origins raise 401. `Host` and `X-Forwarded-Host` are ignored. |
| `test_rp_resolver_empty_config` | 3 | An empty map raises `ConfigError`. |
| `test_open_session_rejects_inactive` | 4 | `is_active=False` raises `FailedAuth` with status 403, and no session is created. |
| `test_open_session_missing_is_active_is_active` | 4 | A user record without the field logs in. |
| `test_open_session_jwt_mfa_amr` | 4 | `extra` with `mfa` and `amr` lands in the JWT payload. |
| `test_basic_authenticate_propagates_failedauth` | 4 | `BasicAuth.authenticate` re-raises the inactive-user `FailedAuth` instead of returning `False`. |
| `test_eval_context_auth_method_mfa` | 6 | The keys are present, with defaults `None` and `False`. |
| `test_get_payload_fast_fail` | 5 | A body without an assertion raises `InvalidAuth` with no Redis or DB access (E11). |
| `test_decoy_ids_deterministic` | 5 | The same RP and username give the same ids, and different RPs give different ids. |

### Integration Tests (live Postgres + Redis, mirroring `tests/test_basic_open_session.py`)

| Test | Description |
|---|---|
| `test_migration_idempotent` | `ensure_passkey_tables` run twice succeeds. |
| `test_store_crud` | Credential insert, get, list by user and RP, `update_usage`, rename and delete; handle get-or-create is stable and unique (C2). |
| `test_register_requires_session` | Both `register/*` endpoints return 401 without a session (E12), and 403 without a CSRF header when CSRF is enabled. |
| `test_register_roundtrip` | Options include the random handle (not `user_id`) and `excludeCredentials`; verify stores the credential with `rp_id` and returns 201 (C3, E10, E15). |
| `test_login_usernameless_success` | Full ceremony: the response has the `BasicAuth` shape plus `auth_method="passkey"`, `mfa=true`, a refresh token and the session cookie (C4). |
| `test_login_username_first_known` | `allowCredentials` holds the user's ids; a credential from another user is rejected with 401. |
| `test_login_username_first_unknown_shape` | Known-without-credentials and unknown users get the same response shape; assertions against them fail with 401 (E5). |
| `test_challenge_replay` | A second verify with the same `challenge_id` returns 401 (E1). |
| `test_challenge_expired` | With the TTL elapsed, the response is 401 "ceremony expired" (E2). |
| `test_origin_mismatch` | Wrong origin in `clientDataJSON`, or a credential whose `rp_id` differs from the RP in the challenge, returns 401 (E3). |
| `test_unknown_credential_uniform_401` | The body and status match a bad signature (E4). |
| `test_sign_count_zero_accepted` | 0/0 is accepted (E6). |
| `test_sign_count_regression_rejected_logged` | Stored 5, new 3: 401 plus a warning log; the credential is still usable afterwards (E7, Q4). |
| `test_uv_required` | An assertion without the UV flag returns 401 under `required` (E8). |
| `test_inactive_user_rejected` | A valid assertion for a disabled user returns 403 (E9, G6). |
| `test_user_handle_mismatch` | A `userHandle` that differs from the stored handle returns 401. |
| `test_tenant_attribute_check` | With `PASSKEY_TENANT_ATTRIBUTE` set and a mismatched org, the login returns 401; with it unset, the login succeeds. |
| `test_session_carries_tenant` | The session `AUTH_SESSION_OBJECT` holds the RP's `org_id`/`client_id`, and `EvalContext` resolves them. |
| `test_fallback_loop_unaffected` | `POST /api/v1/login` with Basic credentials and no header still logs in with `PasskeyAuth` enabled (E11). |
| `test_manage_list_rename_delete` | Covers C5, with 409 on deleting the last credential when there is no password and no identity (E13). |
| `test_oauth2_login_page_passkey` | P2. Playwright with a CDP virtual authenticator: login page → passkey → authorize → consent (C6). Marked `e2e` and skipped when Playwright is unavailable. |

### Test Data / Fixtures

```python
# tests/fixtures/passkey.py
@pytest.fixture
def soft_authenticator():
    """ES256 keypair + helpers: make_attestation(rp_id, origin, challenge, user_handle, uv=True)
    and make_assertion(rp_id, origin, challenge, credential_id, sign_count, uv=True, user_handle=None)
    producing py_webauthn-compatible JSON (base64url fields)."""

@pytest.fixture
def passkey_rp_config(monkeypatch):
    """Two RPs: https://a.test (rp_id a.test, org 5) and https://b.test (rp_id b.test, org 7)."""
```

---

## 5. Acceptance Criteria

This feature is complete when **all** of the following hold:

- [ ] **AC1 (C1).** `PASSKEY_RELYING_PARTIES`, `PASSKEY_CHALLENGE_TTL`, `PASSKEY_USER_VERIFICATION`, `PASSKEY_TENANT_ATTRIBUTE` and `PASSKEY_DECOY_CREDENTIALS` exist in `conf.py`. Startup raises `ConfigError` when `PasskeyAuth` is enabled and the RP map is empty, or when `webauthn` is not installed.
- [ ] **AC2 (packaging).** `pip install navigator-auth[passkey]` installs `webauthn>=2.0,<3`. Importing `navigator_auth.backends` without the extra still works.
- [ ] **AC3 (C2).** `{schema}.user_credentials` and `{schema}.user_passkey_handles` are created idempotently on `PasskeyAuth` startup, and `test_store_crud` passes.
- [ ] **AC4 (G2/E3).** The RP is resolved only from an exact `Origin` match. Every ceremony verifies against the RP stored in the challenge state, and a credential is never accepted for a different `rp_id`.
- [ ] **AC5 (C3/E10/E12/E15).** The enrollment endpoints require a session and CSRF. The options use the random per-`(user, RP)` handle and `excludeCredentials`, and a verified credential is stored with `rp_id`.
- [ ] **AC6 (C4).** A passkey login through `POST /api/v1/login` + `X-Auth-Method: PasskeyAuth` returns the `BasicAuth` body (including `refresh_token`) plus `auth_method="passkey"`, `mfa` and `amr`, and sets the session cookie. The JWT carries `auth_method`, `mfa`, `amr` and a `jti` recorded in `access_token_storage`.
- [ ] **AC7 (G3/E5).** Username-first is the default client flow. Unknown users and known users without credentials receive same-shaped options with deterministic decoys; usernameless (empty body) works.
- [ ] **AC8 (edge cases).** E1, E2, E4, E6, E7 (reject, log, credential stays usable), E8, E9 and E11 each have a passing test.
- [ ] **AC9 (G6).** `BasicAuth.open_session` rejects `is_active=False` with 403, and users without the field are unaffected. The existing `tests/test_basic_auth.py`, `tests/test_basic_open_session.py` and token-exchange tests still pass.
- [ ] **AC10 (tenant).** The session carries the RP's `org_id`/`client_id`. With `PASSKEY_TENANT_ATTRIBUTE` set, a mismatched user is rejected with 401.
- [ ] **AC11 (Q5).** `EvalContext` exposes `auth_method` and `mfa`.
- [ ] **AC12 (C5, P2).** The list, rename and delete endpoints work, and E13 returns 409.
- [ ] **AC13 (C6, P2).** The OAuth2 login page offers username-first passkey sign-in and conditional UI and completes authorize → consent. The authorize, consent and token code is unchanged.
- [ ] **AC14.** `auth.py` (`api_login`, `get_auth_backend`) is unmodified, and `PasskeyAuth` appears in `auth_methods`.
- [ ] **AC15.** `pytest tests/test_passkey_*.py tests/test_basic_auth.py tests/test_basic_open_session.py -v` passes, and `ruff` shows no new findings on the touched files.
- [ ] **AC16.** An operator doc for the `PASSKEY_*` settings, the RP map format and the client JS (including the CSRF header for enrollment) exists in `docs/`.

---

## 6. Codebase Contract

All entries below were verified on 2026-10-02 against `dev` at `c2b50e6` unless they are marked otherwise.

### Verified Imports

```python
from navigator_auth.backends.basic import BasicAuth                  # backends/basic.py:43; exported backends/__init__.py:6
from navigator_auth.backends.abstract import BaseAuthBackend         # backends/abstract.py:42
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY                # conf.py:47 ("auth_exclude_list")
from navigator_auth.conf import AUTH_DB_SCHEMA                       # conf.py:32 (fallback "auth")
from navigator_auth.conf import AUTH_USERS_TABLE                     # conf.py:33 (fallback "users")
from navigator_auth.conf import REDIS_AUTH_URL                       # conf.py:333
from navigator_auth.conf import SECRET_KEY                           # conf.py:341
from navigator_auth.conf import CSRF_HEADER_NAME                     # conf.py:104 ("X-CSRF-Token")
from navigator_auth.conf import BASIC_USER_MAPPING                   # conf.py:371
from navigator_auth.exceptions import (AuthException, ConfigError, UserNotFound,
    InvalidAuth, FailedAuth)                                         # exceptions.py:3,26,32,42,47
from navigator_auth.identities import AuthUser                       # identities.py (imported by basic.py:27)
from navigator_auth.responses import JSONResponse                    # responses.py:75
from navigator_auth.identity.store import IdentityStore              # identity/store.py:49
from navigator_session import AUTH_SESSION_OBJECT                    # used at basic.py:11
import redis.asyncio as aioredis                                     # azure.py:14
```

### Existing Class Signatures

```python
# backends/abstract.py
class BaseAuthBackend(ABC):                                          # :42
    userid_attribute: str = "user_id"                                # :47
    _service: str = None   # set to class name in __init__ (:78)     # :52
    _service_name: str = "abstract"                                  # :56
    _success_callbacks / _callbacks                                  # :58-59
    def __init__(self, user_attribute=None, userid_attribute=None, password_attribute=None,
                 template_parser=None, identity: IdentityProvider = None, **kwargs)   # :69
    #   self._info.uri = "/api/v1/login"                             # :104
    async def create_user(self, userdata) -> Identity                # :154
    def get_userdata(self, user: dict, **kwargs) -> dict             # :172 (uses USER_MAPPING; DEFAULT_MAPPING maps enabled→is_active, conf.py:298-309)
    def configure(self, app)                                         # :185 (sets self._app)
    def Unauthorized(self, reason, **kwargs) -> web.HTTPError        # :248
    async def validate_user(self, login=None, userid=None)           # :251 (BasicAuth overrides with (login, password))
    async def remember(self, request, identity, userdata, user)      # :268 (new_session; session.save_encoded_data(request, "user", user))

# backends/basic.py
class BasicAuth(BaseAuthBackend):                                    # :43
    _service_name: str = "basic"                                     # :50
    def configure(self, app)                                         # :52 (GET /auth/{_service_name}/check_credentials, appended to app[AUTH_EXCLUDE_LIST_KEY])
    async def on_startup(self, app)                                  # :64 (self.access_token_storage = AccessTokenStorage(); callbacks)
    async def validate_user(self, login=None, password=None)         # :87
    _JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at")   # :154
    async def open_session(self, request, user: dict, extra: Optional[dict] = None,
                           expiration: Optional[int] = None) -> dict  # :171
    #   token, refresh_token, exp, scheme = self._idp.create_token(data=payload, expiration=expiration)  # :226
    #   userdata["auth_method"] defaults to "basic" only if absent  # :262
    async def authenticate(self, request)                            # :292 (wraps open_session in except Exception → False, :310-314)

# backends/exchange.py
class TokenExchangeAuth(BasicAuth):                                  # :31 — precedent; open_session(..., extra=extra, expiration=cap) at :216

# backends/idp/__init__.py
class IdentityProvider:                                              # :39
    async def user_from_id(self, uid: int) -> Identity               # :124 (raises UserNotFound)
    async def get_user(self, login: str) -> Identity                 # :146
    def create_token(self, data=None, issuer=None, expiration=None, audience=None) -> tuple   # :379 → (jwt, refresh_token, exp, scheme)

# auth.py
class AuthHandler:
    async def auth_startup(self, app)                                # :174 (await backend.on_startup(app) per backend; then setup_identity_columns)
    def get_backends(self, **kwargs)                                 # :241 (dict keyed by class name)
    def get_auth_backend(self, request)                              # :343 (X-Auth-Method → self.backends[method])
    async def _backend_auth(self, request, backend)                  # :386 (UserNotFound→401; InvalidAuth/Forbidden/FailedAuth→ForbiddenAccess(status=err.status))
    async def api_create_token(self, request)                        # :452 (pattern: request.get("authenticated") at :454; request.user.user_id at :460-461)
    async def api_login(self, request)                               # :470 (fallback loop catches AuthException, UserNotFound, InvalidAuth, FailedAuth)
    async def auth_methods(self, request)                            # :551

# identity/store.py
class IdentityStore:                                                 # :49
    def __init__(self, db_pool: Any, cipher: Optional[IdentityCipher] = None)   # :52
    async def list_for_user(self, user_id: Any) -> list[dict]        # :199

# identity/migrations.py
_MIGRATION_FILES = (...)  ;  async def ensure_identity_columns(db_pool)  ;  async def setup_identity_columns(db_pool)   # non-raising

# models.py
class User(Model):                                                   # :39 — user_id: int PK (:42), username (:53), display_name, email, is_active: bool (:58); Meta name=AUTH_USERS_TABLE, schema=AUTH_DB_SCHEMA (:68-70); NO org_id

# abac/context.py
def _resolve_tenant(request, userinfo, org_id, client_id) -> tuple[int, int]   # :28 (kwargs → trusted headers → userinfo["org_id"/"client_id"] → (1,1))
class EvalContext(dict, MutableMapping):                             # :81
    def __init__(self, request, user, userinfo, session, *args, org_id=None, client_id=None, **kwargs)  # :87
    #   self.store['userinfo'] = userinfo  :124 ; _resolve_tenant(...) :135

# middlewares/csrf.py
def _is_cookie_only_session(request) -> bool    # authenticated and no Authorization header
async def csrf_middleware(request, handler)     # rejects UNSAFE_METHODS without a valid CSRF_HEADER_NAME when ENABLE_CSRF_PROTECTION (conf.py:102, default True)

# backends/oauth2/backend.py
async def check_session(self, request)                               # :561 (session["user"])
async def auth_login(self, request)                                  # :1696 (GET renders "oauth/login.html" :1712; POST uses idp.authenticate_credentials :1716, NOT open_session)
async def authorize(self, request)                                   # :1423
```

### External library (not installed in the venv — verify after `uv add`)

The py_webauthn 2.x API is listed here as **unverified — check before use**:

- `generate_registration_options(rp_id, rp_name, user_id: bytes, user_name, user_display_name, attestation, authenticator_selection, exclude_credentials)`
- `verify_registration_response(credential, expected_challenge, expected_rp_id, expected_origin, require_user_verification)`, returning `.credential_id`, `.credential_public_key`, `.sign_count`, `.aaguid`, `.credential_device_type`, `.credential_backed_up`
- `generate_authentication_options(rp_id, allow_credentials, user_verification)`
- `verify_authentication_response(credential, expected_challenge, expected_rp_id, expected_origin, credential_public_key, credential_current_sign_count, require_user_verification)`, returning `.new_sign_count`, `.credential_backed_up`, `.user_verified`
- `options_to_json`
- `webauthn.helpers.base64url_to_bytes` and `bytes_to_base64url`
- `webauthn.helpers.exceptions.InvalidAuthenticationResponse` and `InvalidRegistrationResponse`

The first task that adds the dependency must confirm these names, especially `VerifiedAuthentication.user_verified`.

### Does NOT Exist (Anti-Hallucination)

- No WebAuthn, FIDO, passkey or TOTP code anywhere in `navigator_auth/`.
- `navigator_auth/passkey/` package, `PasskeyAuth`, `PasskeyUser`, `PasskeyStore`, `RelyingPartyResolver`, `RelyingParty`, `StoredCredential` and `ChallengeState` — all new.
- `IdentityProvider.get_credential`, `list_credentials`, `save_credential` and `update_credential_usage`. These were the brainstorm's names; **do not add them to the IdP**, because storage lives in `PasskeyStore`.
- `PASSKEY_*` settings; the `passkey` extra; a `webauthn` dependency.
- `org_id` on `models.User`. Tenant membership is deployment-specific, hence the optional `PASSKEY_TENANT_ATTRIBUTE`.
- A module-level `exclude_list` that the middleware reads per app. Use `app[AUTH_EXCLUDE_LIST_KEY]`.
- `navigator_auth/templates/`. Templates live at the repo root `templates/oauth/`.
- A 3-tuple return from `create_token`. It returns 4 values.
- Any `is_active` check in the login paths today (Basic, Exchange, Abstract, IdP lookups, OAuth2 `auth_login`).

### Edit Sites (Blueprint Anchors)

| File | Anchor | Change |
|---|---|---|
| `navigator_auth/conf.py` | after the backend settings (~`:333` REDIS block) | Add the `PASSKEY_*` settings. |
| `pyproject.toml` | `:60` `[project.optional-dependencies]` | Add the `passkey` extra. |
| `navigator_auth/backends/basic.py` | `:154` `_JWT_EXTRA_KEYS`; `:171-204` `open_session` before `remember()` (`:213`); `:310-314` `authenticate` | Add `mfa`/`amr`, the `is_active` check and exception propagation. |
| `navigator_auth/backends/__init__.py` | imports `:5-23`, `__all__` `:26-45` | Export `PasskeyAuth` (lazy webauthn import inside the module). |
| `navigator_auth/abac/context.py` | after `:124` | Add the `auth_method` and `mfa` keys. |
| `templates/oauth/login.html` | form `:22-38`; hidden params `:29-37` | Passkey UI and script. |

---

## 7. Implementation Notes & Constraints

### Patterns to Follow

- **Reuse the session tail.** Subclass `BasicAuth` and call `open_session`; never copy the post-validation tail (`TokenExchangeAuth` is the precedent).
- **Call `super()` in lifecycle hooks.** `on_startup` and `on_cleanup` must call `super()`; `access_token_storage` is load-bearing for `_token_is_revoked`.
- **Public routes.** Register them with `app[AUTH_EXCLUDE_LIST_KEY].append(path)`.
- **Protected handlers.** Gate on `request.get("authenticated")` and read `request.user.user_id`.
- **Redis.** Follow `AzureAuth`: `aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True)` in `on_startup`, `async with aioredis.Redis(connection_pool=...)`, and a disconnect in `on_cleanup`.
- **Storage and migrations.** Follow `IdentityStore` and the non-raising `setup_*` migration pattern.
- **Logging.** Use `self.logger` and never `print`. Log credential ids as base64url and never log assertion payloads.
- **Typing and data.** Google-style docstrings and type hints throughout, with Pydantic models for the new data structures (§2 Data Models).

### Known Risks / Gotchas

- **R1. Fallback loop (E11).** Any non-Auth exception (a Redis or DB error) raised by `PasskeyAuth.authenticate` when no header is sent aborts the login for all backends (`auth.py:484-490`). `get_payload` must fail fast with `InvalidAuth` before any I/O. Wrap Redis and DB errors after that point in `AuthException`.
- **R2. `open_session` behaviour change (G6).** Inactive users that could log in before (Basic, TokenExchange) will now get 403. Call this out in `CHANGELOG.md`. Custom `AUTH_USER_VIEW` models without `is_active` are unaffected.
- **R3. Error swallowing.** `BasicAuth.authenticate` currently turns any `open_session` exception into `False`, which becomes a generic 403. Module 4 must re-raise `FailedAuth`/`InvalidAuth`. Check `TokenExchangeAuth` too (`exchange.py:216`, called directly), so the 403 surfaces cleanly there.
- **R4. Decoy residual leak (E5).** A real user with N > 1 credentials shows N ids, while unknown users show `PASSKEY_DECOY_CREDENTIALS` ids. Count-based inference remains possible and is accepted. Keep response timing comparable: always do the DB lookup.
- **R5. OAuth2 session blob (C6).** `Oauth2Provider._decode_session_user` parses the jsonpickle envelope written by `_create_user_session`. It is not verified that `remember()`'s `save_encoded_data(request, "user", user)` produces a compatible blob. Module 8 must test this first. If the blobs differ, add a thin compatibility path in the template flow (still no change to authorize).
- **R6. Origin header.** Some same-origin `fetch` POSTs include `Origin` and some do not, depending on the browser. WebAuthn `clientDataJSON.origin` is still verified cryptographically. If `Origin` is missing on `login/options`, fall back to `Referer` origin only when it is an exact allow-list match; otherwise return 401.
- **R7. ALB / TLS.** Never derive the scheme or host from the request. All origins come from config.
- **R8. Synced passkeys.** These have `sign_count` 0 and `backed_up=true`. Never treat 0/0 as a regression.
- **R9. Optional dependency.** `navigator_auth.backends.__init__` imports `PasskeyAuth`, so `webauthn` must be imported lazily (inside `on_startup` or the methods), or importing the package breaks for installs without the extra.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| `webauthn` (py_webauthn) | `>=2.0,<3` | WebAuthn option generation and verification (optional extra `passkey`). |
| `redis` (existing) | ≥ server 6.2 | `GETDEL` for single-use challenges. |
| `playwright` (dev, optional) | any | C6 end-to-end test with a CDP virtual authenticator. |

---

## 8. Open Questions

Resolved during proposal research and Q&A (`sdd/proposals/passkey-support-backend.proposal.md` §5):

- [x] Q1 — RP ID scope — *Resolved in proposal*: **Per-tenant RP ID**, through the per-origin allow-list map (§2.1).
- [x] U2 — `is_active` scope — *Resolved in proposal*: **Enforced in `BasicAuth.open_session`** for every Basic-derived login (§2.8, Module 4).
- [x] Q8 — Redis version — *Resolved in proposal*: **Production runs 6.2 or later**, so `GETDEL` is used (§2.2).
- [x] Q10 — Enrollment re-auth — *Resolved in proposal*: **Any live session** plus CSRF in v1 (Non-Goals, §2.4).
- [x] Q3 — Where the helpers live — *Resolved in proposal*: **A dedicated store class** following the `IdentityStore` precedent (`PasskeyStore`, Module 2).
- [x] Q7 — Packaging — *Resolved in proposal*: **The optional extra `navigator-auth[passkey]`** (Module 1, R9).
- [x] Q2 — User handle — *Resolved in proposal*: **A random per-`(user, RP)` handle**, never `str(user_id)` (Data Models, §2.4, §2.5).
- [x] Q4 — Counter regression — *Resolved in proposal*: **Reject and log only**; the credential stays usable (§2.5, `test_sign_count_regression_rejected_logged`).
- [x] Q5 — ABAC exposure — *Resolved in proposal*: **Yes**, as `auth_method` and `mfa` keys in `EvalContext` (Module 6).
- [x] Q6 — Passkey as MFA — *Resolved in proposal*: **Yes**, with UV ⇒ `mfa=true`, `amr=["hwk","user"]`, both in the session and the JWT (§2.6, Module 4).
- [x] Q9 — Username-first — *Resolved in proposal*: **Username-first is the preferred, default flow**; usernameless stays supported (§2.5, Module 8).
- [x] RP map and `org_id` — *Resolved in proposal*: **Each RP entry carries `(org_id, client_id)`**, which goes into the session for ABAC (§2.6).
- [x] Q-T — Tenant membership check (default `User` has no `org_id`) — *Resolved in spec Q&A*: **The per-site credential binding does the isolation; a membership check runs only when `PASSKEY_TENANT_ATTRIBUTE` is set and present on the user** (§2.5, AC10).

Unresolved:

- [ ] Q-F1 — `Oauth2Provider.auth_login` (password POST on the OAuth2 page) uses `IdentityProvider.authenticate_credentials` and does not check `is_active` either. Should it be fixed as a follow-up hotfix, or folded into Module 4? *Owner: Jesus Lara*
- [ ] Q-F2 — `PASSKEY_DECOY_CREDENTIALS`: is the default of 1 enough, or should the count be randomized from 1 to 3 per username (still deterministic) to blur R4? This can be decided during implementation. *Owner: implementer*

---

## 9. Design Research Cross-Check

Status: skipped (exploration document status is `review`, not `accepted` — precondition for the codex design-research seat not met)

| # | Suggestion | Disposition | Reason | Landed in |
|---|---|---|---|---|

---

## Worktree Strategy

- **Isolation unit:** per-spec, with a mixed task graph, in one worktree `feat-FEAT-101-passkey-support-backend` based on `origin/dev`.
- **Serial S0 (P0) — freezes the contracts:** Module 1 (config and packaging), Module 2 (storage and migration), Module 3 (RP resolver), plus the software-authenticator fixture from Module 9.
- **After S0, these can run in parallel:**
  - Module 4 (`basic.py`) and Module 6 (`abac/context.py`) touch disjoint files.
  - Module 5 (`passkey.py`) depends on Module 4 only for the `_JWT_EXTRA_KEYS` and `is_active` behaviour. It can develop in parallel against the frozen signatures, and its integration tests run after Module 4 merges.
- **Serial last (P2):** Module 7 and then Module 8 (both depend on Module 5), and finally the docs.
- **Conflict note:** Modules 5 and 7 both edit `backends/passkey.py`, so they must be sequential. No module edits `auth.py`.
- **Cross-feature dependencies:** none must merge first. FEAT-098 (jti revocation) and FEAT-096 (`open_session`) are already on `dev`.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-10-02 | Jesus Lara (with Claude) | Initial draft from the FEAT-101 proposal; adds the Q-T resolution and the C6 / OAuth2 session-blob risk. |
