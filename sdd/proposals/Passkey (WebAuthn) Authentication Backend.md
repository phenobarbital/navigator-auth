# SDD Brainstorm — Passkey (WebAuthn) Authentication Backend

Oct 2, 2026 · @Jesus Lara

## Frontmatter

```yaml
feature: passkey-auth
title: Passkey (WebAuthn / FIDO2) authentication backend
type: brainstorm
status: draft
package: navigator-auth
component: navigator_auth/backends/passkey.py (new)
new_dependency: webauthn (py_webauthn) >= 2.0
runtime: aiohttp + Redis (challenge state) + PostgreSQL via authdb (credentials)
related: SPEC_oauth2_3lo.md (login page of Oauth2Provider)
handoff: implementation agent (Claude Code), phased
```

## Feature description

Add a `PasskeyAuth` backend so users of the navigator-auth IdP can sign in with a WebAuthn passkey instead of a password, reusing the existing session and token issuance path.

**Problem.** Every first-party login today ends in a shared secret (`BasicAuth` password check via `IdentityProvider.check_password`) or a redirect to an external IdP. There is no phishing-resistant, first-party credential.

**Goal.** A user who is already authenticated can enroll one or more passkeys. Later, the same user signs in with a passkey alone, with or without typing a username, and receives the same payload `BasicAuth` returns (`token`, `expires_in`, `token_type`, user data, session cookie).

**Proposed approach.**

- New backend `navigator_auth/backends/passkey.py`, subclass of `BaseAuthBackend`, enabled through `AUTHENTICATION_BACKENDS` like any other.
- Ceremony logic delegated to `webauthn` (py\_webauthn): option generation and signature verification. No hand-rolled CBOR/COSE.
- Challenges live in Redis with `setex` and are consumed once, mirroring the `azure_auth_{state}` pattern in `AzureAuth`.
- Credentials live in a new table `auth.user_credentials` (one user, many passkeys), accessed through `app["authdb"]`.
- Login verification goes through the existing `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth`, so `AuthHandler.api_login` keeps ownership of the session cookie (`self._session.storage.load_session`). Only the options and enrollment endpoints are new routes.

**Non-goals.**

- Attestation verification and authenticator allow-listing (enterprise AAGUID policy). Attestation is requested as `none`.
- Passkey as a second factor on top of a password (MFA step-up). This brainstorm covers passkey as primary sign-in only.
- Account recovery flows. Password and external backends remain the recovery path.
- Changes to ABAC, scopes or the OAuth2 token endpoint. The OAuth2 login page only gains a button.
- Self-service sign-up with a passkey for users that do not yet exist.

## Flows

&#91;embedded content: passkey ceremonies · enrollment and sign-in, 4 steps each\]

Enrollment binds a new public key to the session user; sign-in ends in the existing `api_login` path, so session and token issuance are untouched.

| Method and path | Auth | Request | Response |
| --- | --- | --- | --- |
| `POST /api/v1/auth/passkey/register/options` | Session | Empty | `PublicKeyCredentialCreationOptions` JSON |
| `POST /api/v1/auth/passkey/register/verify` | Session | `{credential, label?}` | 201 `{status: "registered"}` |
| `POST /api/v1/auth/passkey/login/options` | Public | Empty | `{challenge_id, publicKey}` |
| `POST /api/v1/login` + `X-Auth-Method: PasskeyAuth` | Public | `{challenge_id, credential}` | Same body as `BasicAuth`, `auth_method: "passkey"`, session cookie |
| `GET /api/v1/auth/passkey/credentials` (P2) | Session | None | List of the caller's passkeys |
| `DELETE /api/v1/auth/passkey/credentials/{id}` (P2) | Session | None | 204, or 409 per E13 |

## Edge cases and security

The threat model is a remote attacker with a phishing page or a replayed request; a stolen database must yield nothing usable, since only public keys are stored.

| # | Case | Expected behavior |
| --- | --- | --- |
| E1 | Challenge replay | Challenge is deleted from Redis on first read (`GETDEL`). A second verify with the same challenge returns 401. |
| E2 | Challenge expired | TTL 300 s. Missing key returns 401 with a "ceremony expired" reason; the client restarts from options. |
| E3 | Origin or RP ID mismatch | `expected_origin` is the configured allow-list, never derived from the `Host` header. Mismatch returns 401. Behind the ALB, `request.url` scheme is not trusted. |
| E4 | Unknown `credential_id` | Returns the same 401 as a bad signature. No distinction that reveals which credentials exist. |
| E5 | Username enumeration in username-first mode | Options for an unknown user still return a well-formed response with an empty or decoy `allowCredentials`. Default mode is usernameless, which avoids the problem. |
| E6 | `sign_count` is 0 on both sides | Accepted. Synced passkeys (iCloud, Google Password Manager) do not maintain counters. |
| E7 | `sign_count` goes backwards (stored > 0) | Possible cloned authenticator. Reject, log at warning with user and credential id, do not auto-disable (open question Q4). |
| E8 | User verification flag absent | Rejected when `PASSKEY_USER_VERIFICATION=required` (default). Presence-only assertions are not enough for a primary factor. |
| E9 | User disabled after enrollment | The backend loads the user through the IdP after signature verification and `rejects accounts whose is_active is false (whether BasicAuth already enforces this was not verified)`. A valid signature never bypasses account state. |
| E10 | Duplicate enrollment on the same authenticator | Registration options carry `excludeCredentials` with the user's existing ids; the browser refuses to create a second one. |
| E11 | `api_login` fallback loop | When no `X-Auth-Method` header is sent, `AuthHandler.api_login` calls `authenticate()` on every backend. `PasskeyAuth.authenticate` must raise `InvalidAuth` immediately if the body has no assertion, with no Redis or DB I/O. |
| E12 | Enrollment endpoint called without a session | 401. Registration is never public; otherwise anyone could attach a passkey to an arbitrary account. |
| E13 | Last credential deleted | Allowed only if the user has another usable login method (password set or external identity). Otherwise 409. |
| E14 | Multiple RP domains | A passkey is bound to one RP ID. Deployments serving several registrable domains need one RP ID per domain or Related Origin Requests (out of scope). |
| E15 | User handle leaks PII | `user.id` sent to the authenticator is an opaque value derived from the user id, never the email or username. |

## Capabilities

Six deliverable units, ordered so each phase is shippable on its own.

| ID | Capability | Phase | Acceptance criteria |
| --- | --- | --- | --- |
| C1 | Configuration | P0 | `PASSKEY_RP_ID`, `PASSKEY_RP_NAME`, `PASSKEY_ORIGINS` (list), `PASSKEY_CHALLENGE_TTL` (default 300), `PASSKEY_USER_VERIFICATION` (default `required`) read in `conf.py`. Startup fails with `ConfigError` if the backend is enabled and RP ID or origins are missing. |
| C2 | Credential storage | P0 | Table `auth.user_credentials` and model `UserCredential` exist. `credential_id` is unique. CRUD covered by tests: insert, get by `credential_id`, list by `user_id`, update `sign_count` and `last_used_at`, delete. |
| C3 | Enrollment | P1 | `POST /api/v1/auth/passkey/register/options` returns valid `PublicKeyCredentialCreationOptions` for the session user, with `excludeCredentials`. `POST .../register/verify` stores the credential and returns 201. Both return 401 without a session. |
| C4 | Sign-in | P1 | `POST /api/v1/auth/passkey/login/options` returns request options and a `challenge_id`. `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth` and a valid assertion returns the same shape as `BasicAuth` plus `auth_method: "passkey"`, and sets the session cookie. E1 to E9 and E11 each have a test. |
| C5 | Credential management | P2 | `GET /api/v1/auth/passkey/credentials` lists the caller's passkeys (id, label, created, last used, backup state). `DELETE .../credentials/{id}` removes one and enforces E13. `PATCH` renames the label. |
| C6 | Login page integration | P2 | The OAuth2 provider login template offers "Sign in with a passkey" and conditional UI (`autocomplete="username webauthn"`). The authorize and consent steps are unchanged. The backend appears in `auth_methods` output. |

Testing note: `webauthn` verification can be exercised without a browser by generating an ES256 key pair in the test and building the authenticator data and client data by hand, or with a software authenticator fixture. Playwright with a virtual authenticator (CDP `WebAuthn.addVirtualAuthenticator`) covers C6 end to end.

## Impact table

One new module carries most of the change; edits to existing files are additive.

| Component | Change | Kind | Risk |
| --- | --- | --- | --- |
| `navigator_auth/backends/passkey.py` | New `PasskeyAuth(BaseAuthBackend)` | New | Low |
| `navigator_auth/backends/__init__.py` | Export `PasskeyAuth` | Edit | Low |
| `navigator_auth/conf.py` | `PASSKEY_*` settings | Edit | Low |
| `navigator_auth/models.py` | `UserCredential` model | Edit | Low |
| `navigator_auth/backends/idp/__init__.py` | Credential lookup and persistence helpers on `IdentityProvider` | Edit | Medium: touches the shared IdP |
| DDL / migrations | `auth.user_credentials` table and indexes | New | Low |
| `navigator_auth/templates/` (OAuth2 login page) | Passkey button and conditional UI script | Edit | Medium: template location not verified |
| `pyproject.toml` / `setup.py` | `webauthn` dependency, ideally as an optional extra `navigator-auth[passkey]` | Edit | Low |
| `navigator_auth/auth.py` | None required. `api_login`, `get_auth_backend` and `auth_methods` already handle a new backend by name | None | None |
| Session layer (`navigator_session`) | None | None | None |
| ABAC / `PolicyEvaluator` | None. Optionally expose `auth_method` in `EvalContext` later so policies can require a passkey | None | None |

## Verified code context

Everything below was read in the project knowledge base on 2026-10-02. The implementation agent must not assume symbols outside the first table.

### Exists (verified)

| Symbol | Location | Relevance |
| --- | --- | --- |
| `BaseAuthBackend` | `backends/abstract.py` | Base class. Takes `identity` (stored as `self._idp`), `template_parser`, `user_model`, `scheme` in `__init__`. Abstract: `on_startup`, `check_credentials`. |
| `BaseAuthBackend.remember(request, identity, userdata, user)` | `backends/abstract.py` | Creates the session via `new_session`, sets `request.user`, returns the session. |
| `BaseAuthBackend.validate_user(login=None, userid=None)` | `backends/abstract.py` | Calls `self._idp.get_user(login)` or `self._idp.user_from_id(userid)`. |
| `get_userdata`, `create_user`, `auth_successful_callback`, `get_successful_callbacks` | `backends/abstract.py` (called from `basic.py`, `external.py`) | Used to build the session payload and fire post-login callbacks. |
| `self._info` (`AuthBackend`) | `backends/abstract.py` | `uri` defaults to `/api/v1/login`; `headers = {"x-auth-method": self._service}` where `_service` is the class name. |
| `BasicAuth.authenticate` | `backends/basic.py` | Reference flow: validate, `get_userdata`, `create_user`, `remember`, `self._idp.create_token(data=payload)` returning `(token, exp, scheme)`, callbacks, return `{"token": token, **userdata}`. |
| `IdentityProvider` | `backends/idp/__init__.py` | `get_user(login)`, `check_password`, `create_token`, `create_ephemeral_token`, `user_model`. DB access through `self.app["authdb"]` and `async with await db.acquire() as conn`. |
| `AuthHandler.api_login` | `auth.py` | Resolves the backend with `get_auth_backend(request)` (header `X-Auth-Method`, key = backend class name), otherwise iterates all backends. Builds `JSONResponse(userdata)` and calls `self._session.storage.load_session(request, userdata, response=response)`. |
| `AuthHandler.get_backends` | `auth.py` | Loads classes from `AUTHENTICATION_BACKENDS` dotted paths; dict key is the class name. |
| `exclude_list` | `conf.py` | Backends append public routes in `configure(app)`, then call `super().configure(app)`. |
| Redis challenge pattern | `backends/azure.py` | `aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True)` in `on_startup`; `redis.setex(f"azure_auth_{state}", ttl, json)`; pool disconnect in `on_cleanup`. |
| `Oauth2Provider` routes | `backends/oauth2/backend.py` | `login_uri` handled by `auth_login`; `authorize`, `consent`, `token_request`, `userinfo`. |
| `InvalidAuth`, `FailedAuth`, `UserNotFound`, `AuthException` | `exceptions.py` | Error types `api_login` catches in its fallback loop. |
| `AuthUser`, `JSONResponse` | `identities.py`, `responses.py` | Identity base class and response helper. |

### Does not exist (must be created)

- Any WebAuthn, FIDO, passkey, TOTP or MFA code. A knowledge search for these terms returned nothing.
- `navigator_auth/backends/passkey.py`, `PasskeyAuth`, `PasskeyUser`.
- `UserCredential` model and the `auth.user_credentials` table.
- `PASSKEY_*` settings in `conf.py`.
- `IdentityProvider.get_credential`, `list_credentials`, `save_credential`, `update_credential_usage`. These names are proposals of this document.
- A `webauthn` dependency in the package metadata.

### Not verified (check before relying on it)

- The definition of `IdentityProvider.user_from_id`. It is called in `abstract.py`; its body was not read.
- Whether `BasicAuth` or the IdP rejects users with `is_active = false`.
- The contents of `navigator_auth/models.py` beyond the dotted path `navigator_auth.models.User` in `conf.py`, and the primary key type of the user table.
- The file name of the OAuth2 login template rendered by `Oauth2Provider.auth_login`.
- How `request.user` is populated on a protected route (which middleware), needed by the enrollment endpoints.
- The body of `AuthHandler._backend_auth`.

## Backend skeleton

The skeleton below is a starting point for the implementation agent, not tested code. Calls marked `PROPOSED` do not exist yet; calls marked `VERIFY` exist but their exact signature must be checked.

### Storage

```sql
CREATE TABLE IF NOT EXISTS auth.user_credentials (
    credential_id  bytea PRIMARY KEY,
    user_id        integer NOT NULL,          -- VERIFY: type and FK target of the user PK
    public_key     bytea NOT NULL,            -- COSE key as returned by py_webauthn
    sign_count     bigint NOT NULL DEFAULT 0,
    transports     text[],
    aaguid         uuid,
    device_type    varchar(32),               -- single_device | multi_device
    backed_up      boolean NOT NULL DEFAULT false,
    label          varchar(128),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX IF NOT EXISTS user_credentials_user_idx
    ON auth.user_credentials (user_id);
```

### Settings (`conf.py`)

```python
PASSKEY_RP_ID = config.get("PASSKEY_RP_ID")                # e.g. "example.com"
PASSKEY_RP_NAME = config.get("PASSKEY_RP_NAME", fallback="Navigator")
PASSKEY_ORIGINS = [
    e.strip()
    for e in config.get("PASSKEY_ORIGINS", fallback="").split(",")
    if e.strip()
]                                                          # e.g. "https://app.example.com"
PASSKEY_CHALLENGE_TTL = config.getint("PASSKEY_CHALLENGE_TTL", fallback=300)
PASSKEY_USER_VERIFICATION = config.get(
    "PASSKEY_USER_VERIFICATION", fallback="required"
)
```

### `navigator_auth/backends/passkey.py`

```python
"""Passkey Backend.

Navigator Authentication using WebAuthn passkeys (FIDO2).
"""
import secrets
import orjson
from aiohttp import web
from redis import asyncio as aioredis
from navigator_session import AUTH_SESSION_OBJECT, get_session
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from ..conf import (
    REDIS_AUTH_URL,
    PASSKEY_RP_ID,
    PASSKEY_RP_NAME,
    PASSKEY_ORIGINS,
    PASSKEY_CHALLENGE_TTL,
    PASSKEY_USER_VERIFICATION,
    exclude_list,
)
from ..exceptions import AuthException, ConfigError, InvalidAuth, UserNotFound
from ..identities import AuthUser
from ..responses import JSONResponse
from .abstract import BaseAuthBackend


class PasskeyUser(AuthUser):
    """User authenticated with a WebAuthn passkey."""


class PasskeyAuth(BaseAuthBackend):
    """WebAuthn passkey authentication."""

    _ident: AuthUser = PasskeyUser
    _description: str = "Passkey (WebAuthn) authentication"
    _service_name: str = "passkey"
    _pool = None

    # ------------------------------------------------------------------ setup
    def configure(self, app):
        if not PASSKEY_RP_ID or not PASSKEY_ORIGINS:
            raise ConfigError(
                "PasskeyAuth: PASSKEY_RP_ID and PASSKEY_ORIGINS are required"
            )
        base = f"/api/v1/auth/{self._service_name}"
        router = app.router
        # public: start of the login ceremony
        router.add_route(
            "POST", f"{base}/login/options", self.login_options,
            name="passkey_login_options",
        )
        exclude_list.append(f"{base}/login/options")
        # protected (NOT in exclude_list): enrollment and management
        router.add_route(
            "POST", f"{base}/register/options", self.register_options,
            name="passkey_register_options",
        )
        router.add_route(
            "POST", f"{base}/register/verify", self.register_verify,
            name="passkey_register_verify",
        )
        # login/verify is NOT a route here: it is POST /api/v1/login with
        # X-Auth-Method: PasskeyAuth, handled by AuthHandler.api_login,
        # which calls self.authenticate() and sets the session cookie.
        super().configure(app)

    async def on_startup(self, app: web.Application):
        self._pool = aioredis.ConnectionPool.from_url(
            REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        if self._success_callbacks:
            self._user_model = self._idp.user_model
            self.get_successful_callbacks()

    async def on_cleanup(self, app: web.Application):
        if self._pool:
            await self._pool.disconnect(inuse_connections=True)

    # ------------------------------------------------------- challenge state
    async def _save_challenge(self, kind: str, key: str, data: dict) -> None:
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            await redis.setex(
                f"passkey_{kind}_{key}",
                PASSKEY_CHALLENGE_TTL,
                orjson.dumps(data).decode(),
            )

    async def _pop_challenge(self, kind: str, key: str) -> dict:
        """Single use (E1): read and delete atomically. Needs Redis >= 6.2."""
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            raw = await redis.getdel(f"passkey_{kind}_{key}")
        if not raw:
            raise InvalidAuth("Passkey: ceremony expired", status=401)
        return orjson.loads(raw)

    @staticmethod
    def _user_handle(uid) -> bytes:
        # Opaque, stable, no PII (E15). See open question Q2.
        return str(uid).encode("utf-8")

    async def _session_user(self, request: web.Request):
        """Enrollment requires an authenticated session (E12)."""
        user = getattr(request, "user", None)   # VERIFY: which middleware sets it
        if user is None or not getattr(user, "is_authenticated", False):
            raise self.Unauthorized(reason="Passkey: authentication required")
        return user

    # ------------------------------------------------------------ enrollment
    async def register_options(self, request: web.Request) -> web.Response:
        user = await self._session_user(request)
        existing = await self._idp.list_credentials(user.id)        # PROPOSED
        options = generate_registration_options(
            rp_id=PASSKEY_RP_ID,
            rp_name=PASSKEY_RP_NAME,
            user_id=self._user_handle(user.id),
            user_name=user.username,
            user_display_name=getattr(user, "display_name", user.username),
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement(
                    PASSKEY_USER_VERIFICATION
                ),
            ),
            exclude_credentials=[                                    # E10
                PublicKeyCredentialDescriptor(id=c.credential_id)
                for c in existing
            ],
        )
        await self._save_challenge(
            "reg", str(user.id),
            {"challenge": bytes_to_base64url(options.challenge)},
        )
        return web.Response(
            text=options_to_json(options), content_type="application/json"
        )

    async def register_verify(self, request: web.Request) -> web.Response:
        user = await self._session_user(request)
        body = await request.json()
        state = await self._pop_challenge("reg", str(user.id))
        try:
            verified = verify_registration_response(
                credential=body["credential"],
                expected_challenge=base64url_to_bytes(state["challenge"]),
                expected_rp_id=PASSKEY_RP_ID,
                expected_origin=PASSKEY_ORIGINS,                     # E3
                require_user_verification=(
                    PASSKEY_USER_VERIFICATION == "required"
                ),
            )
        except (InvalidRegistrationResponse, KeyError) as err:
            raise self.Unauthorized(reason=f"Passkey: {err}")
        await self._idp.save_credential(                             # PROPOSED
            user_id=user.id,
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            aaguid=verified.aaguid,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
            transports=body["credential"].get("response", {}).get("transports"),
            label=body.get("label"),
        )
        return JSONResponse({"status": "registered"}, status=201)

    # ----------------------------------------------------------------- login
    async def login_options(self, request: web.Request) -> web.Response:
        """Usernameless by default: empty allowCredentials (E5)."""
        options = generate_authentication_options(
            rp_id=PASSKEY_RP_ID,
            user_verification=UserVerificationRequirement(
                PASSKEY_USER_VERIFICATION
            ),
        )
        challenge_id = secrets.token_urlsafe(24)
        await self._save_challenge(
            "login", challenge_id,
            {"challenge": bytes_to_base64url(options.challenge)},
        )
        return web.Response(
            text=orjson.dumps({
                "challenge_id": challenge_id,
                "publicKey": orjson.loads(options_to_json(options)),
            }).decode(),
            content_type="application/json",
        )

    async def get_payload(self, request: web.Request) -> tuple:
        """Return (challenge_id, credential). Fail fast, no I/O (E11)."""
        if request.content_type != "application/json":
            raise InvalidAuth("Passkey: missing assertion", status=401)
        try:
            data = await request.json()
            return data["challenge_id"], data["credential"]
        except Exception as err:
            raise InvalidAuth("Passkey: missing assertion", status=401) from err

    async def authenticate(self, request: web.Request):
        """Verify an assertion and open the session (same tail as BasicAuth)."""
        challenge_id, credential = await self.get_payload(request)
        state = await self._pop_challenge("login", challenge_id)
        try:
            cred_id = base64url_to_bytes(credential["rawId"])
        except (KeyError, ValueError) as err:
            raise InvalidAuth("Passkey: invalid credential", status=401) from err
        stored = await self._idp.get_credential(cred_id)             # PROPOSED
        if stored is None:                                           # E4
            raise InvalidAuth("Passkey: invalid credential", status=401)
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(state["challenge"]),
                expected_rp_id=PASSKEY_RP_ID,
                expected_origin=PASSKEY_ORIGINS,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,     # E6, E7
                require_user_verification=(                          # E8
                    PASSKEY_USER_VERIFICATION == "required"
                ),
            )
        except InvalidAuthenticationResponse as err:
            self.logger.warning(
                f"Passkey: verification failed for user {stored.user_id}: {err}"
            )
            raise InvalidAuth("Passkey: invalid credential", status=401) from err
        await self._idp.update_credential_usage(                     # PROPOSED
            cred_id,
            sign_count=verified.new_sign_count,
            backed_up=verified.credential_backed_up,
        )
        # From here on, mirror BasicAuth.authenticate
        try:
            user = await self.validate_user(userid=stored.user_id)   # VERIFY
        except UserNotFound:
            raise
        except Exception as err:
            raise AuthException(str(err), status=500) from err
        # TODO (E9): reject when the user is not active.
        try:
            userdata = self.get_userdata(user=user)
            username = user[self.username_attribute]
            uid = user[self.userid_attribute]
            userdata[self.username_attribute] = username
            userdata[self.session_key_property] = username
            usr = await self.create_user(userdata[AUTH_SESSION_OBJECT])
            usr.id = uid
            usr.set(self.username_attribute, username)
            session = await self.remember(request, username, userdata, usr)
            payload = {
                self.user_property: uid,
                self.username_attribute: username,
                "user_id": uid,
                self.session_key_property: username,
                self.session_id_property: session.session_id,
            }
            token, exp, scheme = self._idp.create_token(data=payload)
            usr.access_token = token
            usr.token_type = scheme
            usr.expires_in = exp
            userdata["expires_in"] = exp
            userdata["token_type"] = scheme
            userdata["auth_method"] = "passkey"
            if user and self._callbacks:
                await self.auth_successful_callback(
                    request, user,
                    username_attribute=self.username_attribute,
                    userid_attribute=self.userid_attribute,
                    userdata=userdata,
                )
            return {"token": token, **userdata}
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(f"PasskeyAuth: Authentication Error: {err}")
            return False

    async def check_credentials(self, request):
        """Required by BaseAuthBackend; passkeys have nothing to re-check."""
        return True
```

### Browser side (login)

```javascript
const { challenge_id, publicKey } = await (
  await fetch("/api/v1/auth/passkey/login/options", { method: "POST" })
).json();

const credential = await navigator.credentials.get({
  publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey),
  // mediation: "conditional"  // autofill UI, needs autocomplete="username webauthn"
});

const res = await fetch("/api/v1/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Auth-Method": "PasskeyAuth",
  },
  body: JSON.stringify({ challenge_id, credential: credential.toJSON() }),
});
```

Enrollment is symmetric: `register/options`, then `navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })`, then `register/verify` with `{ credential: cred.toJSON(), label }`.

## Parallelism assessment

Three agents can work at once after a short serial P0 that fixes the storage contract; the only shared file with conflict risk is `backends/idp/__init__.py`.

| Stream | Scope | Depends on | Can run in parallel with |
| --- | --- | --- | --- |
| S0 (serial, first) | C1 settings, C2 DDL and `UserCredential` model, IdP helper signatures as stubs | Nothing | Nothing. Everything else imports from it. |
| S1 | C3 enrollment and C4 sign-in in `passkey.py`, with unit tests using a software authenticator | S0 | S2, S3 |
| S2 | IdP helper implementations against `authdb` and their tests | S0 | S1, S3 |
| S3 | C6 login page, conditional UI script, Playwright virtual authenticator test | S0 for the endpoint contract only | S1, S2 |
| S4 (serial, last) | C5 management endpoints, E13 rule, docs | S1, S2 | Nothing |

Conflict notes: S1 and S2 both touch the IdP helper call sites, so S0 must freeze the four method signatures. S3 can develop against a mocked `login/options` response. No stream edits `auth.py`.

## Open questions

- [ ] Q1. RP ID scope: one registrable domain for all Navigator deployments, or per-tenant RP IDs? This decides whether `PASSKEY_RP_ID` is a single value or resolved per request.
- [ ] Q2. User handle: `str(user_id)` bytes are stable and non-PII but guessable. Is a random per-user handle column worth the extra lookup?
- [ ] Q3. Where do credential helpers live: on `IdentityProvider` (consistent with `get_user`) or in a separate `CredentialStorage` class like the OAuth2 `PostgresClientStorage`?
- [ ] Q4. Counter regression (E7): reject only, or also disable the credential and notify the user?
- [ ] Q5. Should `auth_method = "passkey"` be exposed to ABAC (`EvalContext`) so policies can require phishing-resistant login for sensitive resources?
- [ ] Q6. Does a passkey login satisfy future MFA requirements on its own (user verification = possession + biometric or PIN), or is a step-up still wanted for some scopes?
- [ ] Q7. Dependency packaging: hard dependency on `webauthn`, or optional extra `navigator-auth[passkey]` with a lazy import?
- [ ] Q8. Minimum Redis version in production. `GETDEL` needs 6.2; otherwise use a Lua script or `MULTI` for single-use challenges.
- [ ] Q9. Username-first mode: needed at all, or is usernameless plus conditional UI sufficient for the target clients?
- [ ] Q10. Should enrollment require a recent re-authentication (for example, password within the last 5 minutes) rather than any live session?
