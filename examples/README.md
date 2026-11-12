# navigator-auth examples

## `oauth2_3lo_server.py` — end-to-end OAuth2 3LO (Authorization Code + PKCE)

A single aiohttp application that plays all three OAuth2 roles at once, so the
whole three-legged flow can be walked through in one browser tab:

| Role | What provides it |
|---|---|
| Authorization Server | `navigator_auth.backends.oauth2.Oauth2Provider` (`/oauth2/*`) |
| Client application | the SPA at `/` (`static/oauth2_3lo_app.html`) |
| Resource Server | `GET /api/v1/me`, protected with `@is_authenticated()` + `@user_session()` |

### Run it

```bash
mkdir -p env/dev && touch env/dev/.env   # navconfig needs this once
redis-server --daemonize yes             # sessions are stored in Redis
python examples/oauth2_3lo_server.py     # from the repository root
```

Open <http://localhost:5000/> and press **Start OAuth2 login**.
Demo credentials: `demo` / `demo123` (or `alice` / `alice123`).

> Run it from the repository root: the OAuth2 login and consent pages are
> rendered from `templates/oauth/`, which `TemplateParser` resolves relative to
> the project directory.

### What the page walks you through

1. **PKCE** — the SPA generates a `code_verifier` and its S256 `code_challenge`.
2. **Authorize** — the browser goes to `/oauth2/authorize`, which redirects to
   `/oauth2/login`, then to `/oauth2/consent`.
3. **Callback** — navigator-auth redirects back to `/callback?code=…&state=…`.
4. **Token** — the SPA `POST`s to `/oauth2/token` with the `code_verifier`, and
   gets an access token (a JWT), a refresh token and the granted scope.
5. **Resource** — it calls `GET /api/v1/me` with `Authorization: Bearer …`.

It also exercises `/oauth2/userinfo`, the `refresh_token` grant (with rotation)
and the consent grants API (`/api/v1/oauth2/grants`) — revoke the grant and the
next login asks for consent again.

### How an access token authenticates a request

navigator-auth resolves the current user from a **server-side session**, not
from the JWT alone. So when the OAuth2 provider issues a 3LO access token it
also creates (or reuses) the resource owner's session and puts `session_id` and
the user identity in the token claims. `AuthHandler.auth_middleware` then:

1. decodes the bearer JWT,
2. checks the token's `jti` was not revoked (RFC 7009),
3. loads the session the claims point at,
4. attaches the user to the request.

`@is_authenticated()` gates on that, and `@user_session()` injects the `session`
and `user` objects into the handler.

### Example-only shortcuts

Two things are stubbed so the example runs with nothing but Redis. **Drop both
in a real deployment.**

* `AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False)` — no PostgreSQL
  `authdb` pool, and the backends are pinned to `Oauth2Provider` (see below).
* `DemoIdentityProvider` — an in-memory user directory replacing `auth.users`.
  Only the three database lookups are overridden; password hashing, token
  creation and token decoding are the real `IdentityProvider`.

OAuth2 clients likewise live in memory (`OAUTH2_CLIENT_STORAGE=memory`); the
production default is `postgres` (apply the schema with `navauth self upgrade --set oauth2`).

Everything else — code issuance and single use, PKCE verification, consent and
consent-skip, refresh-token rotation with reuse detection, revocation — is the
real implementation.

### Why it pins its backends

`make_app()` constructs `AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False)`.

Two settings inherited from a full Navigator deployment could otherwise change
what this example does, so it pins both:

* **`AUTHENTICATION_BACKENDS` from `settings/settings.py`** — `navigator_auth.conf`
  ends with `from settings.settings import *`, so a local settings file in the
  working directory overrides the environment. It can enable `NoAuth`,
  `APIKeyAuth`, `AzureAuth` and others. `_BACKENDS` pins exactly
  `navigator_auth.backends.oauth2.Oauth2Provider`, whatever the settings say.
* **`AUTHORIZATION_BACKENDS` (`allow_hosts`, `allowed_ips`)** — `authz_backends=[]`
  turns authorization backends off. An inherited `allow_hosts` (`ALLOWED_HOSTS`
  defaults to `localhost*`) would otherwise let the browser's requests through
  without a session.

The example also checks the signing key at startup. `AUTH_SECRET_KEY` is read
through navconfig, and `env/.env` wins over the example's `os.environ.setdefault`.
If the key is shorter than 32 bytes, the example logs
`AUTH_SECRET_KEY is N bytes; use at least 32 bytes.` and continues. The key value
is never logged. To fix it, set `AUTH_SECRET_KEY` to at least 32 bytes in
`env/dev/.env`.

---

## `policy_server.py` — PBAC example

This example combines an `AuthHandler` login form with PDP and Guardian authorization. It loads the
default packs from `navigator_auth/abac/default_policies` through `YAMLStorage`, registers ten example
policies with `pdp.add_policy` (five `ResourcePolicy` policies and five classic `Policy`/`ObjectPolicy`
policies), and exposes the REST decision endpoint at `/api/v1/abac/check`.

### Run

PostgreSQL (used by `pgStorage` and `default_dsn`) and Redis must be available through your environment
or `env/dev/.env` configuration. From the repository root, run:

```bash
python examples/policy_server.py
```

Open <http://localhost:5000/>, log in, and visit `/dashboard/`. To query the decision endpoint directly:

```bash
curl -X POST http://localhost:5000/api/v1/abac/check \
    -H "Content-Type: application/json" \
    -d '{"user":"alice@acme.com","resource":"tool:jira_create","action":"tool:execute","groups":["engineering"]}'
```

### Troubleshooting

* **`428 "No Matching Policies were found, Deny access."`** — no policy covers the path. Register
  one with `pdp.add_policy(...)`; policies pushed straight into the evaluator are dropped by
  `reload_policies()`.
* **`ValueError` from `pdp.add_policy(...)`** — the policy cannot be enforced as written: an invalid
  resource pattern, a duplicate name, or a classic `context` / `conditions` / `scopes` restriction
  (rejected, never silently ignored). Express a username restriction with `subject=[...]`.
  Supported environment keys: `hour`, `dow` (`day_of_week` is accepted as an alias),
  `is_business_hours`, `is_weekend`, `day_segment`.
* **`InsecureKeyLengthWarning: The HMAC key is N bytes long`** or the startup WARNING
  `AUTH_SECRET_KEY is N bytes; HMAC keys should be at least 32 bytes` — set `AUTH_SECRET_KEY` and
  `AUTH_TOKEN_SECRET` / `PARTNER_KEY` to at least 32 bytes (see "Signing keys" in `docs/settings.rst`).
* **`Vault secret failed integrity check ... UnsupportedFormatError`** — a pre-v2 (v1) vault
  secret. Run `navauth self upgrade --set vault --set identity`, then run
  `navigator-vault migrate --dry-run`, then `navigator-vault migrate --run --backup-dir <dir>`.

---

## `identity_vault_server.py` — Identity Vault: login + linked credentials

The example for the Identity Vault (PR #582): one aiohttp app with an
`AuthHandler`, an HTML page that logs you in **every way navigator-auth
supports at once**, and the vault endpoints for linking, managing and *using*
external provider credentials.

| Step | What the page does |
|---|---|
| Sign in — Basic | `POST /api/v1/login` (`X-Auth-Method: BasicAuth`) against `auth.users` |
| Sign in — navigator-auth OAuth2 | Authorization Code + PKCE against this same app (`Oauth2Provider`) |
| Sign in — SSO | `GET /api/v1/auth/azure/`, `/api/v1/auth/odoo/`, … (`AzureAuth`, the new `OdooAuth`) |
| Link an identity | `GET /api/v1/user/identities/link/{provider}` — a *second* OAuth2 flow with `AzureAuth` / `GithubAuth` that only captures tokens |
| Manage | the `UserIdentitiesHandler` API (list / renew / delete) plus the bundled page at `/api/v1/user/identities/manage` |
| Use a credential | `GET /api/v1/demo/whoami/{provider}` calls Microsoft Graph / GitHub / Odoo server-side with the stored token |

> The vault endpoints are registered for you: `AuthHandler.setup(app)` calls
> `navigator_auth.handlers.setup_handlers`, which mounts
> `/api/v1/user/identities*`. The example prints that route table at startup.

### Run it

```bash
mkdir -p env/dev && touch env/dev/.env          # navconfig needs this once
cp examples/identity_vault.env.example env/dev/.env   # then fill it in
redis-server --daemonize yes                    # sessions + OAuth2 flow state
python examples/identity_vault_server.py        # from the repository root
```

Open <http://localhost:5000/>. The Basic form is pre-filled with the demo
account the example seeds (`demo` / `demo123`).

> Run it from the repository root: the OAuth2 login/consent pages and the
> identities management page are rendered from `templates/`, which
> `TemplateParser` resolves relative to the project directory.

### What it needs

* **PostgreSQL** — unlike `oauth2_3lo_server.py` this one cannot run
  storage-less: linked identities are rows in `auth.user_identities`. On
  startup the example applies `examples/sql/identity_vault_schema.sql`
  (minimal `auth.users` + `auth.user_identities`, plus the `demo` user) —
  set `EXAMPLE_BOOTSTRAP_DB=false` once your database already has the
  Navigator `auth` schema. The credential columns and the Session Vault
  tables are added by the example itself through `navigator_auth.migrations.upgrade`
  (startup no longer migrates).
* **Redis** — sessions and per-flow OAuth2 state.
* **`VAULT_MASTER_KEY_v1` + `VAULT_ACTIVE_KEY_ID`** — credentials are ciphered
  with the Session Vault master keys. Without them login and SSO keep working
  and every vault endpoint answers `501`; the example prints a ready-to-paste
  key at startup.
* **Provider credentials** — each external backend is enabled *only* when its
  client id is configured, so you can try the example with just GitHub, or just
  Azure, or none at all. Callback URL to register at every provider:
  `http://localhost:5000/auth/{provider}/callback/` — the **same** URL the
  login flow uses, because the link flow shares it (a single-use Redis record
  keyed by the OAuth2 `state` tells them apart).

### It shows an empty session with a "Log out" button

That symptom (never reaching the login form) means the endpoints answered
*without* a user. Two settings inherited from a full Navigator deployment can
cause it, and the example now shields itself from both by constructing
`AuthHandler(backends=_BACKENDS, authz_backends=[])`:

* **`AUTHENTICATION_BACKENDS` including `NoAuth`** — `navigator_auth.conf` ends
  with `from settings.settings import *`, so a `settings/settings.py` in the
  working directory overrides whatever the environment says. `NoAuth`
  authenticates *every* request as an anonymous guest.
* **`AUTHORIZATION_BACKENDS=allow_hosts,allowed_ips`** — an authorization
  backend lets a request *through* without authenticating it (`ALLOWED_HOSTS`
  defaults to `localhost*`, which matches the browser you run the example in),
  so protected handlers run with no session at all.

### Login vs. identity linking

They look alike and are not the same thing, which is the whole point of the
page: **login** ends in a Navigator session (and a user row); **linking** runs
while you are already logged in and ends in a ciphered credential row —
your session is untouched. Sign in with Basic, then link Azure and GitHub, and
`GET /api/v1/user/identities` shows two credentials owned by the `demo` user.

See [`documentation/identity-vault.md`](../documentation/identity-vault.md) for
the full API, provider notes and the encryption/rotation model.

---

## `passkey_server.py` — Passkey (WebAuthn) enrollment and sign-in

A one-page walk-through of the passkey life cycle against `BasicAuth` + `PasskeyAuth`:
sign in with a password, enroll a passkey, sign out, sign back in with the passkey alone,
then list, rename and delete it. Reference: `docs/passkey.rst`.

### Run it

```bash
pip install "navigator-auth[passkey]"    # py_webauthn
mkdir -p env/dev && touch env/dev/.env   # navconfig needs this once
redis-server --daemonize yes             # sessions and challenges (Redis 6.2+)
python examples/passkey_server.py        # from the repository root
```

Open <http://localhost:5000/> and sign in with `demo` / `demo123` (or `alice` / `alice123`).

> Use `localhost`, not `127.0.0.1`. The relying party is the exact origin
> `http://localhost:5000`, and browsers only allow WebAuthn over plain http on `localhost`.
> `EXAMPLE_HOST` / `EXAMPLE_PORT` change both the listener and the relying party.

No hardware key is needed: the platform authenticator (Touch ID, Windows Hello, a phone or a
password manager) works, and so does a virtual authenticator from Chrome DevTools
(*More tools → WebAuthn*).

### What the page walks you through

| Step | Request |
|---|---|
| Password sign-in | `POST /api/v1/login` with `X-Auth-Method: BasicAuth` |
| Enroll | `POST /api/v1/auth/passkey/register/options` → `navigator.credentials.create()` → `POST …/register/verify` |
| Manage | `GET` / `PATCH` / `DELETE /api/v1/auth/passkey/credentials[/{id}]` |
| Passkey sign-in | `POST /api/v1/auth/passkey/login/options` → `navigator.credentials.get()` → `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth` |
| Protected call | `GET /api/v1/me` — reports `auth_method`, `mfa` and `amr` from the token |

*Sign in with passkey* sends the username, so the server lists that user's credentials.
*Passkey, no username* sends none: `allowCredentials` is empty and the authenticator offers
the passkeys it holds for the site.

The page authenticates with the bearer token from the login response, which is why it sends
no `X-CSRF-Token`. A cookie-session client must send it on the enrollment and management
calls (see "Enrollment (CSRF)" in `docs/passkey.rst`). *Sign out* calls `/api/v1/logout`
and discards the token in the browser.

### Example-only shortcuts

The example runs with nothing but Redis. **Drop all of these in a real deployment.**

* `enable_authdb=False` and `DemoIdentityProvider` — no PostgreSQL; users come from memory.
* `MemoryPasskeyStore` replaces `PasskeyStore` (the `user_credentials` and
  `user_passkey_handles` tables, created by `navauth self upgrade`). Enrolled passkeys are
  forgotten when the server stops but stay on your authenticator: delete them from the page
  first, or remove the `localhost` entries from the authenticator afterwards.
* `_memory_transition` replaces `security_transition`, the `authdb` transaction that commits a
  credential change together with the MFA bookkeeping.
* `secure_cookies=False` — no session cookie; the bearer token is the only credential.

Like `oauth2_3lo_server.py`, the example pins what a local `settings/settings.py` could
otherwise change: the backend list (`backends=_BACKENDS`), the authorization backends
(`authz_backends=[]`) and the login callbacks (`AUTH_SUCCESSFUL_CALLBACKS` are switched off,
since they usually query the auth database).

Option generation, challenge storage and single use, attestation and assertion verification,
the origin / relying-party checks, the session and the JWT are the real implementation.

---

## `oauth2_server.py` — OAuth2 client registrations reference

Registers the four demo clients (public, confidential, device, resource-server)
and prints the endpoint contracts for the 3LO, Device Grant (RFC 8628) and
Token Introspection (RFC 7662) flows. Use it as a reference for the raw
requests; use `oauth2_3lo_server.py` for a flow you can actually click through.

### Browser walk-through (PKCE)

Start from the URL the example prints for the 3LO flow, `http://localhost:5000/login`.
The app pins `backends=[Oauth2Provider]` and `authz_backends=[]`, as the 3LO example
does, so every protected request needs a session.

1. **Authorize** — the index page (`examples/static/oauth2_index.html`) generates a
   random `code_verifier` and its S256 `code_challenge`, plus a random `state`. It
   keeps them in `sessionStorage` under `nav_oauth2_index_pkce`, then sends the
   browser to `/oauth2/authorize` with the challenge.
2. **Login and consent** — the browser goes through `/oauth2/login` and
   `/oauth2/consent`, as in the 3LO example.
3. **Callback** — the callback page (`examples/static/callback.html`) reads the
   stored values from `sessionStorage`, checks that the returned `state` matches the
   stored one, and removes the stored values.
4. **Token** — the callback page sends the `code_verifier` to `/oauth2/token` and
   gets the tokens back. The server checks the verifier against the challenge from
   step 1.

PKCE needs `crypto.subtle`, which browsers expose only in a secure context.
`http://localhost` counts as one, so the walk-through works there. A LAN address
such as `http://192.168.x.x:5000` does not; `crypto.subtle` is then undefined and
the page cannot generate the challenge. Use `localhost`, or serve the example over
HTTPS.

## Other examples

| File | What it shows |
|---|---|
| `policy_server.py` | ABAC policy server |
| `test_abac.py`, `test_policies.py` | ABAC policies and evaluation |
| `test_decorators.py`, `test_handler.py` | auth decorators and handlers |
