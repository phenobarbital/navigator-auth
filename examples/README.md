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

* `AuthHandler(enable_authdb=False)` — no PostgreSQL `authdb` pool.
* `DemoIdentityProvider` — an in-memory user directory replacing `auth.users`.
  Only the three database lookups are overridden; password hashing, token
  creation and token decoding are the real `IdentityProvider`.

OAuth2 clients likewise live in memory (`OAUTH2_CLIENT_STORAGE=memory`); the
production default is `postgres` (see `navigator_auth/backends/oauth2/ddl.sql`).

Everything else — code issuance and single use, PKCE verification, consent and
consent-skip, refresh-token rotation with reuse detection, revocation — is the
real implementation.

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
  tables are added by the library's own idempotent startup migrations.
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

## `oauth2_server.py` — OAuth2 client registrations reference

Registers the four demo clients (public, confidential, device, resource-server)
and prints the endpoint contracts for the 3LO, Device Grant (RFC 8628) and
Token Introspection (RFC 7662) flows. Use it as a reference for the raw
requests; use `oauth2_3lo_server.py` for a flow you can actually click through.

## Other examples

| File | What it shows |
|---|---|
| `policy_server.py` | ABAC policy server |
| `test_abac.py`, `test_policies.py` | ABAC policies and evaluation |
| `test_decorators.py`, `test_handler.py` | auth decorators and handlers |
