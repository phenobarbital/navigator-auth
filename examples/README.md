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
