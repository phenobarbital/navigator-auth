# Feature Proposal: External Token Exchange (Provider Bearer → Basic Session)

**Date**: 2026-09-04
**Author**: Jesus Lara
**Status**: discussion
**Feature ID (reserved)**: FEAT-096
**Depends on**: Identity Vault / identity-link flow (landed: `IdentityStore`,
`auth.user_identities` credential columns, `/api/v1/user/identities/{provider}/credential`),
FEAT-095 (`oauth2-for-mcp-agents`, landed — provider backends already expose
`identity_scopes()`, `get_identity_userid()`, `build_user_info()`).

---

## Why

Today a client that already holds a valid bearer token from Azure, Google or
GitHub (a mobile app, a desktop tool, a partner front-end that ran the
provider's login itself) cannot turn that token into a navigator-auth session
without replaying the whole browser redirect flow. The only existing shortcut,
`AzureAuth.check_credentials`, is Azure-only, does not verify that the token was
minted for *our* application, opens the session as `auth_method: "azure"`, and
Google/GitHub have no equivalent at all (their `check_credentials` is a stub).

We want one uniform, safe operation: **present a provider bearer token, get back
an internal session that looks and behaves exactly like a Basic-auth login**, so
every downstream consumer (middlewares, PBAC, callbacks, session storage, the
frontend) keeps working unchanged while the external credential is kept in the
identity vault for later use.

## What Changes

A client can call the login endpoint with a new auth method, supplying the
provider name and its bearer token. navigator-auth:

1. Verifies the token *with the provider* and confirms it was issued to this
   deployment's client id (audience check). Tokens for other applications are
   rejected.
2. Resolves the provider identity to an **existing** `auth.users` row — first
   through a previously linked identity (`user_identities.provider_user_id`),
   then by verified e-mail. Unknown users are refused. This flow **never
   creates accounts**, regardless of `AUTH_MISSING_ACCOUNT`.
3. Opens a session through the same recipe `BasicAuth` uses (user mapping,
   `BasicUser` identity, `remember()`, internal JWT + refresh token, Basic
   success callbacks). The session and JWT carry
   `auth_method: "basic"` **and** `auth_origin: "<provider>"` so audit and
   logout paths can still tell the two apart.
4. Caps the internal session/JWT lifetime at the external token's `expires_at`
   (when the provider reports one). The internal session never outlives the
   credential it was exchanged from.
5. Stores the external token **only in the identity vault** (ciphered in
   `auth.user_identities`, same path as identity-link). The raw token is not
   written into the Redis session. The frontend obtains it on demand through
   the already-existing `GET /api/v1/user/identities/{provider}/credential`
   endpoint (which handles caching and refresh).
6. Returns the same response shape as a Basic login (`token`, `refresh_token`,
   `expires_in`, `type`, user data).

Explicitly **not** changing: the interactive redirect logins, the identity-link
flow, `AUTH_MISSING_ACCOUNT` semantics for other backends, the Basic backend's
own password behaviour, session storage format.

## Capabilities

### New Capabilities
- `external-token-exchange`: login backend (`X-Auth-Method: TokenExchange`)
  that validates a provider bearer token (audience-bound), maps it to an
  existing user, and opens a Basic-equivalent session tagged with
  `auth_origin`, with lifetime capped to the external token.
- `provider-token-verification`: per-provider "verify this bearer token and
  give me userinfo + normalized `TokenResponse`" capability on the external
  backends (Azure: JWKS signature + `aud`/`iss`/`exp` then Graph `/me`;
  Google: id_token JWKS or `tokeninfo` with `aud`/`azp` check and
  `email_verified`; GitHub: `POST /applications/{client_id}/token` check then
  verified primary e-mail).
- `identity-lookup-by-provider-user`: `IdentityStore` lookup by
  `(auth_provider, provider_user_id)` → `user_id`, used to resolve linked
  accounts before falling back to e-mail.

### Modified Capabilities
- `basic-auth-session`: the tail of `BasicAuth.authenticate` (build userdata →
  remember → create token → callbacks) is factored into a reusable
  `open_session()` accepting extra session fields and an expiration override.
  Behaviour for password logins is unchanged.
- `identity-vault`: `save_linked_identity` is also invoked by the exchange
  flow (not only by identity-link and the OAuth2 AS proxy). No schema change.

## Impact

- **End users / clients**: new way to log in; existing logins untouched.
  Response payload identical to Basic login plus `auth_origin`.
- **API**: new auth method on `POST /api/v1/login` (header
  `X-Auth-Method: TokenExchange`, JSON body `{provider, token, token_type?,
  id_token?}`). No new endpoint for credential retrieval — reuse
  `/api/v1/user/identities/{provider}/credential`.
- **Session / JWT**: two additive claims `auth_origin` and (when capped)
  a shorter `exp`. Consumers that read `auth_method` see `"basic"`.
- **Backends touched**: `basic.py` (refactor), `external.py` (abstract
  verify method), `azure.py`, `google.py`, `github.py` (implementations;
  Azure's current unaudited `check_credentials` should delegate to the new
  verifier), `identity/store.py` (new lookup), new `backends/exchange.py`.
- **Security**: audience binding is mandatory; opaque GitHub tokens are checked
  against our OAuth app; unverified e-mails are rejected; no auto-provisioning.
  Failed exchanges are logged with provider and reason for audit.
- **Dependencies**: none new (`msal`, PyJWT, `jwksutils` already present).
- **Breaking changes**: none.

## Open Questions

- Should `auth_origin` also be mirrored into `AUTH_SESSION_OBJECT` (the
  `session` sub-dict the frontend reads) or only at the top level of the
  session and the JWT? Proposal: both, it is cheap and avoids a second lookup.
- Session cap when the provider reports **no** expiry (GitHub classic OAuth
  tokens never expire): fall back to the normal `SESSION_TIMEOUT`, or to a
  dedicated shorter `TOKEN_EXCHANGE_MAX_TTL`? Proposal: dedicated setting,
  default equal to `SESSION_TIMEOUT`.
- When the caller presents both `id_token` and an access token (Azure/Google),
  verify the id_token for identity and vault the access token? Proposal: yes;
  the id_token is what proves audience, the access token is what is useful
  later.
- Should a successful exchange refresh `last_login` / fire the same
  `AUTH_SUCCESSFUL_CALLBACKS` as Basic? Proposal: yes, "as if Basic".

## Parallelism Potential

- **Per-provider verifiers** (Azure, Google, GitHub) are independent of each
  other and of the exchange backend once the abstract `verify_external_token`
  signature is fixed; they can run in three worktrees.
- **`IdentityStore` lookup** and the **`BasicAuth.open_session` refactor** are
  independent, small, and unblock the exchange backend.
- The **exchange backend + login wiring** depends on the three items above.
- No in-flight worktrees currently touch these files (FEAT-095 has landed).
