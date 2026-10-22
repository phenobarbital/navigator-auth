---
type: feature
base_branch: dev
---

# Feature Specification: Capture, vault and refresh the external provider credential

**Feature ID**: FEAT-103
**Date**: 2026-10-22
**Author**: Jesus Lara
**Status**: approved
**Target version**: 0.28.8

> **Inputs:** free-form problem report passed to `/sdd-spec` (no brainstorm or
> proposal exists for this slug — see §9). Every code reference below was
> re-read on `dev` at `6e0f67e` on 2026-10-22. The MSAL behaviour claims were
> verified against the **installed** `msal 1.38.0` source in `.venv`, not from
> memory. The 7-minute access-token lifetime was measured by decoding a real
> token taken from a live `session["auth_token"]` (see §6 Measurement
> evidence).

---

## 1. Motivation & Business Requirements

### Problem Statement

`AzureAuth` throws away two of the three credentials Microsoft Entra ID hands
it at login, and the one it does keep is dead within minutes.

**(a) The `id_token` and `refresh_token` are discarded even though they are
already in hand.** MSAL unconditionally adds the reserved scopes
`openid profile offline_access` to every request
(`.venv/.../msal/application.py:834`, `_decorate_scope`), so
`initiate_auth_code_flow` (`navigator_auth/backends/azure.py:208`) **already
asks Entra for a refresh token** — no scope change is needed. The dict
returned by `acquire_token_by_auth_code_flow` (`azure.py:243`) therefore
carries `id_token`, `id_token_claims` **and** `refresh_token`: neither
`_clean_up()` (`msal/application.py:155`, which only drops `refresh_in` and
`_`-prefixed keys) nor `Client._obtain_token()`
(`msal/oauth2cli/oauth2.py:865-895`, which pops `refresh_token` *only* for
`grant_type == "refresh_token"`, and only from the copy handed to the cache
callback) removes it on the `authorization_code` path. `auth_callback` reads
just `token_type`, `access_token` and `client_info` (`azure.py:255-259`) and
drops the rest on the floor.

**(b) The access token that *is* stored is a 7-minute credential living inside
a 100-hour session.** `ExternalAuth.build_user_info` puts the raw Graph access
token into the session as `auth_token` (`external.py:696`). A real token pulled
from a live session decoded to a **419-second** lifetime (§6). The session's
own `max_age` is `SESSION_TIMEOUT` = `360000` s (100 h,
`navigator-session/conf.py:24` — not overridden in `env/.env`). Nothing between
logins re-negotiates with Entra, so `session["auth_token"]` is expired for
≈99.9 % of the session's life, and every consumer that calls Graph with it
fails. Without a stored refresh token there is no way to renew it:
`navigator-auth` cannot lengthen the lifetime (it is set by the tenant), only
refresh the credential.

**(c) Secondary: a returning user's fresh `userdata` can be silently
discarded.** `AuthHandler.api_login` persists the login through
`self._session.storage.load_session(request, userdata, response=response)`
(`auth.py:494`). `RedisStorage.load_session`
(`navigator-session/storages/redis.py:111-178`) consults `userdata` **only** to
resolve a `session_id` and to seed `new_session` when Redis holds no payload;
when `conn.get("session:<id>")` returns data it builds
`SessionData(data=data, new=False)` from **the stored payload** and the fresh
`userdata` is dropped — there is no merge. Since `get_session_id`
(`redis.py:100`) resolves the id from `user:{identity}`, which lives the full
`max_age`, a returning user almost always hits that branch. The Azure redirect
flow happens to escape this because `remember()` (`abstract.py:290`) goes
through `new_session` (`redis.py:275`), which reuses the `session_id` but
**overwrites** the payload wholesale (`conn.set(_id_, dt, self.max_age)`).

**(d) Contract bug: `expires_in` is an absolute epoch, not a duration.**
`IdentityProvider.create_token` returns `exp = (iat + timedelta(...)).timestamp()`
(`backends/idp/__init__.py:407`) — an absolute, **float** UNIX timestamp — and
every caller publishes it to clients under the key `expires_in`, which RFC 6749
§4.2.2 defines as *seconds from now*. Measured on `dev`:
`expires_in = 1793050179.051082`. Affected publishers: `external.py:766` (the
Azure/OIDC path), `auth.py:437`, `auth.py:457`, `basic.py:261`, `troc.py:150`,
`noauth.py:76`.

**(e) Blocker: `IdentityStore` cannot write to `auth.user_identities` at all on
a deployment whose table predates the identity-vault model.** G2 routes the
refresh token through `IdentityStore.save_linked_identity`
(`identity/store.py:112`), which goes through the `UserIdentity` model
(`models.py:77`) and therefore requires `identity_id` as the primary key plus
the profile columns. The library's own migrations
(`identity/sql/001_identity_credentials.sql`, `002`, `003`, run by
`ensure_identity_columns`, `identity/migrations.py:46`) are additive and only
add **credential** columns; nothing reconciles the base table, and the
canonical DDL that does define it lives in `examples/sql/identity_vault_schema.sql:58`
— an example, not a migration. On the `navigator` dev database the table is an
older shape: primary key `(user_id, uid)`, no `identity_id`, no
`display_name` / `email` / `title` / `nickname` / `phone` / `short_bio` /
`avatar`. Measured, not inferred — see §6 "Identity-table drift evidence":
a real token exchange reached `save_linked_identity` and died with
`column "identity_id" does not exist`, while the login itself still succeeded
because the vault write is best-effort (`backends/exchange.py:188-194`).
**Consequence: the G2 acceptance criterion "`auth.user_identities` holds a row
for the user with non-null ciphered `refresh_token` and `id_token`" cannot pass
until the base table is reconciled.**

### Goals

- **G1** — Capture the provider `id_token`, `refresh_token` and real expiry
  during the login negotiation, generically for every `ExternalAuth` backend,
  with `AzureAuth` as the first consumer.
- **G2** — Persist the refresh token **ciphered** in `auth.user_identities`
  through the existing `IdentityStore`; never write it to the session in clear.
- **G3** — Expose the `id_token` and a real expiry in the session next to the
  existing `auth_method` / `auth_token`, plus a boolean marker saying a
  refresh token is available — so consumers can tell "renewable" from "dead".
- **G4** — Provide an **on-demand** refresh helper so a consumer holding an
  expired `auth_token` can obtain a live one without a full re-login. Without
  this, G1–G3 do not solve the operational problem in Problem Statement (b).
- **G5** — Make `expires_in` RFC-6749-conformant (integer seconds remaining)
  and publish the absolute instant under a separate, explicitly named key.
  Resolved §8 Q2: this extends to the dynamic `usr.expires_in` attribute as
  well, which gains a sibling `usr.expires_at`.
- **G6** — Stop leaking provider tokens through the `check_credentials` JSON
  response.
- **G7** — Split `AZURE_SESSION_TIMEOUT`'s two unrelated jobs into two settings
  (resolved §8 Q4), so the login-flow record's Redis TTL stops being a 5×
  outlier against every sibling flow TTL in `conf.py`.
- **G8** — Make `RedisStorage.load_session` merge the caller's fresh `userdata`
  into an existing session instead of discarding it (resolved §8 Q3). This is a
  change in the **`navigator-session`** distribution, in scope for this feature.

### Non-Goals (explicitly out of scope)

- Changing the Entra tenant's access-token lifetime policy. The 7-minute
  lifetime is set tenant-side (resolved §8 Q1 — a bounded experiment is in
  scope, a policy change is not); this feature renews the credential, it does
  not lengthen it.
- A middleware that proactively refreshes the provider token on **every**
  request. G4 is an on-demand helper called by consumers that need Graph, not
  a per-request hook.
- Any broader refactor of `navigator-session`'s storage layer. G8 is one
  additive, opt-in merge path in `RedisStorage.load_session` plus its patch
  release — not a redesign of session loading, and not the cookie or Postgres
  storages.
- Removing `max_age` from `initiate_auth_code_flow`. Q1's experiment measures
  its effect; changing the login's freshness requirement may be a deliberate
  security property and is a separate decision.
- Wiring `GoogleAuth` / `GithubAuth` / `OktaAuth` / `ADFSAuth` / `OdooAuth` to
  the new capture path. The generic mechanism lands here and they keep working
  unchanged; adopting it per-backend is follow-up work.

---

## 2. Architectural Design

### Overview

The negotiation already produces a complete OAuth2 grant; the fix is to stop
dropping it and to route each part to the store that fits its sensitivity.

1. **`AzureAuth.auth_callback` / `authenticate`** build a `TokenResponse` from
   the MSAL result instead of reading three keys out of it. The existing
   `_token_from_msal_result` (`azure.py:320`) must first be extended to copy
   `id_token` and prefer `result.get("refresh_token")`, falling back to the
   cache only when absent. It currently omits the ID token and reads the
   refresh token only from the cache. Both call
   sites pass a `msal.SerializableTokenCache` into `get_msal_app`
   (`azure.py:116`, which already accepts one) so `_refresh_token_from_cache`
   (`azure.py:304`) stays available as a belt-and-braces fallback for grants
   where the refresh token is not in the result dict.
2. **`ExternalAuth.build_user_info`** gains four optional keyword arguments
   (`id_token`, `refresh_token`, `expires_at`, `provider_user_id`). Optional is mandatory here: the
   method is called by **seven** backends (`adfs.py:171`, `azure.py:135`,
   `azure.py:223`, `azure.py:534`, `github.py:102`, `github.py:288`,
   `google.py:130`, `google.py:303`, `odoo.py:80`, `okta.py:87`,
   `saml/sp.py:190` — blast radius taken from `wiki_blast_radius`), and every
   one of them must keep working untouched.
3. **Session** receives `id_token`, `external_expires_at` (ISO-8601) and
   `has_refresh_token: bool` and `external_provider_user_id`. The latter is
   derived from verified provider userinfo, not request parameters. The raw refresh token is **never** placed in the
   session — it goes only to the ciphered store. The key names deliberately
   avoid `refresh_token`, which is already taken by **Navigator's own** refresh
   token (`external.py:766`) and is indexed in Redis under
   `auth:refresh_token:<tok>` for 90 days by `auth.py:505-513`; reusing that
   key would corrupt Navigator's refresh-token index.
4. **Vault**: `ExternalAuth._vault_upstream_token` (`external.py:454`) is
   generalized to accept an explicit `TokenResponse` (today it reconstructs a
   partial one from the session, carrying `access_token` only) and is invoked
   from the normal callback path, not only from the OAuth2-AS resume at
   `external.py:440`. It writes through `IdentityStore.save_linked_identity`
   (`identity/store.py:112`), which already seals `access_token`,
   `refresh_token` and `id_token` independently. The Session Vault
   (`cache_credential`, `store.py:360`) is **not** usable here: it is loaded
   only in `api_login` (`auth.py:518`) and `/auth/<provider>/callback/` routes
   straight to the backend (`external.py:139-145`), so a `cache_credential`
   call on that path is a silent no-op.
5. **Refresh on demand**: a new `ExternalAuth.get_live_provider_token()` reads
   the exact enabled credential matching the session's local user, provider
   and `external_provider_user_id`. It must not use the newest-account
   selection in `IdentityStore.get_by_provider`. When `TokenResponse.is_expiring(leeway)`
   (`identity/types.py:32`) is true it calls a new credential-aware
   `refresh_provider_tokens(token)` hook, persists the rotated credential
   via `IdentityStore.update_tokens` (`store.py:261`) and refreshes the
   session's `auth_token` / `external_expires_at`.
   The Azure hook requests the stored grant scopes, excluding MSAL-reserved
   `openid`, `profile`, `offline_access`; it must not substitute
   `AZURE_IDENTITY_SCOPES` (default `User.Read`). If the original result omits
   scopes, capture the requested login scopes (`https://graph.microsoft.com/.default`
   for the callback, `User.ReadBasic.All` for ROPC). If refresh omits scopes,
   retain the requested scopes. An explicitly reduced permission grant must
   return None without replacing the session credential; `.default` is a
   request selector, so compare explicit granted permissions where available,
   not the selector string against returned permissions.
6. **`expires_in`**: `create_token` keeps returning the absolute `exp` (its
   4-tuple contract is depended on by `basic.py:231`, `auth.py:428`,
   `oauth2/backend.py:1855,1946,2050`), but the **publishers** convert:
   `expires_in = int(exp - now)` and a new `expires_at` carries the absolute
   instant.

### Component Diagram

```
Entra ID ──auth code──► AzureAuth.auth_callback
                              │
                              │ MSAL result (access + id + refresh + expires_in)
                              ▼
                     _token_from_msal_result ──► TokenResponse
                              │                      (azure.py:320, reused)
            ┌─────────────────┼──────────────────────┐
            ▼                 ▼                      ▼
   build_user_info      _vault_upstream_token   home_redirect
   (+id_token,          (TokenResponse)         (unchanged)
    +external_          │
    expires_at,         ▼
    +has_refresh    IdentityStore.save_linked_identity
    _token)         → auth.user_identities (ciphered, store.py:112)
            │
            ▼
   remember() ──► new_session() ──► Redis session
   (abstract.py:290)  (redis.py:275, overwrites)
                              │
                              │ later, token already expired
                              ▼
                  get_live_provider_token()  ◄── consumer needing Graph
                              │
                              ├─ IdentityStore.get_for_provider_account (new, exact account)
                              ├─ is_expiring? ─► refresh_provider_tokens (new, grant scopes)
                              └─ IdentityStore.update_tokens (store.py:261)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `ExternalAuth.build_user_info` (`external.py:668`) | extends (additive kwargs) | 7 backends call it; signature must stay backward-compatible |
| `ExternalAuth._vault_upstream_token` (`external.py:454`) | modifies | accepts an explicit `TokenResponse`; called from the normal callback too |
| `AzureAuth._token_from_msal_result` (`azure.py:320`) | extends | capture ID token and result refresh token with cache fallback |
| `IdentityStore.get_for_provider_account` (new) | adds | exact enabled credential lookup by local user, provider and external account |
| `ExternalAuth.refresh_provider_tokens` (new) | adds | credential-aware hook; Azure preserves grant scopes |
| `AzureAuth._refresh_token_from_cache` (`azure.py:304`) | reuses + docstring fix | its claim that MSAL never returns the RT holds only for `acquire_token_silent` |
| `IdentityStore.save_linked_identity` (`store.py:112`) | uses | already seals access/refresh/id tokens separately |
| `IdentityStore.update_tokens` (`store.py:261`) | uses | rotation path after a refresh |
| `TokenResponse` (`identity/types.py:8`) | uses | `is_expiring()`, `credential()`, `from_credential()` all already exist |
| `AuthHandler.api_login` (`auth.py:494`) | documents | `load_session` discards fresh `userdata` when a session exists — §8 Q3 |
| `IdentityProvider.create_token` (`idp/__init__.py:379`) | unchanged | the 4-tuple contract stays; publishers convert |

### Data Models

No new model. `TokenResponse` (`identity/types.py:8`) already carries every
field this feature needs — `access_token`, `token_type`, `refresh_token`,
`id_token`, `expires_in`, `expires_at`, `scopes`, `provider_user_id`, `raw` —
and `UserIdentity` (`navigator_auth/models.py`) already has the three ciphered
token columns plus `expires_at`, `scopes` and `key_version`.

New session keys (plain `dict` entries, written by `build_user_info`):

```python
userdata["auth_method"]          # str  — EXISTING (external.py:694)
userdata["auth_token"]           # str  — EXISTING (external.py:696), provider access token
userdata["token_type"]           # str  — EXISTING (external.py:697)
userdata["id_token"]             # Optional[str]  — NEW, provider OIDC id_token
userdata["external_expires_at"]  # Optional[str]  — NEW, ISO-8601; key name already
                                 #   used by exchange.py:206-209, reused for consistency
userdata["has_refresh_token"]    # bool — NEW; presence marker only, NEVER the token
userdata["external_provider_user_id"]  # Optional[str] — verified login account binding
```

### New Public Interfaces

```python
# navigator_auth/backends/external.py

class ExternalAuth(BaseAuthBackend):

    def build_user_info(                      # verified: external.py:668
        self,
        userdata: dict,
        token: str,
        mapping: dict,
        *,
        id_token: Optional[str] = None,       # new, keyword-only
        refresh_token: Optional[str] = None,  # new, keyword-only — presence only
        expires_at: Optional[datetime] = None,  # new, keyword-only
        provider_user_id: Optional[str] = None,  # new, keyword-only
    ) -> tuple:
        """Build session user info from a provider payload.

        The four new keyword arguments are additive and default to None so
        that the seven existing call sites keep their current behaviour.
        ``refresh_token`` is used ONLY to set ``has_refresh_token``; the
        secret itself is never written into ``userdata``.
        """

    async def _vault_upstream_token(          # verified: external.py:454 (signature changes)
        self,
        request: web.Request,
        *,
        token: Optional["TokenResponse"] = None,
    ) -> None:
        """Cipher the upstream provider credential into auth.user_identities.

        When ``token`` is None the previous behaviour is kept: a partial
        TokenResponse is rebuilt from the session (access token only). Callers
        on the login path now pass the full grant. Best-effort — a vault
        failure must never break the login (unchanged contract).
        """

    async def get_live_provider_token(        # new
        self,
        request: web.Request,
        user_id: Any,
        *,
        leeway: int = IDENTITY_REFRESH_LEEWAY,   # verified: conf.py:545
    ) -> Optional["TokenResponse"]:
        """Return a non-expired provider credential, refreshing if needed.

        Requires user_id to match the authenticated session's local user and
        auth_method to match this backend. Reads the exact enabled credential
        for (user_id, self._service_name, session["external_provider_user_id"]),
        and when ``TokenResponse.is_expiring(leeway)`` is true calls
        ``self.refresh_provider_tokens(token)``, persists the rotated credential
        and updates ``session["auth_token"]`` / ``["external_expires_at"]``.

        Returns None for a missing/mismatched account binding, missing credential,
        or a required refresh that cannot complete. A fresh access token remains
        usable without a refresh token. Never fall back to another linked account.
        """

    async def refresh_provider_tokens(self, token: "TokenResponse") -> "TokenResponse":
        """Refresh a login grant; default delegates to refresh_identity_tokens.

        Azure overrides this hook to preserve the captured grant scopes.
        Existing identity-link refresh interfaces remain backward-compatible.
        """
```

```python
# navigator_auth/backends/azure.py

class AzureAuth(ExternalAuth):

    @staticmethod
    def _token_from_msal_result(              # azure.py:319-336 — body MUST change
        result: dict, cache: msal.SerializableTokenCache
    ) -> TokenResponse: ...

    async def auth_callback(self, request: web.Request):   # verified: azure.py:223
        """Now builds a TokenResponse via _token_from_msal_result and passes
        id_token / refresh_token / expires_at down to build_user_info, and the
        full grant to _vault_upstream_token."""
```

```python
# navigator_auth/libs/... (helper, exact module decided in Module 5)

def expiry_fields(exp: float) -> dict:
    """Map an absolute epoch `exp` to the published expiry pair.

    Returns ``{"expires_in": int(exp - time.time()), "expires_at": int(exp)}``
    — `expires_in` as RFC 6749 §4.2.2 seconds-remaining, never below 0.
    """
```

---

## 3. Module Breakdown

### Module 0: Reconcile the `auth.user_identities` base schema *(prerequisite)*
- **Path**: `navigator_auth/identity/sql/004_identity_base_columns.sql` (new),
  `navigator_auth/identity/migrations.py`,
  `examples/sql/identity_vault_schema.sql`
- **Responsibility**: bring a legacy `auth.user_identities` up to the shape the
  `UserIdentity` model (`models.py:77`) requires, so `IdentityStore` can write
  at all. Additive and idempotent like its three predecessors:
  `ADD COLUMN IF NOT EXISTS identity_id UUID DEFAULT gen_random_uuid()` plus
  the profile columns (`display_name`, `title`, `nickname`, `email`, `phone`,
  `short_bio`, `avatar`), then promote `identity_id` to primary key **only
  when** the existing primary key is not already `identity_id`. The legacy
  `(user_id, uid)` primary key and the `uid` column are left in place — the
  model ignores `uid`, and dropping a column in a migration that also runs on
  healthy databases is the riskier choice. Register `004` in
  `_MIGRATION_FILES` (`identity/migrations.py:21`).
- **Why it lives here**: this is not a separate feature. G2 is unreachable
  without it, and the evidence that it is broken came from exercising G2's own
  write path (§1 (e), §6).
- **Guardrail**: the migration must be a no-op on a database already created
  from `examples/sql/identity_vault_schema.sql`. Prove it by running it twice
  against both shapes (legacy and canonical) in the test fixture.
- **Note on `ON CONFLICT`**: neither the legacy table nor the canonical DDL has
  a **unique** index on `(user_id, auth_provider)` — only the non-unique
  `idx_user_identities_user`. Any upsert targeting that pair fails with
  SQLSTATE 42P10. `IdentityStore` does not do this; external callers that do
  (see §8 Q5) must be fixed on their side, not by adding a constraint that
  would forbid a user holding two accounts on one provider.
- **Depends on**: nothing. Everything else in this spec depends on it.

### Module 1: Additive capture in `ExternalAuth`
- **Path**: `navigator_auth/backends/external.py`
- **Responsibility**: keyword-only `id_token` / `refresh_token` / `expires_at`
  plus `provider_user_id` on `build_user_info` (`:668`); write the four new session keys only
  when the new capture arguments are supplied; never write
  the refresh token itself.
- **Depends on**: nothing in this spec.

### Module 2: Generalized vaulting
- **Path**: `navigator_auth/backends/external.py`, `navigator_auth/identity/store.py`
- **Responsibility**: `_vault_upstream_token` (`:454`) accepts an explicit
  `TokenResponse` and is called from the normal callback path; keep the
  session-reconstruction fallback and the best-effort contract.
  Add `get_for_provider_account(user_id, provider, provider_user_id)`, returning
  only the exact enabled credential-bearing row, or None. Keep the existing
  `get_by_provider` semantics for unrelated consumers. Before vaulting a login,
  populate `token.provider_user_id` using `get_identity_userid` on the verified
  userinfo and pass that same value into `build_user_info`. Missing account IDs
  disable capture/refresh with a warning; never persist an unbound login grant.
  Vault only after successful local authentication and session creation, using
  the session's local user ID. For a captured login, the OAuth2-AS resume must
  skip the old partial re-save so it cannot overwrite expiry/scopes or create
  a second row under a different account ID. Legacy, uncaptured paths retain
  the existing fallback.
- **Depends on**: Module 1.

### Module 3: `AzureAuth` wiring
- **Path**: `navigator_auth/backends/azure.py`
- **Responsibility**: pass a `SerializableTokenCache` to `get_msal_app`
  (`:116`) in `auth_callback` (`:223`) and in the user/password branch of
  `authenticate` (`:135-176`); build the `TokenResponse` via the existing
  `_token_from_msal_result` (`:320`); feed Modules 1 and 2; fix the
  `_refresh_token_from_cache` docstring (`:304-306`).
  Extend the normalizer to populate `id_token` and prefer the result refresh
  token before the cache fallback. Supply verified userinfo account IDs and
  the actual requested scopes when the result omits scopes on both login paths.
  The ROPC path currently uses `get_msal_client`; explicitly add cache support
  there or route it through the cache-aware factory without changing its grant.
- **Depends on**: Modules 1, 2.

### Module 4: On-demand refresh (`get_live_provider_token`)
- **Path**: `navigator_auth/backends/external.py`, `navigator_auth/backends/azure.py`
- **Responsibility**: exact account lookup → `is_expiring` → `refresh_provider_tokens` →
  `update_tokens` → update the session. Uses `IDENTITY_REFRESH_LEEWAY`
  (`conf.py:545`, default 120).
  Implement the generic hook and Azure override described in §2. Validate the
  authenticated user/provider/account binding before reading or changing any
  credential. Never select another account because it was linked/refreshed
  more recently. Missing legacy bindings require re-login rather than guessing.
- **Depends on**: Modules 2, 3.

### Module 5: `expires_in` / `expires_at` contract
- **Path**: published dicts — `navigator_auth/backends/external.py:766`,
  `navigator_auth/auth.py:437`, `navigator_auth/auth.py:457`,
  `navigator_auth/backends/basic.py:261`, `navigator_auth/backends/troc.py:150`,
  `navigator_auth/backends/noauth.py:76`; user-object attribute —
  `navigator_auth/backends/basic.py:259`, `navigator_auth/backends/troc.py:148`,
  `navigator_auth/backends/noauth.py:69`, `navigator_auth/backends/token.py:144`
- **Responsibility**: `expires_in` becomes `int` seconds-remaining; new
  `expires_at` carries the absolute epoch. `create_token` itself is untouched.
- **This is not a new convention — it is the repo's existing one.** The OAuth2
  provider backend already does exactly this under a named decision: *"B1:
  expires_in is seconds (int)"* (`backends/oauth2/backend.py:9`, with
  `expires_in = int(exp_abs - now_utc.timestamp())` at `:1863`, `:1953` and
  `:2056`, and the inline note *"B1: expires_in is seconds (not an absolute
  timestamp)"* at `:1861`). Module 5 extends **B1** to the legacy login
  publishers that never received it. This is what resolves §8 Q2 — it was never
  a product decision, it was an inconsistency.
- **Resolved §8 Q2 — scope includes the user-object attribute**: `usr.expires_in`
  also becomes seconds-remaining and gains a sibling `usr.expires_at` carrying
  the absolute epoch. Note the risk this accepts: `expires_in` is **not**
  declared on `Identity`/`AuthUser` (`identities.py` declares `access_token` at
  `:164` but no `expires_in`), so it is a dynamic attribute with no contract,
  and it reaches consumers through `save_encoded_data(request, "user", user)`
  (`abstract.py:304`). Anything reading `request.user.expires_in` as a timestamp
  breaks. Called out in `CHANGELOG.md` alongside the response change.
- **Depends on**: nothing functionally; coordinate shared-file edits with 1-4.

### Module 6: Stop leaking provider tokens in `check_credentials`
- **Path**: `navigator_auth/backends/azure.py:585`, and the two mirrors
  `navigator_auth/backends/github.py:314`, `navigator_auth/backends/google.py:333`
- **Responsibility**: redact `auth_token`, `id_token` (and never include a
  refresh token) from the `sessioninfo` JSON. `mask_value`
  (`identity/types.py:93`) already exists for exactly this.
- **Depends on**: Module 1.

### Module 8: Split `AZURE_SESSION_TIMEOUT` into two settings *(resolved §8 Q4)*
- **Path**: `navigator_auth/conf.py:430`, `navigator_auth/backends/azure.py:212`,
  `navigator_auth/backends/azure.py:217`
- **Responsibility**: one setting currently serves two unrelated jobs — AAD's
  OIDC `max_age` (`azure.py:212`) and the Redis TTL of the login-flow record
  (`azure.py:217`). Introduce `AZURE_FLOW_TTL = config.getint("AZURE_FLOW_TTL",
  fallback=600)` for the `setex`, and convert `AZURE_SESSION_TIMEOUT` to
  `config.getint` (it is `config.get` today, i.e. a **string**, which is why
  `azure.py:212` has to wrap it in `int()`), leaving it as the `max_age` value
  only.
- **Why 600**: every sibling flow-record TTL in `conf.py` is 600 —
  `AUTH_CODE_EXPIRATION` (`:350`), `SAML_FLOW_TTL` (`:506`),
  `IDENTITY_LINK_TTL` (`:543`), `OAUTH_CODE_TTL` (`:726`),
  `OAUTH_DEVICE_CODE_TTL` (`:785`), `OAUTH_UPSTREAM_FLOW_TTL` (`:854`);
  `PASSKEY_CHALLENGE_TTL` (`:590`) is 300. At 120 s the Azure login flow is a
  5× outlier: a user who lingers on the Microsoft login screen loses the flow
  record and gets *"Lost Authentication Flow, please try again"*.
- **Out of scope here**: removing `max_age` altogether (see Non-Goals). Module 8
  only stops the two concerns sharing one knob; it does **not** change the
  freshness requirement the login currently asserts.
- **Unblocks**: the §8 Q1 experiment, which needs `max_age` adjustable
  independently of the flow TTL.
- **Depends on**: nothing. Coordinate `azure.py` edits with Module 3.

### Module 9: `load_session` merges fresh `userdata` *(resolved §8 Q3 — second repo)*
- **Repo**: **`navigator-session`** (`/home/jesuslara/proyectos/navigator-session`,
  currently `1.1.0`), *not* this one.
- **Path**: `navigator_session/storages/redis.py:111-206`
  (`RedisStorage.load_session`), `navigator_session/version.py`
- **Responsibility**: when Redis already holds a payload, `load_session` builds
  `SessionData(data=data, new=False)` from the **stored** payload and silently
  discards the caller's `userdata` — there is no merge (`redis.py:163-206`).
  Add an opt-in merge so a caller passing fresh `userdata` updates the live
  session instead of being ignored. Additive and opt-in: the default path must
  stay byte-identical, because this storage is shared by every consumer of
  `navigator-session`, not just `navigator-auth`.
- **Honest scope note**: this fixes a real latent defect, but it is **not** the
  cause of the stale `auth_token` in §1 (b). `load_session` has exactly **one**
  caller in `navigator-auth` (`auth.py:494`), and every backend that reaches it
  has already written the session through `remember()` → `new_session()`
  (`api.py`, `token.py`, `troc.py`, `basic.py`, `django.py`; `passkey.py` and
  `exchange.py` delegate to `basic.open_session`), which **overwrites** the
  payload wholesale (`redis.py:311`). So today the discard re-reads *fresh*
  data. The user chose to fix it anyway rather than only pin it with a test.
- **Release mechanics** (this is why it is its own module): `navigator-auth`
  declares `navigator-session>=1.1.0` (`pyproject.toml:52`) but overrides it
  with an **editable path** source (`pyproject.toml:142`,
  `navigator-session = { path = "../navigator-session", editable = true }`).
  Local development therefore picks the change up immediately and *masks* the
  pin — so the task MUST also bump `navigator_session.__version__` to `1.1.1`
  and raise the floor in `pyproject.toml:52` to `>=1.1.1`, or CI and production
  silently keep the old behaviour.
- **Depends on**: nothing in this repo. Lands before or in parallel with
  Modules 1-8; Module 7's regression test asserts the navigator-auth-side
  expectation either way.

### Module 7: Tests
- **Path**: `tests/unit/identity/test_external_token_capture.py` (new),
  `tests/test_azure_token_verifier.py` (extend); for Module 9, the test lives
  in the `navigator-session` repo next to its storage tests
- **Responsibility**: §4.
- **Depends on**: Modules 0-6, 8, 9.

### Delegation-eligible modules

| Module | Delegation-eligible | Why / decided contract |
|---|---|---|
| 0 | no | promoting a primary key on a live table is a judgement call, and the no-op guarantee must be reasoned about |
| 1 | yes | signature and the exact four key names are fixed above |
| 2 | yes | signature fixed; behaviour is "pass the token through instead of rebuilding it" |
| 3 | no | needs judgement on the ROPC branch of `authenticate` and on error paths |
| 4 | no | the refresh/rotate/persist ordering and failure semantics are design decisions |
| 5 | yes | mechanical; the 10 call sites, the B1 precedent and the helper contract are listed |
| 6 | yes | mechanical redaction at 3 listed sites using the existing `mask_value` |
| 7 | no | test design follows from the above |
| 8 | yes | mechanical; the new setting, its fallback, and both call sites are fixed above |
| 9 | no | second repo, shared by other consumers, and the default path must stay byte-identical |

---

## 4. Test Specification

### Unit Tests — `tests/unit/identity/test_external_token_capture.py`

| Test | Module | Description |
|---|---|---|
| `test_build_user_info_without_new_kwargs_is_unchanged` | 1 | Calling with the old 3-arg signature produces byte-identical `userdata` to today's output — guards the 7 existing call sites |
| `test_build_user_info_sets_id_token_and_expiry` | 1 | `id_token` and `external_expires_at` (ISO-8601) land in `userdata` |
| `test_build_user_info_never_writes_refresh_token` | 1 | Passing `refresh_token="secret"` sets `has_refresh_token is True` and `"secret"` appears in **no** value of `userdata` |
| `test_navigator_refresh_token_key_not_clobbered` | 1 | After `validate_user_info`, `userdata["refresh_token"]` is still Navigator's own token (guards the `auth.py:505` Redis index) |
| `test_vault_upstream_token_uses_passed_tokenresponse` | 2 | `save_linked_identity` receives the refresh token and id_token, not a session-rebuilt partial |
| `test_vault_upstream_token_failure_does_not_raise` | 2 | A raising `IdentityStore` is swallowed and logged (contract preserved) |
| `test_get_live_provider_token_returns_cached_when_fresh` | 4 | No `refresh_identity_tokens` call when `is_expiring(leeway)` is False |
| `test_get_live_provider_token_refreshes_when_expiring` | 4 | Expiring credential triggers refresh, `update_tokens` persists it, session `auth_token` updated |
| `test_get_live_provider_token_without_refresh_token_returns_none` | 4 | Expired credential without a refresh token returns None rather than raising; a fresh credential is still returned |
| `test_capture_binds_verified_provider_account` | 2, 3 | Callback and ROPC save the verified userinfo account ID and the same session binding; missing ID does not create an unbound row |
| `test_refresh_uses_login_account_not_newest_link` | 2, 4 | Log in as account A, link/refresh account B more recently, expire A: only A is read, refreshed and written to the session |
| `test_refresh_rejects_missing_or_mismatched_binding` | 4 | Missing/deleted/disabled account, wrong local user or wrong auth_method returns None without provider calls or session mutation |
| `test_oauth2_resume_preserves_captured_grant` | 2 | Callback followed by AS resume preserves the exact row, scopes, expiry and tokens without a partial second save |
| `test_expires_in_is_seconds_remaining` | 5 | `0 < expires_in <= SESSION_TIMEOUT` and `isinstance(expires_in, int)` |
| `test_expires_at_is_absolute_epoch` | 5 | `expires_at` ≈ `now + expires_in` (±2 s) |
| `test_user_object_expires_in_is_seconds` | 5 | `usr.expires_in` is `int` seconds-remaining and `usr.expires_at` carries the epoch, at all four set sites (`basic.py:259`, `troc.py:148`, `noauth.py:69`, `token.py:144`) |
| `test_expires_in_matches_oauth2_b1_convention` | 5 | The legacy login publishers and `oauth2/backend.py`'s B1 path produce the same shape for the same `exp` — pins the convention instead of re-deriving it |
| `test_azure_flow_ttl_is_independent_of_max_age` | 8 | `setex` on `azure_auth_<state>` uses `AZURE_FLOW_TTL` (600) while `initiate_auth_code_flow` still receives `max_age=AZURE_SESSION_TIMEOUT`; the two move independently |
| `test_azure_session_timeout_is_int` | 8 | `AZURE_SESSION_TIMEOUT` is an `int` from `conf.py`, so `azure.py` no longer needs the `int()` wrapper |
| `test_check_credentials_redacts_provider_tokens` | 6 | The JSON body contains neither the raw access token nor the id_token |

### Unit Tests — `tests/test_azure_token_verifier.py` (extend)

| Test | Module | Description |
|---|---|---|
| `test_auth_callback_captures_refresh_and_id_token` | 3 | A stubbed MSAL result containing `refresh_token` + `id_token` reaches `build_user_info` and `_vault_upstream_token` |
| `test_auth_callback_refresh_token_from_cache_fallback` | 3 | Result **without** `refresh_token` falls back to `_refresh_token_from_cache` |
| `test_msal_normalizer_captures_id_and_prefers_result_refresh` | 3 | ID token is copied; when result and cache have different refresh tokens, the result wins |
| `test_azure_login_refresh_preserves_grant_scopes` | 3, 4 | Login grant includes User.Read and Mail.Read; refresh requests both despite identity scopes being User.Read; reserved scopes are excluded |
| `test_azure_missing_scope_fallback` | 3, 4 | Callback and ROPC capture their respective requested scopes when omitted; refresh uses those scopes and retains them if its response omits scope |
| `test_azure_refresh_reduced_grant_is_not_published` | 4 | Refresh explicitly removes Mail.Read from a previously explicit grant: helper returns None and does not replace session auth_token |
| `test_check_credentials_audience_bound_regression` | — | EXISTING (`tests/test_azure_token_verifier.py:241`) must still pass |

### Tests in the `navigator-session` repo (Module 9)

| Test | Module | Description |
|---|---|---|
| `test_load_session_merges_fresh_userdata` | 9 | With a payload already in Redis, the opt-in merge updates the named keys from `userdata` instead of discarding them |
| `test_load_session_default_path_is_unchanged` | 9 | Without the opt-in flag, the returned `SessionData` is byte-identical to `1.1.0`'s — the regression guard for every other consumer of this storage |
| `test_load_session_no_payload_still_seeds_new_session` | 9 | The `data is None` + `new=True` branch (`redis.py:170-172`) keeps delegating to `new_session` |

### Regression test pinning the navigator-auth-side reliance (Module 7)

| Test | Module | Description |
|---|---|---|
| `test_api_login_session_is_written_by_remember_not_load_session` | 7 | Pins the actual invariant found during investigation: the session is created/refreshed by the backend's `remember()` → `new_session()`, and `auth.py:494`'s `load_session` only re-reads it. Keeps the §1 (c) behaviour from silently regressing whichever way Module 9 lands |

### Test Data / Fixtures

```python
@pytest.fixture
def msal_result_full():
    """An MSAL authorization_code result shaped like msal 1.38.0 returns it."""
    return {
        "token_type": "Bearer",
        "access_token": "AT.graph",
        "id_token": "ID.jwt",
        "refresh_token": "RT.secret",      # present on the auth-code grant
        "expires_in": 419,                 # measured lifetime, see §6
        "scope": "User.Read Mail.Read",
        "id_token_claims": {"oid": "4e2aa0ea-...", "tid": "af176793-..."},
    }
```

---

## 5. Acceptance Criteria

- [ ] Module 0 first: on a database with the legacy `(user_id, uid)` table,
      `ensure_identity_columns` makes `IdentityStore.save_linked_identity`
      succeed; running it a second time, and running it against a database
      built from `examples/sql/identity_vault_schema.sql`, are both no-ops
      (§1 (e), Module 0)
- [ ] `pytest tests/unit/identity/test_external_token_capture.py -v` passes
- [ ] `pytest tests/test_azure_token_verifier.py -v` passes (including the
      pre-existing `test_check_credentials_audience_bound_regression`)
- [ ] `pytest tests/ -v` shows no new failures versus the `dev` baseline
- [ ] `build_user_info` called with its old 3-argument signature produces
      output identical to `dev` — verified by test, not by inspection (G1)
- [ ] After an Azure login, `auth.user_identities` holds a row for the user
      with non-null ciphered `refresh_token` and `id_token` (G2)
- [ ] The raw provider refresh token appears in **no** session value and in
      **no** HTTP response body (G2, G6)
- [ ] `session["id_token"]`, `session["external_expires_at"]` and
      `session["has_refresh_token"]` are present after an Azure login (G3)
- [ ] `get_live_provider_token` returns a live credential for a session whose
      `auth_token` has expired, without a re-login (G4)
- [ ] Captured MSAL grants contain the returned ID token and prefer the returned
      refresh token over the cache fallback (G1, G2).
- [ ] Login refresh preserves the grant's requested permissions instead of
      substituting identity-link defaults; missing and reduced scopes are
      handled as specified in §2 (G4).
- [ ] Session and stored credential share a verified external account binding;
      refresh cannot switch accounts when another linked account is newer (G4).
- [ ] OAuth2-AS resume does not overwrite the newly captured full grant (G2, G4).
- [ ] `session["refresh_token"]`, where present, is still **Navigator's** token
      and `auth:refresh_token:<tok>` in Redis still resolves to the user id (G2)
- [ ] `expires_in` in every login/refresh/token response is an `int` of
      seconds remaining; `expires_at` carries the absolute epoch (G5)
- [ ] `usr.expires_in` is seconds remaining and `usr.expires_at` carries the
      epoch, at all four set sites; `CHANGELOG.md` records both the response
      and the attribute change as client-visible (G5, §8 Q2)
- [ ] `AZURE_FLOW_TTL` (`getint`, default 600) governs the Redis TTL of the
      login-flow record, and `AZURE_SESSION_TIMEOUT` is an `int` used only as
      `max_age` (G7, §8 Q4)
- [ ] The §8 Q1 experiment has been run and its outcome recorded in §7 as a
      one-line note — either `max_age` affects the Graph token's lifetime, or
      the 7 minutes are tenant policy (§8 Q1)
- [ ] `navigator-session`'s `load_session` merges fresh `userdata` on the
      opt-in path and is byte-identical to `1.1.0` on the default path;
      `navigator_session.__version__ == "1.1.1"` and this repo's
      `pyproject.toml:52` floor reads `>=1.1.1` (G8, §8 Q3)
- [ ] `pytest` passes in the `navigator-session` repo too, not only here (G8)
- [ ] `ruff check navigator_auth/` and `mypy` clean on the changed files
- [ ] No breaking change to the `create_token` 4-tuple contract
- [ ] `docs/` updated: the new session keys, `get_live_provider_token`, and the
      `expires_in` / `expires_at` change (the last one noted as client-visible)

---

## 6. Codebase Contract

### Measurement evidence (2026-10-22, `dev` @ `6e0f67e`)

A real access token taken from a live `session["auth_token"]` decoded to:

```
aud        https://graph.microsoft.com     ← a Graph access token, NOT a Navigator JWT
appid      bbc8ff0c-f3f5-4294-a692-f90e17f3782a   (navigator-auth)
ver        1.0        amr  ["fido", "mfa"]
acrs       ["p1", "pfdr"]      xms_pftexp  iat + 25.5 h
iat        1792689808  (2026-10-22T17:23:28Z)
exp        1792690227  (2026-10-22T17:30:27Z)
lifetime   419 s = 7.0 min
```

A Navigator JWT minted through `IdentityProvider.create_token` on the same
tree, for comparison:

```
session_timeout  360000 s (100 h)
exp              1793050179.051082   ← absolute epoch, FLOAT, published as "expires_in"
payload          {'exp': 1793050179.05, 'iat': 1792690179, 'iss': 'Mobileinsight', 'jti': ...}
```

MSAL version in `.venv`: `msal 1.38.0`.

### Identity-table drift evidence (2026-10-22, `navigator` dev DB)

Collected by driving a real Azure access token through
`TokenExchangeAuth` against a throwaway aiohttp app with `AzureAuth` +
`TokenExchangeAuth` loaded (the exchange reaches the same
`IdentityStore.save_linked_identity` that G2 uses). The login returned
`HTTP 200` for `user_id=35`; the vault write did not survive:

```
TokenExchange: vault write failed provider=azure user_id=35:
  Error on get user_identities: Error: Model GET over auth.user_identities:
  column "identity_id" does not exist
TokenExchange: success provider=azure user_id=35 cap=89
```

`auth.user_identities` as it exists on that database:

```
columns     user_id, uid, auth_provider, auth_data, attributes, created_at,
            provider_user_id, scopes, access_token, refresh_token, token_type,
            expires_at, refreshed_at, enabled, key_version, id_token
pk          pk_auth_user_identities_pkey  PRIMARY KEY (user_id, uid)
indexes     idx_user_identities_user              (user_id, auth_provider)        non-unique
            uq_user_identities_provider_account   (user_id, auth_provider,
                                                   provider_user_id) WHERE provider_user_id IS NOT NULL
missing     identity_id, display_name, email, title, nickname, phone,
            short_bio, avatar
```

So the credential columns from migrations `001`-`003` are all present — it is
exactly the base columns, defined only in `examples/sql/identity_vault_schema.sql:58-72`,
that were never applied.

### Existing symbols (verified)

```python
# navigator_auth/backends/external.py
class ExternalAuth(BaseAuthBackend):                                   # verified: :80
    def configure(self, app):                                          # verified: :114
        #   /api/v1/auth/<svc>/            -> self.authenticate        # verified: :119-124
        #   /auth/<svc>/callback/          -> self._auth_callback_dispatch  # verified: :139-145
        #   /auth/<svc>/check_credentials  -> self.check_credentials    # verified: :160-167
    async def _auth_callback_dispatch(self, request):                  # verified: :368
    async def _resume_oauth2_authorize(self, ...):                     # verified: :419
        await self._vault_upstream_token(request)                      # verified: :440  (ONLY call site today)
    async def _vault_upstream_token(self, request) -> None:            # verified: :454
        access_token = session.get("auth_token")                       # verified: :471
        token = TokenResponse(access_token=..., token_type=..., provider_user_id=...)  # verified: :480-484
        store = IdentityStore(request.app["authdb"])                   # verified: :485
        await store.save_linked_identity(user_id, self._service_name, token, {})  # verified: :486-488
    async def refresh_identity_tokens(self, ...):                      # verified: :576
    async def finish_identity_link(self, request, flow):               # verified: :611
    def build_user_info(self, userdata, token, mapping) -> tuple:      # verified: :668
        userdata["auth_method"] = self._service_name                   # verified: :694
        userdata["auth_token"] = token                                 # verified: :696
        userdata["token_type"] = self.scheme                           # verified: :697
    async def validate_user_info(self, request, user_id, userdata, token) -> dict:  # verified: :700
        session = await self.remember(request, user_id, userinfo, user)             # verified: :755
        token, refresh_token, exp, scheme = self._idp.create_token(data=payload)    # verified: :765
        return {"token": ..., "refresh_token": refresh_token, "type": scheme,
                "expires_in": exp, **userdata}                                      # verified: :766

# navigator_auth/backends/azure.py
class AzureAuth(ExternalAuth):                                         # verified: :75
    def get_msal_app(self, token_cache: msal.SerializableTokenCache = None):  # verified: :116
    async def authenticate(self, request):                             # verified: :135
        Default_SCOPE = ["User.ReadBasic.All"]                         # verified: :146
        result = app.acquire_token_by_username_password(...)           # verified: :156
        SCOPE = ["https://graph.microsoft.com/.default"]                # verified: :205
        flow = app.initiate_auth_code_flow(..., max_age=int(AZURE_SESSION_TIMEOUT))  # verified: :208-213
        await redis.setex(f"azure_auth_{state}", AZURE_SESSION_TIMEOUT, ...)         # verified: :217
    async def auth_callback(self, request):                            # verified: :223
        result = app.acquire_token_by_auth_code_flow(...)              # verified: :243
        token_type = result["token_type"]                              # verified: :255
        access_token = result["access_token"]                          # verified: :256
    @staticmethod
    def _refresh_token_from_cache(cache) -> Optional[str]:             # verified: :303-317
    @staticmethod
    def _token_from_msal_result(result, cache) -> TokenResponse:       # verified: :319-336
    async def refresh_identity_tokens(self, refresh_token) -> TokenResponse:  # verified: :375
    async def check_credentials(self, request):                        # verified: :534
        sessioninfo = {**data, **userdata}                             # verified: :585  (LEAK)
        return JSONResponse(sessioninfo, status=200)                   # verified: :586

# navigator_auth/identity/types.py
@dataclass
class TokenResponse:                                                   # verified: :8
    access_token: str; token_type: str = "Bearer"
    refresh_token: Optional[str] = None; id_token: Optional[str] = None
    expires_in: Optional[int] = None; expires_at: Optional[datetime] = None
    scopes: list; provider_user_id: Optional[str] = None; raw: dict     # verified: :16-24
    def is_expiring(self, leeway: int = 0) -> bool:                    # verified: :32
    def credential(self) -> dict:                                      # verified: :39
    @classmethod
    def from_credential(cls, data: dict) -> "TokenResponse":           # verified: :54
def mask_value(value: Any) -> Optional[str]:                           # verified: :93

# navigator_auth/identity/store.py
class IdentityStore:                                                   # verified: :49
    async def save_linked_identity(self, user_id, provider, token, userinfo=None):  # verified: :112
        # seals access_token / refresh_token / id_token separately     # verified: :132-138
    async def get_by_provider(self, ...):                              # verified: :222
    async def update_tokens(self, ...):                                # verified: :261
    def decrypt_credential(self, identity) -> TokenResponse:           # verified: :280
    def masked(self, identity) -> dict:                                # verified: :301
async def cache_credential(session, provider, credential) -> None:     # verified: :360

# navigator_auth/backends/idp/__init__.py
class IdentityProvider:
    session_timeout: int = int(SESSION_TIMEOUT)                        # verified: :49
    def create_ephemeral_token(self, data=None, expiration: int = 1800):  # verified: :310
    def create_token(self, data=None, issuer=None, expiration=None, audience=None) -> tuple:  # verified: :379
        exp = (iat + timedelta(seconds=expiration)).timestamp()        # verified: :407  (ABSOLUTE, float)
        return jwt_token, refresh_token, exp, self.scheme              # verified: :436

# navigator_auth/auth.py
await self._session.storage.load_session(request, userdata, response=response)  # verified: :494
refresh_token = userdata.get("refresh_token")                          # verified: :505-509
await redis.setex(f"auth:refresh_token:{refresh_token}", 7776000, str(user_id))  # verified: :512
vault = await load_vault_for_session(...)                              # verified: :518-526

# navigator_auth/conf.py
AZURE_TRUSTED_APPIDS = [...]                                           # verified: :367
AZURE_MAPPING = azure_mapping                                          # verified: :395
AZURE_SESSION_TIMEOUT = config.get("AZURE_SESSION_TIMEOUT", fallback=120)  # verified: :430
IDENTITY_LINK_TTL = config.getint("IDENTITY_LINK_TTL", fallback=600)   # verified: :543
IDENTITY_CACHE_TTL = config.getint("IDENTITY_CACHE_TTL", fallback=3600)  # verified: :544
IDENTITY_REFRESH_LEEWAY = config.getint("IDENTITY_REFRESH_LEEWAY", fallback=120)  # verified: :545
AZURE_IDENTITY_SCOPES = [...]  # fallback "User.Read"                  # verified: :548
```

### Verified third-party behaviour (`msal 1.38.0`, in `.venv`)

```python
# msal/application.py
def _decorate_scope(self, scopes,
        reserved_scope=frozenset(['openid', 'profile', 'offline_access'])):  # verified: :832-834
    decorated = scope_set | reserved_scope                                   # verified: :851
    # => offline_access is ALWAYS requested; no scope change needed for a refresh token
def _clean_up(result):                                                       # verified: :155
    return_value = {k: result[k] for k in result
                    if k != "refresh_in" and not k.startswith('_')}          # verified: :162-166
    # => id_token / id_token_claims / refresh_token all SURVIVE

# msal/oauth2cli/oauth2.py
def _obtain_token(self, grant_type, ...):                                    # verified: :865
    if grant_type == RT and RT in _resp and not also_save_rt:
        _resp.pop(RT, None)                                                  # verified: :876-879
    return resp   # the ORIGINAL resp, unmodified                            # verified: :895
    # => refresh_token is popped only from the cache-callback copy, and only
    #    for grant_type == "refresh_token"; the authorization_code result keeps it

# msal/oauth2cli/oidc.py
def obtain_token_by_auth_code_flow(self, auth_code_flow, auth_response, **kwargs):  # verified: :290
    if auth_code_flow.get("max_age") is not None:                            # verified: :310
        skew = 120
        if now - skew > auth_time + auth_code_flow["max_age"]:
            raise RuntimeError("13. auth_time ... too much time has elapsed")  # verified: :315-328
```

### Verified `navigator-session` behaviour (`/home/jesuslara/proyectos/navigator-session`)

```python
# navigator_session/conf.py
SESSION_TIMEOUT = config.getint('SESSION_TIMEOUT', fallback=360000)      # verified: :24
SESSION_KEY = config.get('SESSION_KEY', fallback='id')                   # verified: :43
SESSION_ID = config.get('SESSION_ID', fallback='session_id')             # verified: :44

# navigator_session/storages/redis.py
async def get_session_id(self, conn, identity) -> str:                   # verified: :100
    session_id = await conn.get(f"user:{identity}")                      # verified: :103
async def load_session(self, request, userdata=None, response=None,
                       new=False, ignore_cookie=True) -> SessionData:    # verified: :111
    session_id = userdata.get(SESSION_ID, None) if userdata else None    # verified: :149
    if not session_id: session_id = await self.get_session_id(conn, session_identity)  # verified: :154
    data = await conn.get(_id_)                                          # verified: :163
    if data is None and new is True: return await self.new_session(request, userdata)  # verified: :170-172
    session = SessionData(id=session_id, identity=..., data=data, new=False, ...)      # verified: :200-206
    # => when Redis HAS data, `userdata` is DISCARDED — no merge. See §8 Q3.
async def new_session(self, request, data=None, response=None):          # verified: :275
    session_id = await self.get_session_id(conn, session_identity)       # verified: :295  (reuses the id)
    result = await conn.set(_id_, dt, self.max_age)                      # verified: :311-313  (OVERWRITES)

# navigator_session/middleware.py
if session.is_changed: await storage.save_session(request, response, session)  # verified: :45-57

# navigator_auth/backends/abstract.py
session_key_property: str = SESSION_KEY                                  # verified: :71
async def remember(self, request, identity, userdata, user):             # verified: :290
    session = await new_session(request, userdata)                       # verified: :299
```

### Blast radius of `build_user_info` (`wiki_blast_radius`, depth 2)

Callers that MUST keep working with the unchanged 3-arg signature:
`adfs.py:171`, `azure.py:135`, `azure.py:223`, `azure.py:534`, `github.py:102`,
`github.py:288`, `google.py:130`, `google.py:303`, `odoo.py:80`, `okta.py:87`,
`saml/sp.py:190`. Tests touching it: `tests/test_azure_token_verifier.py:241`,
`tests/test_github_token_verifier.py:131,145`,
`tests/test_google_token_verifier.py:231,246`,
`tests/unit/identity/test_{github,google,odoo,okta}_backend.py`.

### Does NOT exist (do not reference)

- **No** `ExternalAuth.get_live_provider_token` — created by Module 4.
- **No** `expires_at` key in any login response today; only the misnamed
  `expires_in`.
- **No** `id_token`, `external_expires_at` or `has_refresh_token` key in the
  session on the Azure login path. (`external_expires_at` *does* exist, but only
  in the token-exchange `extra` dict, `exchange.py:206-209`, and in
  `basic.py:152`'s `_JWT_EXTRA_KEYS` — reuse that name, do not invent another.)
- **No** `AZURE_REFRESH_SCOPES` / `AZURE_OFFLINE_ACCESS` setting, and none is
  needed — MSAL adds `offline_access` itself.
- **No** vault available on the `/auth/<provider>/callback/` path:
  `load_vault_for_session` is called only at `auth.py:518`, so
  `cache_credential` (`store.py:360`) would be a silent no-op there.
- **No** sync-down GitHub Action in this repo despite `CLAUDE.md`'s claim —
  after a merge to `main`, fast-forward `dev` by hand.
- **No** `parrot/` directory — `CLAUDE.md` and `.agent/CONTEXT.md` describe
  **ai-parrot**, a different project. This repo's package root is
  `navigator_auth/`, and the template's `parrot/...` paths do not apply.

---

## 7. Implementation Notes & Constraints

### Patterns to Follow

- `uv` only, and `source .venv/bin/activate` before any python command.
- Google-style docstrings + strict type hints on every new function.
- `async`/`await` throughout; `aiohttp`, never `requests`/`httpx`.
- `self.logger` — never `print`. Never log a token value; use `mask_value`
  (`identity/types.py:93`).
- Vault/identity writes stay **best-effort**: a failure logs a warning and must
  never break authentication (the contract already stated at
  `external.py:489-492` and `vault/integration.py:11-13`).
- New keyword arguments are **keyword-only** (`*`) so positional call sites
  cannot drift.

### Known Risks / Gotchas

- **`refresh_token` key collision.** `validate_user_info` returns Navigator's
  own refresh token under that key (`external.py:766`) and `auth.py:505-513`
  indexes it in Redis for 90 days. Writing the provider's refresh token there
  would corrupt Navigator's refresh flow. Mitigation: the provider's secret
  never enters `userdata`; only `has_refresh_token`. There is a dedicated
  acceptance criterion and test for this.
- **`expires_in` is a client-visible contract change.** Clients currently
  receiving an absolute epoch will receive seconds. They are already broken
  (nothing can correctly consume a value whose name promises a duration), but
  the change is observable. Mitigation: ship `expires_at` alongside, and call
  it out in `docs/` and `CHANGELOG.md`. See §8 Q2.
- **A session can outlive the provider token by ~850×** (100 h vs 7 min). Even
  with Module 4, a consumer that reads `session["auth_token"]` *directly*
  instead of calling `get_live_provider_token` still gets a dead token.
  Mitigation: document it; consider deprecating direct reads in follow-up.
- **MSAL enforces `max_age` on the callback.** With
  `AZURE_SESSION_TIMEOUT=120` and MSAL's hardcoded 120 s skew
  (`oauth2cli/oidc.py:316`), a user who lingers on the Microsoft login screen
  gets a `RuntimeError`; and the flow record in Redis (`azure.py:217`) is gone
  after the same 120 s. Not introduced by this feature. Module 8 fixes the
  second half (the flow TTL); the `max_age` half stays deliberately, see
  Non-Goals and §8 Q4.
- **The 7-minute lifetime has no verified cause** (§8 Q1). Module 8 makes
  `max_age` independently adjustable so the experiment can run, but the
  outcome is unknown: if it is tenant policy, every Graph-using session will
  refresh roughly every 5 minutes at `IDENTITY_REFRESH_LEEWAY=120`. Watch for
  AAD throttling and refresh-token rotation churn under load; the leeway is
  operator-tunable precisely so this can be backed off without a release.
- **`usr.expires_in` is an undeclared, dynamic attribute** (§8 Q2 scope
  extension). `identities.py` declares `access_token` (`:164`) but no
  `expires_in`, so there is no contract to version. It is set at
  `basic.py:259`, `troc.py:148`, `noauth.py:69` and `token.py:144` and reaches
  consumers via `save_encoded_data(request, "user", user)` (`abstract.py:304`).
  Changing it from an absolute epoch to seconds-remaining breaks any consumer
  reading `request.user.expires_in` as a timestamp — accepted by the user;
  mitigation is the additive `usr.expires_at` plus a `CHANGELOG.md` entry.
- **Module 9 crosses a distribution boundary.** The editable path source
  (`pyproject.toml:142`) means a `navigator-session` change is live locally
  **without** any version bump, which masks the `>=1.1.0` floor
  (`pyproject.toml:52`). Forgetting the bump therefore fails *silently* — green
  locally, old behaviour in CI and production. The version bump and the floor
  raise are part of Module 9's definition of done, not follow-up.
- **Non-integer `user_id`.** `load_vault_for_session` skips vault loading when
  `user_id` is not an int (`vault/integration.py:74-84`); `IdentityStore` keys
  on `user_id` too. Backends that put a username in `user_id` will not get a
  vaulted credential — fail soft, log, do not raise.
- **`IdentityCipher` requires key configuration.** `IdentityStore.__init__`
  builds one eagerly (`store.py:52-58`) and it raises `ConfigError` when keys
  are missing (see the `ConfigError` catch at `passkey.py:578`). Guard the new
  call sites the same way.
- **Shared `.venv` across worktrees.** It is editable-installed against the
  main checkout; `navigator-session` is also a local editable path
  (`/home/jesuslara/proyectos/navigator-session`). Never `uv sync` inside a
  worktree.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| `msal` | `1.38.0` (installed) | already a dependency; relied on for `offline_access` + the auth-code result shape |
| `navigator-session` | `>=1.1.0` → **`>=1.1.1`** | **MODIFIED by Module 9.** Declared at `pyproject.toml:52`, overridden by an editable path source at `pyproject.toml:142`; installed version is `1.1.0`. Module 9 edits `storages/redis.py`, bumps `__version__` to `1.1.1` and raises the floor |
| `pyjwt` | installed | already used by `_verify_jwt` (`external.py:827`) |
| — | — | **No new dependency is required.** |

---

## 8. Open Questions

- [x] **Q1** — Why does this tenant issue 7-minute Graph access tokens when
      Microsoft documents 60-90 min? — *Resolved by the user, 2026-10-22*:
      **run a bounded experiment, then record the result; do not chase a policy
      change.** The cause is not determinable from code (`pfdr` and
      `xms_pftexp` are not documented in Microsoft's published claims
      reference), and the decision Q1 was supposed to gate — Module 4's
      leeway — is settled independently: keep `IDENTITY_REFRESH_LEEWAY`
      (`conf.py:545`, default 120 s), already operator-configurable. With
      7-minute tokens that means a Graph-using session refreshes roughly every
      5 minutes; if Q1's experiment shows a longer lifetime is attainable, the
      leeway needs no change either way.

      **The experiment** (needs Module 8, which makes `max_age` adjustable on
      its own): raise or remove `max_age` at `azure.py:212`, log in, pull
      `session["auth_token"]`, and decode `exp - iat`. If the lifetime changes,
      Q1 and Q4 share one cause and `max_age` is the lever; if it does not, the
      7 minutes are tenant policy. **Unverified hypothesis**, recorded as such:
      `max_age` is an OIDC *freshness* request and the token carries exactly
      freshness claims (`acrs: ["p1","pfdr"]`, `xms_pftexp` = `iat` + 25.5 h) —
      suggestive, not evidence. Either outcome is a one-line note in §7; neither
      blocks a module. → §7 Known Risks, Module 8.
- [x] **Q2** — Should `expires_in` change in place or be deprecated over a
      release? — *Resolved, 2026-10-22, by in-repo precedent rather than by
      preference*: **change it in place.** This was never an open product
      decision — `backends/oauth2/backend.py` already publishes
      `expires_in = int(exp_abs - now_utc.timestamp())` under a named decision
      *"B1: expires_in is seconds (int)"* (`:9`, `:1861-1863`, `:1953`,
      `:2056`). The legacy login publishers are simply inconsistent with B1.
      Module 5 extends B1 to them, plus an additive `expires_at`.
      **Scope extended by the user**: the dynamic `usr.expires_in` attribute
      changes too, gaining `usr.expires_at` — accepting that it is undeclared
      on `Identity` and that consumers reading it as a timestamp will break.
      → Module 5, §5, §7 Known Risks.
- [x] **Q3** — `RedisStorage.load_session` discards the fresh `userdata`
      whenever Redis already holds a session (`redis.py:163-206`). — *Resolved
      by the user, 2026-10-22*: **fix it in `navigator-session` in this cycle**,
      not merely pin it with a regression test. Recorded plainly: the
      investigation showed this is **not** the cause of the stale `auth_token`
      (one caller, `auth.py:494`, and every backend reaching it already
      overwrote the session via `remember()` → `new_session()`), so this is a
      latent-defect fix taken on its own merits, and it carries a second
      distribution plus a version bump into FEAT-103. → Module 9 (G8),
      §7 External Dependencies, Worktree Strategy.
- [x] **Q4** — `AZURE_SESSION_TIMEOUT` (fallback 120 s, `conf.py:430`) serves
      two unrelated purposes. — *Resolved by the user, 2026-10-22*: **split it
      inside this spec** as Module 8 — new `AZURE_FLOW_TTL` (`getint`, 600, to
      match every sibling flow TTL) for the Redis record, and
      `AZURE_SESSION_TIMEOUT` converted to `getint` and left as `max_age` only.
      Removing `max_age` was explicitly **not** chosen; it stays a Non-Goal
      because the freshness requirement may be deliberate. → Module 8 (G7).
- [ ] **Q5** — Which `auth.user_identities` shape is authoritative in
      **production**? Only the `navigator` dev database was inspected (§6).
      If production already carries `identity_id`, Module 0 is a dev-only
      repair and its no-op path is the one that runs there. Separately:
      `ai-parrot`'s `IdentityMappingService`
      (`ai-parrot/packages/ai-parrot-server/src/parrot/services/identity_mapping.py`)
      writes this same table with `ON CONFLICT (user_id, auth_provider)` and
      selects `identity_id, display_name, email` — it fails against **both**
      shapes (42P10 on the conflict target). Owner of that fix is the
      ai-parrot side, not this spec; recorded here so the two repos do not
      diverge on one table.
      — *Owner: Jesus Lara*
- [x] **Where does the provider refresh token live?** — *Resolved by the user,
      2026-10-22*: ciphered in `auth.user_identities` via
      `IdentityStore.save_linked_identity`; the session holds only the
      `id_token`, the expiry and a presence marker. Never the refresh token in
      clear. → §2 items 3-4, Modules 1-2, acceptance criteria.
- [x] **Azure-only or generic?** — *Resolved by the user, 2026-10-22*: generic
      in `ExternalAuth`, with `AzureAuth` as the first consumer; the other
      backends keep working unchanged. → §2 items 2 and 4, Modules 1-3,
      Non-Goals.
- [x] **One spec or two?** — *Resolved by the user, 2026-10-22*: the
      `expires_in` contract bug ships in **this** spec, not a separate hotfix.
      → Module 5.

---

## 9. Design Research Cross-Check

**Model**: —
**Status**: skipped (no accepted exploration document — this spec was scaffolded
from a free-form problem report, and the `/sdd-spec` §3b design-research seat
runs only over an *accepted* brainstorm/proposal, never over a spec draft)

| Suggestion | Disposition | Reason | Landed in |
|---|---|---|---|
| — | — | — | — |

### Adversarial review of the draft (separate seat, recorded for auditability)

A `codex` review of the **spec draft** produced revision 0.2. That is a
different seat from §3b above and does not change its `skipped` status, but
`CLAUDE.md` requires every substantive reviewer finding to carry an explicit
disposition and none to be silently dropped. Each claim below was
**independently re-verified against the source before adoption** — not taken on
the reviewer's word:

| Finding (rev 0.2) | Disposition | Evidence re-checked |
|---|---|---|
| `_token_from_msal_result` does not capture `id_token` and reads the refresh token only from the cache — the 0.1 draft wrongly called its body "UNCHANGED" | **CONFIRM** | `azure.py:329-336`: the `TokenResponse(...)` call has no `id_token=` argument and passes `refresh_token=AzureAuth._refresh_token_from_cache(cache)`. The 0.1 draft was in error |
| `IdentityStore.get_by_provider` picks the **newest** linked account, so refresh can silently switch accounts | **CONFIRM** | `store.py:222-247`: the docstring reads *"The newest enabled credential-bearing identity for a provider"* and the body sorts by `refreshed_at`/`created_at` descending, returning `rows[0]` |
| Azure's `refresh_identity_tokens` would downgrade a login grant to `AZURE_IDENTITY_SCOPES` (default `User.Read`) | **CONFIRM** | `azure.py:375-384` calls `acquire_token_by_refresh_token(..., scopes=self.identity_scopes())`, and `identity_scopes()` (`azure.py:293-297`) returns `AZURE_IDENTITY_SCOPES` (`conf.py:548`) |
| The ROPC path uses `get_msal_client`, which accepts no token cache | **CONFIRM** | `azure.py:126-133`: `get_msal_client()` takes no `token_cache` parameter, unlike `get_msal_app` (`azure.py:116`) |
| The OAuth2-AS resume's partial re-save can overwrite a freshly captured grant | **CONFIRM** | `external.py:440` calls `_vault_upstream_token(request)`, which rebuilds a `TokenResponse` carrying `access_token` only (`external.py:471-484`) |
| No unique index on `(user_id, auth_provider)`, so an upsert on that pair fails with 42P10 (rev 0.3, Module 0) | **CONFIRM** | `identity/sql/001_identity_credentials.sql` creates `uq_user_identities_provider_account` on `(user_id, auth_provider, provider_user_id)` — a *partial* index, and on a different column set; `examples/sql/identity_vault_schema.sql:73` has only the non-unique `idx_user_identities_user` |
| The live `auth.user_identities` lacks `identity_id` and the profile columns (rev 0.3) | **CONFIRM (code side) / ESCALATE (DB side)** | Code side verified: `UserIdentity` (`models.py:77`) declares `identity_id` as primary key plus the seven profile columns, and `_MIGRATION_FILES` (`identity/migrations.py:19-23`) lists only `001`-`003`, so `004` is genuinely absent. The **production** table shape was not independently re-inspected in this session — that is exactly §8 Q5, which stays open |

---

## Worktree Strategy

- **Default isolation unit**: `per-spec` — one worktree,
  `.worktrees/feat-FEAT-103-external-provider-token-capture`, created from
  `origin/dev`.
- **Module 0** is a prerequisite: everything else depends on it, so it lands
  first in that worktree.
- Modules 1→2→3 are a strict chain (each depends on the previous) and Module 4
  depends on 2 and 3, so they run sequentially in that worktree.
- **Module 5** (`expires_in`/`expires_at`) and **Module 6** (redaction) share
  files with 1-4 and must coordinate edits or run sequentially;
  Module 6 only needs Module 1's key names, which are fixed in §2.
- **Module 8** (`AZURE_FLOW_TTL`) edits `conf.py` and `azure.py` — the latter
  shared with Module 3, so sequence it with 3 rather than running it concurrently.
- **Module 9 does NOT belong in this worktree.** It changes the
  `navigator-session` distribution at
  `/home/jesuslara/proyectos/navigator-session` (its own git repo, currently on
  `97a1763`), so it needs its own branch, commit and `1.1.1` release there,
  plus the floor raise in this repo's `pyproject.toml:52`. Two consequences the
  implementing lane must respect:
  - The shared `.venv` is editable-installed against **both** repos, so a
    `navigator-session` edit is immediately live for every session and worktree
    on this machine — including ones testing unrelated branches. Make the edit
    on a branch there and be aware the working tree, not the branch, is what
    the `.venv` imports.
  - Never `uv sync` inside a worktree: it repoints the shared venv and breaks
    the main checkout's imports for every session.
- **Module 7** (tests) lands last, or incrementally alongside each module; its
  Module 9 test lives in the `navigator-session` repo.
- **Cross-feature dependencies**: none. FEAT-102 is already merged into `dev`.
  Nothing here requires another spec to merge first. The one cross-**repo**
  dependency is Module 9 → `pyproject.toml:52`.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-10-22 | Jesus Lara | Initial draft — token capture, vaulting, on-demand refresh, `expires_in` contract fix |
| 0.2 | 2026-10-22 | Codex | Review fixes: complete MSAL normalization, preserve login scopes on refresh, bind capture/refresh to the verified external account, and add regression criteria |
| 0.3 | 2026-10-22 | Claude | Added Module 0: the `auth.user_identities` base table predates the `UserIdentity` model, so `IdentityStore` cannot write and G2 was unreachable. Evidence from a real token exchange (§1 (e), §6, Q5) |
| 0.4 | 2026-10-22 | Claude | Resolved §8 Q1-Q4. Q2 settled by the in-repo **B1** precedent (`oauth2/backend.py:9`) rather than by preference, and extended to `usr.expires_in` (G5). New Module 8 — split `AZURE_SESSION_TIMEOUT` (G7, Q4). New Module 9 — `load_session` merge in the `navigator-session` repo plus its `1.1.1` bump (G8, Q3). Q1 reduced to a bounded `max_age` experiment with the leeway decision taken independently. Corrected a 0.1 error: the `load_session` discard is **not** the cause of the stale `auth_token` |
