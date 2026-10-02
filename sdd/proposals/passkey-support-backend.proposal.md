---
id: FEAT-101
feature: passkey-support-backend
title: Passkey (WebAuthn / FIDO2) authentication backend
type: feature
mode: enrichment
status: review
base_branch: dev
projects: [navigator-auth]
source:
  kind: file
  path: "sdd/proposals/Passkey (WebAuthn) Authentication Backend.md"
confidence: medium
research_state: sdd/state/FEAT-101/
tags: [passkey, webauthn, fido2, passwordless, basic-auth, multi-tenant]
---

# Feature Proposal: Passkey (WebAuthn) Authentication Backend

**Date**: 2026-10-02
**Author**: Jesus Lara (research by Claude)
**Status**: review

---

## §0 Origin

The source is the brainstorm `sdd/proposals/Passkey (WebAuthn) Authentication Backend.md`
(a snapshot is in `sdd/state/FEAT-101/source.md`). It is detailed: flows, an
endpoint table, edge cases E1–E15, capabilities C1–C6, an impact table, a backend
skeleton, a parallelism plan and open questions Q1–Q10. Because of that, this
proposal runs in **enrichment** mode. It does not re-derive the design. It
checks the brainstorm's code claims against the repository, corrects the ones
that are wrong, and records the decisions made at the review gate.

## §1 Synthesis Summary — Why

Every first-party login today ends in one of two places: a shared secret, which
`BasicAuth.validate_user` checks through `IdentityProvider.check_password`, or a
redirect to an external IdP. No first-party credential resists phishing. Passkeys
fill that gap. A user who already has a session enrolls one or more passkeys, then
later signs in with a passkey alone and gets the same payload and session cookie
as a `BasicAuth` login.

The research **confirms the brainstorm's architecture**:

- a new backend class (F002);
- `webauthn` (py_webauthn) for the ceremonies;
- single-use challenges in Redis;
- verification through the existing `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth` (F009);
- new routes only for the options and enrollment endpoints.

It found **six contract errors** in the skeleton (§2.2). It found **existing
precedents** for storage and migrations (F008) and for reusing the session tail
(F002). It added two decisions that widen the scope:

- **per-tenant RP IDs** (U1);
- **`is_active` enforcement in the shared `open_session`** (U2).

## §2 Codebase Findings

### 2.1 Localization (verified)

| Path | Symbol | Role | Evidence |
|---|---|---|---|
| `navigator_auth/backends/basic.py:171` | `BasicAuth.open_session(request, user, extra=None, expiration=None)` | Shared session and token tail. Covers `get_userdata`, `BASIC_USER_MAPPING`, `remember`, JWT, jti revocation record, `refresh_token` and callbacks. `extra["auth_method"]` is mirrored into the JWT through `_JWT_EXTRA_KEYS` (`:154`). | F002 |
| `navigator_auth/backends/exchange.py:31` | `TokenExchangeAuth(BasicAuth)` | Precedent: a `BasicAuth` subclass that verifies its own credential and then calls `open_session(request, user, extra=...)` (`:216`). | F002 |
| `navigator_auth/backends/basic.py:52-73` | `BasicAuth.configure` / `on_startup` | A subclass inherits the `/auth/{_service_name}/check_credentials` route and `self.access_token_storage`. The attribute name matters: `AuthHandler._token_is_revoked` depends on it. | F003 |
| `navigator_auth/backends/idp/__init__.py:379` | `IdentityProvider.create_token` | Returns a **4-tuple** `(token, refresh_token, exp, scheme)`. | F001 |
| `navigator_auth/backends/idp/__init__.py:124` | `IdentityProvider.user_from_id(uid: int)` | Exists. Raises `UserNotFound`. Reached through `BaseAuthBackend.validate_user(userid=...)` (`abstract.py:251`). `BasicAuth` overrides `validate_user(login, password)`. | F006 |
| `navigator_auth/auth.py:343,386,470` | `get_auth_backend`, `_backend_auth`, `api_login` | Selects the backend by the `X-Auth-Method` header and maps errors. The fallback loop catches only `(AuthException, UserNotFound, InvalidAuth, FailedAuth)`; any other exception aborts the login for every backend. | F009 |
| `navigator_auth/auth.py:1062` | `_auth_middleware` | Sets `request.user` and `request["authenticated"]`. Protected handlers check `request.get("authenticated")` and read `request.user.user_id` (`api_create_token` pattern). | F010 |
| `navigator_auth/identity/store.py` | `IdentityStore(db_pool, cipher=None)` | Precedent for a dedicated CRUD store class over `app["authdb"]`. | F008 |
| `navigator_auth/identity/migrations.py` + `identity/sql/00N_*.sql` | `setup_identity_columns` | Idempotent SQL files run at startup (`auth.py:188`). This is the migration mechanism to copy. | F008 |
| `navigator_auth/models.py:39-70` | `User` | `user_id: int` primary key. `is_active: bool` at `:58`. Schema is `AUTH_DB_SCHEMA` (default `auth`, `conf.py:32`). | F007 |
| `navigator_auth/middlewares/csrf.py` | `csrf_middleware` | When the session cookie is the only credential, unsafe methods need a valid CSRF header. | F011 |
| `templates/oauth/login.html` | — | The OAuth2 login page, rendered by `Oauth2Provider` at `oauth2/backend.py:1712`. | F012 |
| `navigator_auth/abac/context.py:28` | `_resolve_tenant` | The only tenant resolver. It needs user info or trusted headers, so it cannot run before a usernameless login. | F015 |
| `pyproject.toml:60` | `[project.optional-dependencies]` | Extras precedent (`uvloop`, `geoip`). | F013 |

### 2.2 Constraints and corrections to the brainstorm

| # | Brainstorm claim or skeleton | Reality | Evidence |
|---|---|---|---|
| K1 | `token, exp, scheme = self._idp.create_token(...)` | It returns 4 values. The 3-value unpack raises an error that the broad `except` swallows, so every login silently returns `False` (403). | F001 |
| K2 | `PasskeyAuth(BaseAuthBackend)` copies the tail of `BasicAuth.authenticate` | Subclass `BasicAuth` and call `open_session(request, user, extra={"auth_method": "passkey"})`. Copying the tail would drop jti revocation (FEAT-098), `refresh_token` and `BASIC_USER_MAPPING`. | F002, F003 |
| K3 | `exclude_list.append(...)` (module list in `conf.py`) | Use `app[AUTH_EXCLUDE_LIST_KEY].append(...)` (`conf.py:47`), as `BasicAuth.configure` does. | F004 |
| K4 | Template under `navigator_auth/templates/` (not verified) | It is `templates/oauth/login.html` at the repo root. | F012 |
| K5 | `_session_user` checks `getattr(user, "is_authenticated")` and uses `user.id` | Check `request.get("authenticated")` and use `request.user.user_id`. | F010 |
| K6 | CSRF not mentioned | Browser POSTs to `register/*`, and the P2 `PATCH` and `DELETE`, need the CSRF header. The JS samples must send it. `login/options` and `/api/v1/login` are unauthenticated and not affected. | F011 |
| K7 | E9 "whether BasicAuth already enforces this was not verified" | **No login path checks `is_active`** (verified in Basic, Exchange, Abstract, External and the IdP lookups). | F005 |
| K8 | `PasskeyAuth.on_startup` builds only a Redis pool | It must call `super().on_startup(app)` to keep `access_token_storage` and the callbacks. | F003 |
| K9 | DDL hardcodes the schema `auth` | Follow `AUTH_DB_SCHEMA`, and ship the DDL as an idempotent migration file run at startup. | F007, F008 |

Other rules that still apply:

- `PasskeyAuth.get_payload` must raise `InvalidAuth` with no I/O when the body has no assertion (E11, F009).
- `BasicAuth.get_payload` already returns `[None, None]` for a passkey JSON body, so the fallback loop is also safe in the other direction.

### 2.3 Recent history

| Commit | Change | Relevance |
|---|---|---|
| `458084c` | TASK-046: `open_session()` factored out of `authenticate()` | The reuse point for K2. |
| `c20818e` | TASK-066: jti recorded on Basic JWTs and `access_token_storage` | Why copying the tail is unsafe. |
| `d7dbc8f` | TASK-077: context-bound `IdentityCipher`; Identity Vault store re-seal | The store precedent is current. |
| `5df3e94` | CSRF protection middleware | K6. |

## §3 Scope — What Changes

Hypothesis H1 (confidence: medium) has five parts:

- `PasskeyAuth(BasicAuth)`;
- a dedicated credential store with a startup migration;
- a per-origin RP resolver;
- an `is_active` check in `open_session`;
- no change to `api_login`.

Together they deliver C1–C6.

1. **Backend.** New file `navigator_auth/backends/passkey.py` defines `PasskeyAuth(BasicAuth)` with `_service_name = "passkey"`.
   - **`configure`.** Registers `login/options` as public through `AUTH_EXCLUDE_LIST_KEY`. Registers `register/options` and `register/verify` as protected.
   - **`on_startup`.** Calls `super()`, then opens the Redis pool.
   - **`get_payload`.** Fails fast (E11).
   - **`authenticate`.** Runs these steps:
     1. pop the challenge with `GETDEL` (U3 settled this; production runs Redis 6.2 or later);
     2. look up the credential;
     3. run `verify_authentication_response`;
     4. update `sign_count` and `last_used_at`;
     5. call `self._idp.user_from_id(stored.user_id)`;
     6. call `self.open_session(request, user, extra={"auth_method": "passkey"})`.
2. **Per-tenant RP resolution (U1, new design).**
   - **Configuration.** Replace the single `PASSKEY_RP_ID` / `PASSKEY_ORIGINS` with an allow-list map, for example `PASSKEY_RELYING_PARTIES`: origin → `{rp_id, rp_name}`.
   - **Resolution.** On every ceremony, read the RP from the request's `Origin` header, matched exactly against the map. Never derive it from `Host` or the URL scheme (E3, behind the ALB).
   - **Unknown origins.** An origin missing from the map gets 401.
   - **Storage.** Save the resolved RP in the challenge state, and store `rp_id` on each credential row.
   - **Scoping.** Filter `excludeCredentials` and the credential list by RP.
   - **Startup.** Startup fails with `ConfigError` when the backend is enabled and the map is empty.
   - **ABAC.** `_resolve_tenant` does not apply before authentication (F015). Whether the map is also keyed by `org_id` for ABAC belongs in the spec.
3. **Credential store (answers Q3 from precedent).** A `CredentialStore`-style class, modeled on `IdentityStore`, over `app["authdb"]`.
   - **Methods.** `get(credential_id)`, `list_by_user(user_id, rp_id=None)`, `save(...)`, `update_usage(...)`, `delete(...)`, `rename(...)`.
   - **Data.** A `UserCredential` model in `models.py`, and the table `{AUTH_DB_SCHEMA}.user_credentials` with `user_id integer` as a foreign key to `users.user_id` plus an `rp_id` column.
   - **Migration.** An idempotent SQL file run at startup, following the `identity/migrations.py` pattern.
4. **`is_active` enforcement (U2, cross-cutting).**
   - **Where.** `BasicAuth.open_session` rejects users whose `is_active` is false, by raising `FailedAuth`/`InvalidAuth` and returning 401/403.
   - **Who is affected.** Every Basic-derived login: Basic, TokenExchange and Passkey.
   - **Compatibility.** This is a **behavior change for existing logins**. The spec must cover the `AUTH_USER_VIEW` models that do not expose `is_active` (treat a missing attribute as active). It also needs regression tests in `test_basic_open_session.py`.
5. **Enrollment (C3).**
   - **Access.** Any authenticated session plus the CSRF header can enroll (U4: no recent re-authentication in v1).
   - **Duplicates.** `excludeCredentials` is scoped to the resolved RP.
   - **Options.** `attestation="none"` and `residentKey=required`.
6. **Configuration (C1).** Add to `conf.py`:
   - the relying-party map;
   - `PASSKEY_CHALLENGE_TTL` (default 300);
   - `PASSKEY_USER_VERIFICATION` (default `required`).
7. **Packaging (Q7).** Add the extra `passkey = ["webauthn>=2.0"]` to `pyproject.toml`, and import it lazily. Startup raises `ConfigError` when the backend is enabled and the extra is missing.
8. **P2.** Credential management covers list, delete with the E13 rule, and rename. It also covers the `templates/oauth/login.html` button and conditional UI with the CSRF-aware JS (C6).

**Out of scope.** These stay as the brainstorm set them:

- attestation and AAGUID policy;
- MFA step-up;
- account recovery;
- passkey sign-up;
- ABAC `auth_method` exposure (Q5).

`api_login`, `navigator_session` and the OAuth2 token endpoint are unchanged.

### New capabilities

- `passkey-auth`: C1–C6 as defined in the source, corrected per §2.2.
- `passkey-rp-resolver`: per-origin relying-party resolution.

### Modified capabilities

- `basic-open-session`: rejects inactive users (U2).

## §4 Confidence Map

| Claim | Confidence | Basis |
|---|---|---|
| Verification through `api_login` + `X-Auth-Method` works without editing `auth.py` | high | F009 |
| Subclassing `BasicAuth` and calling `open_session` is the right reuse | high | F002, F003 (TokenExchange precedent) |
| The `create_token` 4-tuple, the exclude-list key and the template path | high | F001, F004, F012 |
| No current `is_active` enforcement | high in code; medium for deployments whose `AUTH_USER_VIEW` may filter | F005 |
| `request.user.user_id` is the attribute on the session user | medium | F010 (inferred from `api_create_token`) |
| A per-origin RP map is the right per-tenant mechanism | medium | F015. New design with no precedent. |
| Production Redis is 6.2 or later | user-asserted | U3 |

## §5 Open Questions

### Resolved

- [x] **U1 / Q1 — RP ID scope.** **Per-tenant RP ID.** Implemented as a per-origin allow-list map (§3.2).
- [x] **U2 — `is_active` scope.** **Enforced in `BasicAuth.open_session`** for every Basic-derived login.
- [x] **U3 / Q8 — Redis.** **Production runs 6.2 or later.** Use `GETDEL`.
- [x] **U4 / Q10 — Enrollment re-auth.** **Any live session** (plus CSRF) in v1. Recent re-auth is deferred to the MFA work.
- [x] **Q3 — Where the helpers live.** **A dedicated store class**, following the `IdentityStore` precedent (F008).
- [x] **Q7 — Packaging.** **An optional extra `navigator-auth[passkey]`**, following the existing extras precedent (F013).

### Still open (for the spec)

- [ ] **Q2.** User handle: `str(user_id)` versus a random per-user handle column.
- [ ] **Q4.** Counter regression: reject only, or also disable and notify.
- [ ] **Q5.** Expose `auth_method` to ABAC `EvalContext`.
- [ ] **Q6.** Does a passkey satisfy future MFA requirements?
- [ ] **Q9.** Is a username-first mode needed at all?
- [ ] **New.** Is the RP map keyed only by origin, or also tied to `org_id` for ABAC alignment?

## §6 Recommended Next Step

→ `/sdd-spec FEAT-101`

**Rationale.** Localization is high-confidence and every material unknown has an
answer. The per-tenant RP resolver and the `open_session` behavior change are new
design and belong in spec §2. The spec's parallelism plan has to change: S0 must
now also freeze the RP-resolver interface and the store signatures, and the
`open_session` change is a separate, early serial task with its own regression
tests.

## §7 Research Audit

- **State:** `sdd/state/FEAT-101/` (`source.md`, `research_plan.json`, `findings/F001`–`F015`, `synthesis.json`, `state.json`).
- **Budget:** default profile. About 20 file reads and about 14 greps, 1 git log. Not truncated.
- **Wiki:** unavailable (`wikitoolkit` is not installed). The research fell back to grep and read.
