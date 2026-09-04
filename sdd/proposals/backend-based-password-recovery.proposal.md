# Feature Proposal: Backend-Based Password Recovery (3-Step Signed Flow)

**Date**: 2026-09-04
**Author**: Jesus Lara
**Status**: discussion
**Feature ID (reserved)**: FEAT-097
**Replaces**: `navigator_auth/handlers/recovery.py` (`ForgotPasswordHandler`,
`ResetPasswordHandler`) and their routes `/api/v1/forgot-password`,
`/api/v1/reset-password`.

---

## Why

navigator-auth has no working self-service password recovery. The module that
exists today, `handlers/recovery.py`, is a two-step draft that does not run:

- `save_token` calls `json_decoder(data)` to **encode** a dict before writing to
  Redis, and `get_token` calls the same decoder on the way out — the write path
  is wrong.
- It hashes the new password through `self.request.app['auth']._idp.set_password(...)`,
  a method that does not exist on the IdP. The real hasher is
  `set_basic_password()` in `handlers/users/passwd.py`.
- It builds a fresh `redis.from_url()` client on **every request** instead of
  using a pooled connection, and never closes it.
- It extends `web.View` directly, so it gets none of the `BaseHandler` response
  helpers (`json_response`, `error`, `critical`) the rest of the handlers use.
- It hands the whole reset to a **single** token: whoever holds the e-mailed
  token can post a new password. There is no separation between "you proved you
  opened the mailbox" and "you are now authorized to write a password".

The only other reset paths require a session that the locked-out user cannot
have: `POST /api/v2/user/set_password` needs the current password, and
`POST /api/v2/user/password_reset/{userid}` needs a superuser session. A user who
has forgotten their password today has to ask an administrator.

We want a recovery flow that actually works, splits proof-of-mailbox from
authorization-to-write, and leaves the sending of e-mail to whatever system the
deployment already uses.

## What Changes

A new HTTP module built on `navigator.views.BaseHandler` (the same base
`UserSession` uses) exposes a **three-step** flow. navigator-auth never sends
e-mail; it produces the payload and hands it to a configured callback.

**Step 1 — Request recovery.**
`POST /api/v1/password-recovery` with `{"email": "..."}`.
The service looks the user up, mints a **recovery token** and stores it in Redis
under a random key for one hour, with a payload bound to the user (user_id,
username, e-mail, issue time) and signed with an internal signature so a token
cannot be forged or replayed against a different account. It then invokes the
configured callback with a ready-to-mail payload (recipient, display name,
token, the URL for step 2, expiry). The **HTTP response never contains the
token** — it is always the same generic "if that account exists, instructions
have been sent", with the same status code and approximately the same latency
whether or not the address is known.

**Step 2 — Validate the recovery token.**
`GET /api/v1/password-recovery/{token}` — the call the landing page makes when
the user clicks the link. If the token is valid and unexpired the service mints
a **second, separate confirmation token** (default 15-minute TTL) and returns it
in the payload. The recovery token is *not* consumed here: it stays valid for
its full hour so a refresh, a back button, or an e-mail scanner prefetching the
link does not burn the reset. Each call rotates the confirmation token — the
previously issued one stops working, so only the newest is live.

**Step 3 — Set the password.**
`POST /api/v1/password-recovery/confirm` with `{"password", "confirm_password",
"token"}` where `token` is the **confirmation** token from step 2. The service
validates the pair, checks the two passwords match, enforces the password
policy, writes the new hash with `set_basic_password()`, deletes **both** Redis
records so the link cannot be replayed, and revokes the user's existing
sessions and outstanding JWTs.

Explicitly **not** changing: the login flow, `password_change` /
`password_reset` under `/api/v2/user/*`, the password hashing scheme, session
storage format, or any external provider backend.

## Capabilities

### New Capabilities

- `password-recovery-flow`: the three-step handler on
  `navigator.views.BaseHandler` — request, validate, confirm — with the
  uniform-response and constant-ish-timing behaviour on step 1.
- `recovery-token-store`: Redis-backed, TTL'd, signed two-stage token store
  modelled on `identity/flow_store.py` (pooled connection, `setex`, `GETDEL`
  for single-use consumption). Holds the recovery token (1 h) and the
  confirmation token (15 min), links the second to the first, rotates the
  second on re-issue, and drops both atomically on success.
- `recovery-notification-callback`: configurable callback contract
  (`AUTH_RECOVERY_CALLBACK`) receiving the mail-ready payload, invoked for both
  the success path and the "no such account" path so the deployment can decide
  what, if anything, to send. Callback failures are logged and never change the
  HTTP response.
- `password-policy`: reusable validator for minimum length and complexity, with
  a structured error payload naming which rule failed. New to the codebase —
  nothing validates password strength today.
- `recovery-rate-limit`: per-e-mail and per-IP throttle on step 1, backed by
  Redis counters, reusing the `"<count>/<window>"` spec parser
  `parse_rate_limit()` already in `backends/oauth2/dcr.py`.

### Modified Capabilities

- `basic-auth-session`: Basic-auth JWTs gain a `jti` claim, and `BasicAuth` gains
  an `access_token_storage` so an issued token can be revoked. This is what makes
  "revoke sessions on reset" real rather than cosmetic — see Impact.
- `user-session-management`: session revocation by user, deleting both
  `session:{session_id}` and the `user:{identity}` index key that
  `navigator_session`'s Redis storage maintains.

## Impact

- **End users**: a locked-out user can recover without an administrator. No
  change to anyone already signed in, except that a completed reset now ends
  their other sessions.
- **API**: three new routes under `/api/v1/password-recovery`. The two old
  routes (`/api/v1/forgot-password`, `/api/v1/reset-password`) are repointed at
  the new module; `handlers/recovery.py` is rewritten in place. Nothing working
  is lost, because the current implementation cannot complete a reset.
- **Files touched**: `handlers/recovery.py` (rewrite), `handlers/__init__.py`
  (routes), `conf.py` (new settings), a new token-store module alongside
  `identity/flow_store.py`, a new password-policy module, `backends/idp/__init__.py`
  (`create_token` emits `jti`), `backends/basic.py` (records the `jti`, exposes
  `access_token_storage`).
- **Auth middleware**: **no change required.** `AuthHandler._token_is_revoked`
  (`auth.py:985`) already walks every backend looking for an
  `access_token_storage` and checks any token carrying a `jti`. Giving `BasicAuth`
  that attribute and emitting a `jti` is enough for revocation to take effect on
  the existing path.
- **Blast radius of the `jti` change**: every Basic login starts writing a `jti`
  record to Redis and every authenticated request with a `jti` costs one Redis
  lookup. This affects all Basic-auth traffic, not only recovery. Tokens minted
  before the upgrade carry no `jti` and keep working untouched (the check
  short-circuits on a missing `jti`), so the rollout is backward compatible.
- **Security posture**: the recovery token proves mailbox control and is not
  itself sufficient to write a password; the confirmation token is short-lived,
  rotating, and single-use. Step 1 cannot be used to enumerate accounts or to
  spam an inbox. A completed reset invalidates prior credentials.
- **Dependencies**: none new — `redis.asyncio`, `navconfig`, `navigator.views`
  are all already in use.
- **Breaking changes**: none at the HTTP contract level. Deployments that wired
  `FORGOT_PASSWORD_CALLBACK` must move to `AUTH_RECOVERY_CALLBACK`, whose payload
  is richer; the old name should be honoured for one release with a deprecation
  warning.

## Decisions (resolved 2026-09-04)

- **D1** Step 1 is a **public** endpoint that never returns the token. The
  mail-ready payload goes to `AUTH_RECOVERY_CALLBACK`; the HTTP response is
  always the generic "instructions sent".
- **D2** Step 1 is **POST with a JSON body**, not GET with the e-mail in the
  query string — it has side effects (Redis write, mail dispatch) and the
  address must not land in access logs, proxy logs or browser history.
- **D3** `handlers/recovery.py` is **replaced**: the new `BaseHandler` module
  takes over, and the existing routes are repointed at it.
- **D4** Step 2 does **not** consume the recovery token. It stays valid for its
  full hour; each step-2 call mints a fresh confirmation token and invalidates
  the previous one.
- **D5** Confirmation-token TTL is **15 minutes**, configurable via
  `AUTH_RECOVERY_CONFIRM_TTL` (default 900 s). Recovery-token TTL is one hour,
  configurable via `AUTH_RECOVERY_TTL` (default 3600 s).
- **D6** Rate limiting on step 1, per e-mail and per IP, is in scope.
- **D7** Password policy validation at step 3 is in scope, as a new reusable
  validator.
- **D8** Session revocation after reset is in scope, and goes all the way:
  Basic JWTs gain a `jti` so already-issued tokens can actually be killed,
  rather than surviving until `exp`.
- **D9** Unknown e-mail addresses get an identical response body, status and
  approximately identical latency to known ones.
- **D10** **Every** active user may set a local password through this flow,
  including accounts that authenticate only through Azure / Google / GitHub and
  have no local password today.

## Open Questions

- **Q1** What is the exact composition of the "internal signature"? The
  description says the checksum is built from time, date, username and an
  internal signature. An HMAC over `(user_id, username, issued_at, nonce)` keyed
  by `SECRET_KEY` gives integrity and lets the payload be validated without
  trusting Redis alone. To settle at spec time: which secret keys it
  (`SECRET_KEY` vs a dedicated `AUTH_RECOVERY_SECRET`), and whether the Redis
  key is the token itself or a hash of it, so a Redis dump does not hand over
  usable tokens.
- **Q2** What are the default password-policy rules? Proposed starting point:
  minimum 8 characters, at least one letter and one digit, rejected if identical
  to the current password — all overridable by setting. Needs your call.
- **Q3** What are the default rate limits? Proposed: 3 requests per hour per
  e-mail address, 10 per hour per IP.
- **Q4** Should step 3 log the user straight in (return a session/JWT like a
  Basic login) or require a fresh login? Proposed: require a fresh login, which
  is the safer default and keeps step 3 free of session-minting logic.
- **Q5** Does the step-2 URL handed to the callback need to be per-tenant or
  per-deployment configurable (`AUTH_RECOVERY_URL_TEMPLATE`), or is a single
  base URL enough?
- **Q6** Should a successful reset clear the `is_new` flag on the user record,
  the way `password_reset` currently **sets** it?

## Parallelism Potential

Four of the five new capabilities are independent and can run in separate
worktrees:

- **`password-policy`** — a pure, dependency-free validator plus its tests. No
  contact with Redis, HTTP or the user model. Fully parallel.
- **`recovery-token-store`** — Redis two-stage store with signing, TTL and
  rotation, modelled on `identity/flow_store.py`. Its only contract with the
  handler is the store API. Fully parallel.
- **`recovery-rate-limit`** — Redis counters plus the reused `parse_rate_limit`.
  Fully parallel.
- **`basic-auth-session` `jti` + revocation** — touches `backends/idp/__init__.py`
  and `backends/basic.py`, files no other item in this feature touches. Parallel,
  and the one item worth reviewing on its own because it affects all Basic
  traffic.
- **`password-recovery-flow`** (the handler itself) and
  **`recovery-notification-callback`** depend on the four above and land last.

No in-flight worktree touches `handlers/recovery.py`, `backends/basic.py` or
`backends/idp/__init__.py`. FEAT-096 (`external-token-exchange`) is specced but
not started; it refactors the *tail* of `BasicAuth.authenticate` into
`open_session()`, which is the same region of `basic.py` where the `jti` record
is written — **sequence these two, or expect a conflict in `basic.py`**.
