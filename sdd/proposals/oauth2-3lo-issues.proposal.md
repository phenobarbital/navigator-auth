---
id: FEAT-108
title: OAuth2 3LO examples fail end-to-end — miswired examples expose four latent auth defects
slug: oauth2-3lo-issues
type: feature
mode: investigation
status: discussion
source:
  kind: inline
  jira_key: null
  jira_url: null
  fetched_at: 2026-11-11
  summary_oneline: "OAuth2 3LO examples: /api/v1/me 500s, anonymous gets 200, grants 401, empty userinfo, session bind fails for user 35, PKCE verifier missing"
overall_confidence: medium
base_branch: dev
projects: [oauth2, backends, decorators, examples]
tags: [oauth2, 3lo, pkce, session-binding, is-authenticated, examples]
research_state: sdd/state/FEAT-108/
created: 2026-11-11
updated: 2026-11-11
---

# FEAT-108 — OAuth2 3LO examples fail end-to-end — miswired examples expose four latent auth defects

> **Mode**: investigation
> **Confidence**: medium (high for localization; medium only for *how* user 35 entered the flow — U1)
> **Source**: `inline` (user report, 2026-11-11, plus one addendum reported mid-run)
> **Audit**: [`sdd/state/FEAT-108/`](../state/FEAT-108/)

---

## 0. Origin

Reported while running `python examples/oauth2_3lo_server.py` (full log excerpts, with
Azure/ADFS identifiers and auth codes redacted, in `sdd/state/FEAT-108/source.md`):

> * When clicked "/api/v1/me" we got a 500 internal server error: … `navigator_auth/backends/api.py`, line 154, in authenticate — `device_id = str(data["device_id"])` — `TypeError: 'bool' object is not subscriptable`
> * When clicked at userinfo … `Oauth2: cannot bind a session to the token for user_id=35: Invalid Credentials for user_id=35`
> * When clicked at "Refresh Token" we got a token but a warning in log: (same warning)
> * When clicked at "Call it without credentials (expect 401)", instead of 401, a 200 OK with anonymous dict: `"message": "Hello Anonymous 3031c458…!"`
> * When click on "List my grants": a 401 with "unauthorized": `{"error":"unauthorized","error_description":"Not authenticated."}`
> * When clicked "oauth2/userinfo" we got a 200 OK with: `{"sub":"35","username":"","given_name":"","family_name":"","email":""}`

Addendum (mid-run): with `examples/oauth2_server.py` running, the printed 3LO URL
(`…&code_challenge=<S256_hash>&code_challenge_method=S256`) reaches the callback page,
but "Get Token" answers `{"error": "invalid_grant", "error_description": "code_verifier required."}`.

**Initial signals** (extracted, not interpreted):
- Verbs: "got a 500", "instead of 401 … 200", "cannot bind a session" → bug-shaped.
- Named entities: `Oauth2Provider` (backend.py:700), `APIKeyAuth.authenticate` (api.py:154), `decorators._wrap` (:217), `NoAuth`, `TrocToken`, AzureAuth/ADFSAuth log lines, `user_id: 35`, `iss: Mobileinsight`, 6-byte HMAC key, `code_verifier`.
- Components / labels: none (inline source).
- Acceptance criteria provided: implicit — the SPA's own button labels ("expect 401").

---

## 1. Synthesis Summary

Both OAuth2 examples are miswired. `examples/oauth2_3lo_server.py` builds
`AuthHandler(enable_authdb=False)` without `backends=` / `authz_backends=`, so the
developer's `settings/settings.py` (star-imported last by `navigator_auth/conf.py`) and
`env/.env` decide the backends (8, including APIKeyAuth and NoAuth) and add `allow_hosts`
authorization. Every localhost request therefore skips real authentication in
`AuthHandler._auth_middleware` and lands in the backend loop of
`is_authenticated._func_wrapper._wrap`, where `APIKeyAuth.authenticate` crashes on the 3LO
bearer (the 500) and `NoAuth.authenticate` admits anonymous callers (the 200). Separately, the
token's `user_id=35` is not a demo user: `Oauth2Provider.authorize` takes the resource owner
from an existing browser session, `Oauth2Provider._token_session_claims` cannot resolve it and
silently issues session-less tokens, which empties `Oauth2Provider.userinfo` and makes
`Oauth2Provider.list_grants` answer 401. In `examples/oauth2_server.py`, the PKCE check in
`Oauth2Provider._handle_authorization_code` is correct, but `examples/static/callback.html` never
sends a `code_verifier`. Recommendation: fix both examples **and** the four library defects
they exposed, via `/sdd-spec`.

---

## 2. Codebase Findings

> All entries are grounded in `sdd/state/FEAT-108/findings/` (F001–F017). Lane originals
> are archived in `findings/.audit/`. 40 citations were re-checked by `sdd-contract-probe`:
> 35 found, 5 anchors non-unique but consistent with the cited ranges, 0 missing.

### 2.1 Localization

| # | Path | Symbol | Lines | Role | Evidence |
|---|------|--------|-------|------|----------|
| 1 | `examples/oauth2_3lo_server.py` | `make_app` | 218 | `AuthHandler(enable_authdb=False)` with no `backends=`/`authz_backends=` — local settings decide the backend list | F003 |
| 2 | `navigator_auth/conf.py` | settings override | 912-915 | `from settings.settings import *` runs last, overriding the example's `os.environ.setdefault` | F003 |
| 3 | `examples/identity_vault_server.py` | `AuthHandler(...)` | 722 | existing pattern: `AuthHandler(backends=_BACKENDS, authz_backends=[])` | F003 |
| 4 | `navigator_auth/auth.py` | `AuthHandler._auth_middleware` | 1056-1073 | `allow_hosts` exempt branch: bearer resolution needs an existing session and never sets `request["userdata"]` | F004 |
| 5 | `navigator_auth/decorators.py` | `is_authenticated._func_wrapper._wrap` | 207-237 (+261) | loops every backend's `authenticate()`, catches only `AuthException`, accepts the first truthy result | F005 |
| 6 | `navigator_auth/backends/api.py` | `APIKeyAuth.authenticate` | 143-157 | indexes the `False` returned by `check_token_info` → `TypeError` at 154 (the 500) | F006 |
| 7 | `navigator_auth/backends/noauth.py` | `NoAuth.authenticate` | 54-82 | always returns a truthy anonymous user + new session (the anonymous 200) | F007 |
| 8 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider._token_session_claims` | 688-710 | `self._idp.user_from_id` failure → logs the warning, returns `{}`; token still issued | F002 |
| 9 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider.authorize` | 1422-1456 | resource owner from the session cookie (`check_session`); skips login/consent when a grant exists | F001 |
| 10 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider.userinfo` | 2194-2254 | profile claims from `user_from_id`, default `""` on failure | F008 |
| 11 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider.list_grants` | 2311-2315 | 401 "Not authenticated." when no user id is found | F008 |
| 12 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider._get_request_user_id` | 2801-2830 | reads `request["userdata"]`, then `request.user` | F008 |
| 13 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider.authenticate` | 2833 | correct resource-server check (401 for a token without a bound session) — never reached first by the loop | F014, F015 |
| 14 | `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider._handle_authorization_code` | 1799-1808 | PKCE: requires `code_verifier` when the code carries a challenge (correct, RFC 7636) | F017 |
| 15 | `examples/static/callback.html` | `exchangeToken` | 30-41 | posts the code without `code_verifier` — nothing ever generates one | F017 |
| 16 | `examples/static/oauth2_index.html` | Authorize link | 54 | authorize link with no `code_challenge` for a PKCE-required public client | F017 |
| 17 | `examples/oauth2_server.py` | startup hint (3LO flow) | 172-182 | prints a URL with a literal `<S256_hash>` placeholder and no verifier | F017 |
| 18 | `tests/test_oauth2_3lo_session_binding.py` | `TestTokenSessionBinding` | 102-136 | mock-only; `test_unknown_user_degrades_without_raising` locks the silent `{}` degrade | F009 |

### 2.2 Constraints Discovered

- **Examples pin their auth config through existing API.** `AuthHandler.__init__` already
  accepts `backends=` and `authz_backends=`; its docstring names the bundled examples as the
  use case, and `identity_vault_server.py` uses them.
  *Implication*: the 3LO example fix is wiring, not new library API. *Evidence*: F003, F007
- **The silent degrade is deliberate and tested.** d3f85ba issues a session-less token when
  the owner cannot be resolved ("usable for introspection-based resource servers"), and
  `test_unknown_user_degrades_without_raising` asserts it.
  *Implication*: the decided fail-closed behaviour (§5, U3) must replace that test explicitly.
  *Evidence*: F002, F009, F014
- **Anonymous access already has explicit opt-ins.** `is_authenticated` short-circuits on
  the exclude list and `request.allow_anonymous` (covered by `tests/unit/test_is_authenticated_exclude.py`).
  *Implication*: rejecting guest results in the backend loop (U2) keeps a path for apps that
  want anonymous access. *Evidence*: F005, F009
- **Library changes reach every app.** Real deployments enable NoAuth, `allow_hosts` and
  8 backends; `AuthHandler.api_login` iterates backends the same way.
  *Implication*: decorator/middleware changes need their own unit tests, not only the example.
  *Evidence*: F003, F007, F002
- **The short HMAC key is local config.** The 6-byte `AUTH_SECRET_KEY` and the
  `Mobileinsight` issuer come from the developer's `env/.env`; `conf.SECRET_KEY` is bound at
  import. *Implication*: the example can only warn or document, not override it.
  *Evidence*: F003, F011
- **APIKeyAuth reads OAuth2 bearers on purpose** (TASK-029 / af51e88 bearer branch).
  *Implication*: the fix makes it *decline* non-API-key bearers cleanly, not stop reading them.
  *Evidence*: F006, F016

### 2.3 Recent History (Relevant)

| Commit | When | Author | Message | Touched files |
|--------|------|--------|---------|---------------|
| `416a5f8` | 2026-10-08 | Jesus Lara | fix(csrf): scope the check by authentication mechanism | `auth.py`, `backends/api.py`, `oauth2/backend.py`, `middlewares/csrf.py`, … |
| `e919298` | 2026-10-02 | Jesus Lara | fix(passkey-support-backend): scope session to the ceremony origin | `oauth2/backend.py` (session helpers region; effect on 3LO not checked) |
| `af51e88` | 2026-08-31 | Jesus Lara | feat(oauth2-for-mcp-agents): TASK-044 — OAuth 2.1 conformance hardening | `auth.py`, `backends/api.py` (bearer challenge), `oauth2/backend.py` |
| `d3f85ba` | 2026-08-21 | Claude | feat(oauth2): end-to-end 3LO example + fixes to make the flow work | `examples/oauth2_3lo_server.py`, `examples/static/*`, `oauth2/backend.py` (`_token_session_claims`, `authenticate`), `conf.py`, `tests/test_oauth2_3lo_session_binding.py` |

No commit after d3f85ba touches `APIKeyAuth.authenticate`, the `is_authenticated` backend
loop or `_token_session_claims` behaviour: these are latent defects, not regressions (F012–F014).
`decorators.py` changed only for ABAC and session-user normalization in this window (F013).

---

## 3. Hypothesis

### Hypothesis 1 — Both OAuth2 examples are miswired  · Confidence: high

**Supporting evidence**: F003, F004, F005, F006, F007, F010, F011, F017
**Contradicting evidence**: —
**Reasoning**:
- *(a) 3LO example.* `os.environ.setdefault("AUTHENTICATION_BACKENDS", …)` loses to
  `settings/settings.py` (star-imported last) and to `env/.env`. A runtime probe resolved
  8 backends, `AUTHORIZATION_BACKENDS=allow_hosts,allowed_ips`, `ALLOWED_HOSTS=localhost*`
  and a 6-byte key. `allow_hosts` sends every localhost request down the exempt branch of
  `_auth_middleware`, so `@is_authenticated()` runs its backend loop:
  - APIKeyAuth comes before Oauth2Provider and crashes on the 3LO bearer (`api.py:154`, the traceback frame).
  - With no credentials, NoAuth answers truthy. The SPA sends that call with `credentials:'omit'`, so the 200 is produced server-side.
  - Azure/ADFS "Redirect URL" lines in the log are those backends being tried by the same loop.
- *(b) oauth2_server.py.* The token endpoint correctly requires `code_verifier` for a
  code issued with a challenge (`backend.py:1803`, same string as the error). No page in
  that walk-through generates, stores or sends a PKCE pair. `oauth2_3lo_app.html` already
  does it in JS (`crypto.subtle` + `sessionStorage`).

**Suggested next probe**:
```bash
# (a) in examples/oauth2_3lo_server.py:
#   AuthHandler(backends=["navigator_auth.backends.oauth2.Oauth2Provider"],
#               authz_backends=[], enable_authdb=False)
# then repeat the six clicks.
# (b) run the 3LO flow from oauth2_3lo_server.py — its page completes the PKCE exchange.
```

### Hypothesis 2 — user 35 came from an existing browser session the demo IdP cannot resolve  · Confidence: medium

**Supporting evidence**: F001, F002, F008
**Contradicting evidence**: —
**Reasoning**: Every IdP call in the provider uses the swapped-in demo IdP, including login
(`auth_login`, backend.py:1636). The only way a non-demo `user_id` reaches the code is
`check_session` (backend.py:523-536): `/oauth2/authorize` takes the user from the
session cookie and, with an existing grant, issues the code without login or consent.
`user_from_id(35)` then fails, so:
- `_token_session_claims` returns `{}` on both the code and the refresh grant, which is why the warning repeats;
- `userinfo` falls back to `""` for every profile claim;
- `list_grants` finds no user and answers 401.

Which app created the user-35 session is not provable from the code (U1).

**Suggested next probe**: private window (or clear cookies for `localhost:5000`), log in as
`demo` / `demo123`, check the token's `user_id` is 1.

### Hypothesis 3 — four library defects turn a misconfiguration into wrong answers instead of a clean 401  · Confidence: high

**Supporting evidence**: F001, F002, F004, F005, F006, F007, F008, F009, F013
**Contradicting evidence**: —
**Reasoning**: Each defect is read directly in the code, none has a test, and none is a
recent regression:
1. `APIKeyAuth.authenticate` lacks the `if not data` guard that `check_credentials` already has.
2. `is_authenticated` (function and method wrappers) lets any non-`AuthException` error escape as a 500, and accepts anonymous results.
3. The `allow_hosts` exempt branch of `_auth_middleware` never publishes `request["userdata"]`.
4. `/oauth2/authorize` and the token grants accept a resource owner the IdP cannot resolve.

Fixing only the examples turns the 500 into a 401 and hides all four again (C13).

**Suggested next probe**: unit tests — `APIKeyAuth.authenticate` with a 3LO JWT returns
`None`; `is_authenticated` with `[APIKeyAuth, NoAuth]` answers 401 for a non-API-key bearer
and for no credentials.

### Fix direction (from the resolved decisions in §5)

For `/sdd-spec` to turn into acceptance criteria. This is a direction, not a design.

1. **3LO example wiring**:
   - `examples/oauth2_3lo_server.py` passes `backends=[Oauth2Provider]` and `authz_backends=[]`, like `identity_vault_server.py`.
   - At startup it warns when the effective `SECRET_KEY` is under 32 bytes, or when the backends it asked for differ from what loaded.
   - Its README section documents the settings override.
2. **oauth2_server.py PKCE**:
   - `oauth2_index.html` generates the S256 pair (reusing the 3LO app's approach), stores the verifier, and sends `code_challenge`.
   - `callback.html` sends `code_verifier`.
   - The startup hint points at the page instead of printing a `<S256_hash>` placeholder.
3. **`APIKeyAuth.authenticate`**: decline (return `None`) when the token info is empty, mirroring `check_credentials`.
4. **`@is_authenticated()` loop**, both the function and the method wrapper:
   - A guest/unauthenticated result counts as failure (U2).
   - A backend's unexpected exception no longer turns into a 500 for the whole request; the exact policy is in §5, "Unresolved".
5. **`_auth_middleware` exempt branch**: when a bearer resolves, set `request["userdata"]` the same way the main path does (`auth.py:1136/1168`).
6. **Unknown resource owner** (U3):
   - `Oauth2Provider.authorize` and the consent step check the session user with `self._idp.user_from_id`. If the user is unknown, they drop the session and redirect to login.
   - The code and refresh grants return `invalid_grant` instead of issuing a session-less token.
   - Replace `test_unknown_user_degrades_without_raising` with a test for the new behaviour.
7. **`userinfo`**: omit the claims it cannot supply instead of returning `""` (OIDC).
8. **Tests**:
   - unit tests for 3–7;
   - an app-level test that wires `AuthHandler` the way the fixed example does, then asserts: `/api/v1/me` gives 200 with a bearer and 401 without; `List my grants` gives 200; `userinfo` returns the user's profile.

**Non-goals**: changing the developer's `env/.env`; the TrocToken/TokenAuth middlewares
(they only pass the 3LO bearer through, F011); `navigator_session` (wheel install); the
same backend-loop pattern in `AuthHandler.api_login`, which needs its own change.

---

## 4. Confidence Map

| ID | Claim | Evidence | Confidence | Reasoning |
|----|-------|----------|------------|-----------|
| C1 | The 3LO example builds `AuthHandler` without `backends=`/`authz_backends=`, unlike `identity_vault_server.py` | F003 | high | both lines read and probed |
| C2 | `conf.py` star-imports `settings.settings` last; local `settings/settings.py` enables 8 backends incl. APIKeyAuth, TrocToken, Azure, ADFS, NoAuth | F003 | high | read, probed, runtime-resolved |
| C3 | At runtime authz is `allow_hosts,allowed_ips` with `ALLOWED_HOSTS=localhost*`, and `AUTH_SECRET_KEY` is 6 bytes from `env/.env` | F003, F011 | high | runtime probe (names/lengths only) |
| C4 | `allow_hosts` exempts localhost requests; the exempt branch needs an existing session and never sets `request["userdata"]` | F004 | high | code read |
| C5 | `is_authenticated` loops every backend, catches only `AuthException`, accepts the first truthy result | F005 | high | code read; traceback frame matches |
| C6 | The 500 is `APIKeyAuth.authenticate` indexing the `False` from `check_token_info` | F006 | high | code read; traceback frame matches |
| C7 | The anonymous 200 is NoAuth accepted by the decorator loop, not a leaked cookie | F007, F010 | high | NoAuth always truthy; SPA uses `credentials:'omit'` |
| C8 | `_token_session_claims` swallows the lookup failure; code and refresh grants still issue a session-less token | F002 | high | code read; decoded tokens carry no session claims |
| C9 | The bind warning is raised by `DemoIdentityProvider.user_from_id`, which knows only ids 1 and 2 | F001, F002 | high | message format matches |
| C10 | user 35 entered via a pre-existing `localhost:5000` session cookie used as resource owner | F001 | medium | only code path; session origin unprovable (U1) |
| C11 | "List my grants" is 401 because neither `request["userdata"]` nor `request.user` is set | F008, F004 | high | code read |
| C12 | `userinfo` returns `""` claims because `user_from_id` fails and `_claim` defaults to `""` | F008 | high | code read; body matches |
| C13 | Fixing only the example turns the 500 into a 401 while user 35 stays unresolvable | F005, F014 | medium | inferred from loop order + `Oauth2Provider.authenticate` |
| C14 | None of the failing paths changed after d3f85ba — latent, not regressions | F012, F013, F014 | high | `git log -L` |
| C15 | Existing 3LO tests are mock-only; nothing covers the loop, APIKeyAuth with an OAuth2 bearer, NoAuth or `allow_hosts` | F009 | high | file read; greps empty |
| C16 | TrocToken/TokenAuth middlewares pass the 3LO bearer through and cause nothing | F011 | medium | entry points read, deeper paths not traced |
| C17 | "code_verifier required." is the provider correctly enforcing RFC 7636 | F017 | high | branch read; string matches |
| C18 | No page in the `oauth2_server.py` walk-through sends a `code_verifier`; `oauth2_3lo_app.html` has a working in-browser PKCE to reuse | F017 | high | files read/grepped |

Distribution: **15** high, **3** medium, **0** low. The overall confidence is medium because
C10 (how the unresolvable user got in) is medium. The U3 decision makes the fix the same
whatever the answer, so it does not block the spec.

---

## 5. Open Questions

### Resolved (during proposal phase)

- [x] **Should `@is_authenticated()` reject anonymous results (NoAuth guest) from its
  backend loop, keeping the exclude list / `allow_anonymous` as the only ways to admit
  anonymous callers?** — *Resolved*: "Reject anonymous (Recommended)" — the loop treats a
  guest/unauthenticated result as failure and answers 401.
  *Resolves claims*: C7
- [x] **When the resource owner cannot be resolved by the IdP, what should the provider
  do?** — *Resolved*: "Validate at authorize (Recommended)":
  - `/oauth2/authorize` checks the session user with the IdP; if the user is unknown, it drops the session and sends the browser to login.
  - The token and refresh grants fail with `invalid_grant` instead of issuing a session-less token.

  *Resolves claims*: C8, C10

### Unresolved (defer to spec / implementation)

- [ ] **Was the browser already logged in to another Navigator app on `localhost:5000` (same
  Redis) as user 35, with no demo login form shown?** — *Owner*: Jesus Lara.
  User answered "not sure". **Non-blocking**: the U3 decision covers this case and any other source of an unresolvable user.
  *Blocks claims*: C10 (confidence only).
  *Plausible answers*: a) yes, another app on :5000 · b) no, logged in with demo/demo123 — then re-investigate · c) unknown
- [ ] **When one backend in the `is_authenticated` loop raises an unexpected (non-`AuthException`)
  error, should the loop log it and continue to the next backend, or still fail, but with a 401 rather than a 500?**
  — *Owner*: tbd (spec).
  *Blocks claims*: none (fix item 4).
  *Plausible answers*: a) log at warning and continue · b) log and answer 401 · c) only fix APIKeyAuth, leave the loop strict

---

## 6. Recommended Next Step

**`/sdd-spec FEAT-108`** — *Rationale*: localization is high-confidence (15 of 18 claims),
both behaviour decisions are resolved, and the fix set is bounded: two examples, `api.py`,
`decorators.py`, the exempt branch in `auth.py`, and the 3LO paths of `oauth2/backend.py`. No
architectural fork is left to explore.

### Alternatives

- **`/sdd-brainstorm FEAT-108`** — if you want to revisit the `is_authenticated` backend-loop
  design itself, for example making it dispatch on the request's auth mechanism instead of
  trying every backend.
- **`/sdd-task FEAT-108`** — not recommended: the change crosses 6+ files and alters two
  library behaviours that need explicit acceptance criteria.
- **Manual review** — not needed; research was not truncated.

---

## 7. Research Audit

| Artifact | Path |
|----------|------|
| State checkpoints | `sdd/state/FEAT-108/state.json` |
| Source (raw, redacted) | `sdd/state/FEAT-108/source.md` |
| Research plan | `sdd/state/FEAT-108/research_plan.json` |
| Findings (digests) | `sdd/state/FEAT-108/findings/F001-*.md` … `F017-*.md` |
| Lane originals (pre-merge) | `sdd/state/FEAT-108/findings/.audit/` |
| Synthesis (JSON) | `sdd/state/FEAT-108/synthesis.json` |

**Budget consumed** (profile `default`):
- Files read: 19 / 40
- Grep calls: 21 / 25
- Git calls: 17 / 10 — **over budget** (the git lane used 15 against its quota of 10)
- Wall time: the codebase lane ran 315 s against its 255 s quota, which is also over the 300 s profile
- Truncated: **no** — all 24 planned and follow-up queries ran

**Execution**: research ran in three parallel lanes (codebase, git, wiki). Their 24 findings
were merged into 16 (F001–F016). F017 was added in the parent session after a mid-run user report
(Q040–Q042). Citations were re-verified by `sdd-contract-probe` (40 checks).

**Mode determination**: `auto` resolved to `investigation` (error reports: "500 internal
server error", "instead 401, a 200 OK").

---

## 8. Provenance

| Field | Value |
|-------|-------|
| Generated by | `/sdd-proposal v1.0` |
| Synthesis prompt | `sdd/templates/synthesis.prompt.md v1.0` |
| Plan prompt | `sdd/templates/research_plan.prompt.md v1.0` |
| Schema versions | state=1.0, synthesis=1.0, research_plan=1.0 |
| Operator | Jesus Lara / Claude (Opus 5.5) |
