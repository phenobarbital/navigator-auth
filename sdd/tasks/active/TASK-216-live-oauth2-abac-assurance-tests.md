# TASK-216: End-to-end AC27/AC29 — fresh-factor ABAC with really minted OAuth2 tokens

**Feature**: FEAT-114 — Live end-to-end OAuth2 MFA tests for the FEAT-106 review fixes
**Spec**: `sdd/specs/tests-test-mfa-review-fixes-oauth2-fixes.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-215
**Assigned-to**: unassigned
**Discovered-from**: `issue:1a329591f638`

---

## Context

Ledger issue `issue:1a329591f638` also says: *"TASK-187 has no real end-to-end OAuth token-minting
test for AC27/AC29."* TASK-187's Completion Note confirms it: the AC27/AC29 tests in
`tests/test_mfa_review_fixes_oauth2_tokens.py` feed hand-written claims to a `_FakeRequest`. No test
proves that a token minted by `/oauth2/token` after a real TOTP, trusted-device or password-only
browser login is evaluated, through the real `_auth_middleware` and `EvalContext`, without borrowing
the identity-shared session's assurance.

This task implements spec **Module 2** (AC5, AC6) using TASK-215's `oauth_live` harness.

---

## Scope

- Append `test_oauth2_live_abac_fresh_factor` (spec AC5 = FEAT-106 AC27) and
  `test_oauth2_live_assurance_isolation` (spec AC6 = FEAT-106 AC29) to
  `tests/test_mfa_review_fixes_oauth2.py`, plus at most two small private helpers
  (`_oauth_claims`, `_drop_session`).

**NOT in scope**: the harness (TASK-215), production code, the unit-level AC27/AC29 tests in
`tests/test_mfa_review_fixes_oauth2_tokens.py` (they stay).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_mfa_review_fixes_oauth2.py` | MODIFY | AC27 and AC29 end-to-end tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `d179984` (dev). TASK-215 symbols are created by the dependency — verify they landed.

### Verified Imports
```python
# all already imported by the module after TASK-215:
import jwt, secrets, redis.asyncio as aioredis
from navigator_auth.mfa.types import PROVIDER_TOTP, TRUSTED_COOKIE, MfaMode
from tests.test_mfa_e2e import Live, requires_fresh_factor
```

### Existing Signatures to Use
```python
# Created by TASK-215 in tests/test_mfa_review_fixes_oauth2.py (verify they landed):
OAUTH_CLIENT_ID; OAUTH_REDIRECT; EVALCTX_PATH; live_test(func)
class OAuthLive(Live):
    provider -> Oauth2Provider
    def authorize_params(self) -> tuple[dict, str]
    async def grant(self, user) -> None
    async def oauth_login(self, user, params, *, cookies=None)
    async def oauth_mfa(self, params, challenge, provider, code, *, remember=False)
    async def challenge_of(response) -> str   (staticmethod)
    async def mint(self, login_response, verifier) -> str
    async def evalctx(self, token) -> dict    # keys: mechanism, mfa, amr, fresh, session_mfa, session_amr
@pytest_asyncio.fixture oauth_live

# tests/test_mfa_e2e.py
class Live:
    async def user(self, **kwargs) -> dict                            # line 181
    async def org(self, *members, mode=MfaMode.OFF, remember_days=0)  # line 198
    def totp(self, secret_b32) -> str                                 # line 270 — advances the frozen clock 30 s
    async def plain_login(self, user) -> str                          # line 285 (BasicAuth, no factor owed)
    async def totp_login(self, user, secret, *, remember=False)       # line 298 -> (response, body) of /auth/mfa/verify
    async def enrol_totp(self, user, token) -> tuple[str, list[str]]  # line 304
# trusted devices need an OPTIONAL tenant with remember_days=30: tests/test_mfa_e2e.py:569-586

# navigator_auth/mfa/state.py:136-144 — OPTIONAL + no TOTP -> MfaState.NONE (no factor owed); + TOTP -> TOTP
# navigator_auth/backends/oauth2/backend.py:2201-2203 — mfa/amr claims only when the code carries both
# navigator_session/storages/redis.py — new_session reuses the id at f"user:{identity}"; a later new_session
#   OVERWRITES session data; keys f"session:{session_id}", f"user:{identity}"
# session storage Redis pool: request.app["auth"].session.storage._redis  (aioredis.ConnectionPool)
#   (verify the attribute path before use: navigator_auth/backends/oauth2/backend.py:655 reads
#    request.app["auth"].session.storage; RedisStorage keeps its pool in self._redis)
```

### Does NOT Exist
- ~~a password-only OAuth login for a TOTP-enrolled user~~ — enrolment makes every later login owe a
  factor; mint the password-only token BEFORE enrolling.
- ~~assurance in the OAuth-created session~~ — the OAuth flow stores mfa/amr only in the auth-event
  record. Only a BasicAuth/passkey login writes them into `AUTH_SESSION_OBJECT`.
- ~~a first-class `amr` on `EvalContext`~~ — read it from `ctx.userinfo` (the route already does).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "tests/test_mfa_review_fixes_oauth2.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:tests/test_mfa_e2e.py#Live",
    "sym:tests/test_mfa_e2e.py#requires_fresh_factor",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_authorization_code",
    "sym:navigator_auth/auth.py#AuthHandler._auth_middleware"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- One user per test, in `live.org(uid, mode=MfaMode.OPTIONAL, remember_days=30)`; `await live.grant(user)`
  before the first mint. Use a fresh `authorize_params()` pair for every mint.
- AC6 order (spec §7) — sessions are identity-shared and a later `new_session` overwrites them:
  1. OAuth login, no factor owed → `pwd = mint(...)`;
  2. `enrol_totp(user, await live.plain_login(user))`;
  3. OAuth TOTP login with `remember=True` → `totp1`, keep `TRUSTED_COOKIE` from the 302;
  4. OAuth login with the trusted cookie → 302 directly → `trusted`;
  5. OAuth TOTP login without the cookie → `totp2`;
  6. LAST: `live.totp_login(user, secret)` (BasicAuth) → assert through `evalctx(pwd)` that
     `session_mfa is True` and `"totp" in session_amr` (the precondition; never pass vacuously);
  7. assert `fresh` is False for `pwd`/`trusted` and True for `totp1`/`totp2`, with
     `mechanism == "bearer"`;
  8. delete `session:<sid>` and `user:<username>` via the session storage's Redis pool, then re-run
     step 7 (each first request recreates the session from the token).
- Claims: decode with `jwt.decode(token, options={"verify_signature": False})`. Signature and
  validity are the middleware's job; this keeps the test independent of HS256/RS256 deployment.
- Never print or log tokens or codes.

---

## Implementation Blueprint

### Steps (in order)
1. Add `_oauth_claims` and `_drop_session` helpers — *why*: both tests read claims; AC6 needs session recreation.
2. Write `test_oauth2_live_abac_fresh_factor` (AC5) — *why*: proves each login type's claims and the ABAC verdict.
3. Write `test_oauth2_live_assurance_isolation` (AC6) — *why*: proves no borrowing across tokens, mint order, recreation.
4. Run the Validation Commands.

### `tests/test_mfa_review_fixes_oauth2.py` (MODIFY) — append at end of file
```python
# occurrences: 1 (verified after TASK-215: grep -c 'async def test_oauth2_login_single_connection_pool(' tests/test_mfa_review_fixes_oauth2.py)
# AFTER — append at end of file, below the body of `test_oauth2_login_single_connection_pool` (TASK-215)


def _oauth_claims(token: str) -> dict:
    """Unverified claims of a minted token (the middleware verifies; this only reads assurance)."""
    return jwt.decode(token, options={"verify_signature": False})


async def _drop_session(live: "OAuthLive", user: dict, session_id: str) -> None:
    """Delete the identity-shared session so the next bearer request recreates it from the token."""
    # FILL IN: pool = live.app["auth"].session.storage._redis (verify path); async with aioredis.Redis(connection_pool=pool)
    #   as r: await r.delete(f"session:{session_id}", f"user:{user['username']}")


async def _totp_mint(live: "OAuthLive", user: dict, secret: str, *, remember: bool = False):
    """OAuth TOTP login -> (access_token, response of /oauth2/login/mfa)."""
    # FILL IN: params, verifier = live.authorize_params(); page = await live.oauth_login(user, params) -> 200;
    #   response = await live.oauth_mfa(params, await live.challenge_of(page), PROVIDER_TOTP, live.totp(secret),
    #   remember=remember) -> 302; return await live.mint(response, verifier), response


@live_test
async def test_oauth2_live_abac_fresh_factor(oauth_live):
    """FEAT-106 AC27 end to end: a TOTP-login token is fresh; trusted-device and no-MFA tokens are not."""
    # FILL IN: OPTIONAL org (remember_days=30) + grant; no-factor login -> 302 -> plain token (no mfa/amr claims);
    #   enrol TOTP; _totp_mint(remember=True) -> totp token (mfa True, amr [pwd,totp]) + trusted cookie;
    #   oauth_login with trusted cookie -> 302 -> trusted token (amr [pwd,trusted_device]);
    #   evalctx: fresh True only for totp; mechanism "bearer" for all


@live_test
async def test_oauth2_live_assurance_isolation(oauth_live):
    """FEAT-106 AC29 end to end: weaker tokens stay denied before/after TOTP mints, with the shared session
    holding a TOTP login's assurance, and after the session is recreated from each token."""
    # FILL IN: the 8 steps of Key Constraints; session_id from _oauth_claims(pwd)["session_id"]
```

### FILL IN checklist
- [ ] `_drop_session` — Redis pool path verified before use; bounded by AC6 "session recreation".
- [ ] `_totp_mint` — statuses asserted at each hop; bounded by AC5.
- [ ] AC5 body — claims and verdicts for the three login types; bounded by AC5.
- [ ] AC6 body — order, precondition, recreation; bounded by AC6.

---

## Acceptance Criteria

- [ ] Spec AC5 (`test_oauth2_live_abac_fresh_factor`) and AC6 (`test_oauth2_live_assurance_isolation`)
      pass on live Postgres + Redis; AC6 asserts its shared-session precondition.
- [ ] Both skip (not fail) without live services (inherited from `oauth_live`).
- [ ] `tests/test_mfa_review_fixes_oauth2_tokens.py` still passes unchanged.
- [ ] `flake8 tests/test_mfa_review_fixes_oauth2.py` reports nothing.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_oauth2.py -q`
- `pytest tests/test_mfa_review_fixes_oauth2_tokens.py -q`

---

## Test Specification

```python
# AC5: claims(plain) has no "mfa"/"amr"; claims(totp)["amr"] == ["pwd", "totp"]; claims(trusted)["amr"] == ["pwd", "trusted_device"]
#      evalctx(totp)["fresh"] is True; evalctx(trusted)["fresh"] is False; evalctx(plain)["fresh"] is False
# AC6: precondition evalctx(pwd)["session_mfa"] is True and "totp" in evalctx(pwd)["session_amr"]
#      fresh: pwd False, trusted False, totp1 True, totp2 True — before and after _drop_session
```

---

## Agent Instructions

1. **Work in the feature worktree** — `parrot sdd worktree ensure --slug tests-test-mfa-review-fixes-oauth2-fixes --feature-id FEAT-114`.
2. **Read the spec** (§3 M2, §5 AC5–AC6, §7 "AC6 ordering").
3. **Check dependencies** — TASK-215 must be `"done"` in the per-spec index.
4. **Verify the Codebase Contract** (TASK-215 symbols landed; session storage pool path).
5. **Update status** → `"in-progress"`; commit only the index file.
6. **Implement** from the blueprint; complete every `# FILL IN:`.
7. **Verify** — Validation Commands; `flake8` on the file.
8. **Commit the code** — stage only `tests/test_mfa_review_fixes_oauth2.py`.
9. **Close** — `parrot sdd task close TASK-216 tests-test-mfa-review-fixes-oauth2-fixes verified`.
10. **Fill in the Completion Note**, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
