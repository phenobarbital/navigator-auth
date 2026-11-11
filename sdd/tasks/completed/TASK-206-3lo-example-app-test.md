# TASK-206: App-level test drives the fixed 3LO example end to end

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-195, TASK-199, TASK-202, TASK-204
**Assigned-to**: unassigned

---

## Context

Spec G8, §3 Module 8, §4 Integration Tests, AC18. The seven symptoms were found by pressing the six
buttons of `examples/oauth2_3lo_server.py`. This task boots that example with `aiohttp`'s `TestClient`
and asserts each button's outcome, so a regression in any of the fixes (pinned backends, the
`@is_authenticated` loop, the exempt-branch `userdata`, the owner checks and session binding) fails here.
It extends `tests/test_oauth2_3lo_example.py`, created by TASK-195 (which owns `_load_example()`).

**Exclusive task** (`parallel: false`): sessions live in the local Redis, the same resource as
`tests/test_auth_middleware_mechanism.py`.

---

## Scope

- Add a `pytest_asyncio` fixture `example_client` that loads the example, builds `make_app()`, and starts a
  `TestClient` (Redis required; skip cleanly when unavailable).
- Make JWTs independent of the developer's `env/.env`: patch `navigator_auth.backends.idp.SECRET_KEY`
  to a ≥ 32-byte value for the fixture's lifetime (`filterwarnings = ["error"]` turns a short key into
  `InsecureKeyLengthWarning` errors — this is why 6 tests already fail locally on `dev`).
- Drive the flow: login form (demo / demo123) → authorize → consent approve → code → token (PKCE S256) →
  the six checks below; plus the foreign-session regression (S5).

**NOT in scope**: changing the example or library code (all fixes are in the dependency tasks); the
`oauth2_server.py` walk-through (TASK-196 covers it with page-content tests).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_oauth2_3lo_example.py` | MODIFY | `example_client` fixture + AC18 integration tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` (2026-11-11). Example files are not touched by FEAT-106.

### Verified Imports
```python
import pytest_asyncio                                   # verified: tests/test_auth_middleware_mechanism.py:22
from aiohttp import DummyCookieJar, web                 # verified: tests/test_auth_middleware_mechanism.py:23
from aiohttp.test_utils import TestClient, TestServer   # verified: tests/test_auth_middleware_mechanism.py:24
from navigator_auth.backends.oauth2.pkce import generate_challenge   # verified: tests/test_oauth2_access_gate.py:317
import navigator_auth.backends.idp as idp_module        # SECRET_KEY bound at module level: navigator_auth/backends/idp/__init__.py:30
```

### Existing Signatures to Use
```python
# tests/test_oauth2_3lo_example.py (TASK-195)
def _load_example() -> ModuleType                       # imports examples/oauth2_3lo_server.py by path

# examples/oauth2_3lo_server.py
CLIENT_ID = "nav_example_spa"; REDIRECT_URI = f"{BASE_URL}/callback"; SCOPES = "default profile email offline_access"   # :77-79
DEMO_USERS = [...]                                      # :86 (demo / demo123, user_id 1 at :88, demo@example.com at :93)
class DemoIdentityProvider(IdentityProvider)            # :106; user_from_id :136 raises UserNotFound for unknown ids
def make_app() -> web.Application                       # :214; registers clients on startup (register_demo_clients)
async def me(request: web.Request, *, session=None, user=None) -> web.StreamResponse   # :178 — GET /api/v1/me → {"user": …, "token_claims": {client_id, scope, jti, aud}}
# Oauth2Provider.grants_uri = "/api/v1/oauth2/grants"   # backend.py:289; list handler docstring :2312

# navigator_auth/backends/oauth2/backend.py — routes used
#   nav_oauth2_login (login_uri), nav_oauth2_authorize (authorize_uri), consent, /oauth2/token,
#   /oauth2/userinfo, GET /api/v1/oauth2/grants (lists the caller's grants; needs request["userdata"])

# Session creation pattern for the foreign-session case: tests/test_auth_middleware_mechanism.py:62-68
#   storage.new_session(request, {SESSION_KEY: identity}); session.save_encoded_data(request, "user", user)
```

### Does NOT Exist
- No test imports or boots an example module apart from TASK-195's loader.
- ~~`examples/__init__.py`~~ — `examples/` is not a package; always load by path.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "tests/test_oauth2_3lo_example.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:examples/oauth2_3lo_server.py#make_app",
    "sym:examples/oauth2_3lo_server.py#DemoIdentityProvider"
  ]
}
```

---

## Implementation Notes

- Run the whole browser leg with one cookie-carrying client (a real `CookieJar`): the login sets the
  session cookie that `/oauth2/authorize` reads. Use `allow_redirects=False` and assert each `Location`.
- Parse the consent page / redirects for the parameters instead of hard-coding the code.
- Never log or print tokens in test output.

---

## Implementation Blueprint

### Steps (in order)
1. Add the fixture (SECRET_KEY patch, Redis skip, TestClient start/close) — *why*: AC18 needs a live app.
2. Add a `_login_and_get_tokens(client)` helper driving login → authorize → consent → token with PKCE.
3. Add the seven tests; run the file with Redis up.

### `tests/test_oauth2_3lo_example.py` (MODIFY) — append
```python
# --- FEAT-108 M8: app-level 3LO flow (Redis) -------------------------------------------------
import secrets  # noqa: E402  (merge into the top-level imports)

import pytest_asyncio  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

import navigator_auth.backends.idp as idp_module  # noqa: E402
from navigator_auth.backends.oauth2.pkce import generate_challenge  # noqa: E402

_TEST_SECRET = "feat108-" + "k" * 40   # >= 32 bytes: filterwarnings=error rejects short HMAC keys


@pytest_asyncio.fixture
async def example_client(monkeypatch):
    monkeypatch.setattr(idp_module, "SECRET_KEY", _TEST_SECRET)
    example = _load_example()
    app = example.make_app()
    client = TestClient(TestServer(app))
    # FILL IN: start the server; skip the test (pytest.skip) when Redis is unreachable, using the same
    #          detection tests/test_auth_middleware_mechanism.py relies on; yield (client, example); close.


async def _login_and_get_tokens(client, example) -> dict:
    """Drive login → authorize → consent → token with PKCE S256; return the token response JSON."""
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(12)
    authorize = {
        "response_type": "code",
        "client_id": example.CLIENT_ID,
        "redirect_uri": example.REDIRECT_URI,
        "scope": example.SCOPES,
        "state": state,
        "code_challenge": generate_challenge(verifier),
        "code_challenge_method": "S256",
    }
    # FILL IN: POST /oauth2/login (demo / demo123 + authorize fields) → follow to /oauth2/authorize →
    #          POST consent approve → read `code` and check `state` from the redirect to REDIRECT_URI →
    #          POST /oauth2/token (form) with code, client_id, redirect_uri, code_verifier=verifier.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_3lo_me_with_bearer_200(example_client):
    # FILL IN: 200; user.username == "demo"; token_claims.client_id == "nav_example_spa"; jti and scope non-null — AC18.
    pass


@pytest.mark.asyncio
async def test_3lo_me_without_credentials_401(example_client):
    # FILL IN: no header, no cookie ⇒ 401 — AC18.
    pass


@pytest.mark.asyncio
async def test_3lo_list_grants_200(example_client):
    # FILL IN: GET /api/v1/oauth2/grants with the bearer ⇒ 200 listing nav_example_spa — AC18 (S3).
    pass


@pytest.mark.asyncio
async def test_3lo_userinfo_profile(example_client):
    # FILL IN: /oauth2/userinfo ⇒ sub == "1", username == "demo", email == "demo@example.com" — AC18 (S4).
    pass


@pytest.mark.asyncio
async def test_3lo_refresh_binds_session(example_client, caplog):
    # FILL IN: refresh grant ⇒ new access token accepted by /api/v1/me; no "cannot bind a session" in caplog — AC18 (S5).
    pass


@pytest.mark.asyncio
async def test_3lo_foreign_session_forces_login(example_client):
    # FILL IN: create a Redis session whose user the demo IdP does not know (e.g. user_id 35) on the client's
    #          cookie, then GET /oauth2/authorize ⇒ 302 to the login form keeping client_id/state/code_challenge;
    #          no code issued — AC11 / S5 regression.
    pass
```
**Why**: `_login_and_get_tokens` is shared so each test asserts one outcome, mirroring one button.

### FILL IN checklist
- [ ] Fixture start/skip/close; AC18.
- [ ] `_login_and_get_tokens` full browser leg; AC18.
- [ ] Six button tests + foreign-session test; AC18, AC11.

---

## Acceptance Criteria

- [ ] AC18: with the fixed example, after login as `demo` / `demo123`: `/api/v1/me` with a bearer → 200 with `token_claims.client_id`, `scope`, `jti` non-null; without credentials → 401; `GET /api/v1/oauth2/grants` → 200 listing `nav_example_spa`; `/oauth2/userinfo` → the demo profile; a refresh grant logs no "cannot bind a session" warning.
- [ ] A pre-existing session for a user the demo IdP does not know is sent to the login form by `/oauth2/authorize`.
- [ ] The tests pass regardless of the local `AUTH_SECRET_KEY` length (SECRET_KEY patched).
- [ ] `ruff check tests/test_oauth2_3lo_example.py` clean.

---

## Validation Commands

- `pytest tests/test_oauth2_3lo_example.py -q`

---

## Test Specification

Spec §4 Integration Tests: `test_3lo_me_with_bearer_200`, `test_3lo_me_without_credentials_401`,
`test_3lo_list_grants_200`, `test_3lo_userinfo_profile`, `test_3lo_refresh_binds_session`,
`test_3lo_foreign_session_forces_login`.

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` / line reference before editing; a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands with Redis running.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-206 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none

## Completion Note

Delivered by gpt-5.6-terra (1 attempt), engine task-tier validation passed, merged.
