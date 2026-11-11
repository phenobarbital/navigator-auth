# TASK-215: Live OAuth2 harness and TASK-184 live MFA tests (e-mail OTP, replay, event record, AC10)

**Feature**: FEAT-114 — Live end-to-end OAuth2 MFA tests for the FEAT-106 review fixes
**Spec**: `sdd/specs/tests-test-mfa-review-fixes-oauth2-fixes.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:1a329591f638`

---

## Context

Ledger issue `issue:1a329591f638` (feature_gap, minor, from `spec:FEAT-106`): *"TASK-184 test spec
live-Postgres AC10 single_connection_authdb test and live email-OTP/replay checks were not written
(tests are mock-based) …"*. TASK-184's Completion Note records the same deviation. Today
`tests/test_mfa_review_fixes_oauth2.py` drives `Oauth2Provider` with a stubbed `SecondFactorGate`
(`_FakeGate`) and lease, so the real gate, OTP delivery, challenge single-use, auth-event storage and
the one-connection lock property (AC10) are untested on the OAuth2 path.

This task implements spec **Module 1**: a reusable live harness (real
`AuthHandler(BasicAuth + Oauth2Provider)` on live Postgres + Redis, driven over HTTP) plus the
live tests for spec **AC1, AC2, AC3, AC4, AC7, AC9**. TASK-216 reuses the harness for AC27/AC29.

---

## Scope

- Update the module docstring of `tests/test_mfa_review_fixes_oauth2.py`. It currently says the
  module needs neither Postgres nor Redis. Mock tests still need neither; the new live section
  skips without them.
- Extend the import block (top of file, so flake8 E402 never fires).
- Append a "Live Postgres + Redis" section with: constants, `live_test` decorator,
  `_start_oauth`, `_stop_oauth`, `_oauth_evalctx_view`, `OAuthLive(Live)`, the `_oauth_env` async
  context manager, the `oauth_live` fixture, and three tests:
  `test_oauth2_live_email_otp_single_delivery_and_replay` (AC1, AC2),
  `test_oauth2_live_event_record` (AC3), `test_oauth2_login_single_connection_pool` (AC4).

**NOT in scope**: AC27/AC29 tests (TASK-216); any production code change; editing
`tests/test_mfa_e2e.py` or `tests/fixtures/mfa.py`; deleting or changing existing mock tests.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_mfa_review_fixes_oauth2.py` | MODIFY | docstring, imports, live harness, AC1–AC4 live tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `d179984` (dev).

### Verified Imports
```python
import asyncio, hashlib, re, secrets, warnings                            # stdlib
import jwt                                                                # used by tests/test_mfa_e2e.py:30
import pytest_asyncio                                                     # used by tests/test_mfa_e2e.py:32
import redis.asyncio as aioredis                                          # used by tests/test_mfa_e2e.py:33
from aiohttp.test_utils import TestClient, TestServer                     # verified: tests/test_mfa_e2e.py:35
from navigator_session import AUTH_SESSION_OBJECT, get_session            # verified: tests/test_mfa_e2e.py:38
from navigator_auth import AuthHandler                                    # verified: tests/test_mfa_e2e.py:41
from navigator_auth.abac.context import EvalContext                       # verified: tests/test_mfa_e2e.py:42
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage   # verified: client_backend.py:76
from navigator_auth.backends.oauth2.models import OAuthClient, OauthGrant       # verified: models.py:72, :300
from navigator_auth.backends.oauth2.pkce import generate_challenge              # verified: pkce.py:49
from navigator_auth.conf import AUTH_MECHANISM_KEY                        # verified: auth.py imports it from .conf
from navigator_auth.mfa.services import get_mfa_services                  # verified: mfa/services.py:205
from navigator_auth.mfa.types import PROVIDER_EMAIL, PROVIDER_TOTP, TRUSTED_COOKIE, MfaMode  # verified: tests/test_mfa_e2e.py:56-63
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, single_connection_authdb,
)                                                                         # verified: tests/fixtures/mfa.py:24,38,61,103,120,194
from tests.test_mfa_e2e import CAPTURED, Live, _patch_settings, _stop, requires_fresh_factor
                                                                          # verified: tests/test_mfa_e2e.py:100,165,369,398,123
# already imported by the module (keep): conf, oauth_backend, OAUTH2_EVENT_COOKIE, OAUTH2_EVENT_KEY_PREFIX,
#   Oauth2Provider, TRUSTED_COOKIE, pytest, web, parse_qs, urlparse          (tests/test_mfa_review_fixes_oauth2.py:8-27)
```

### Existing Signatures to Use
```python
# tests/test_mfa_e2e.py
CAPTURED: list = []                                                   # line 100 — _capture_otp appends here
def requires_fresh_factor(ctx) -> bool                                # line 123
class Live:                                                           # line 165
    def __init__(self, app, auth, client, services, db, clock, factory, abac)   # line 168
    async def user(self, **kwargs) -> dict                            # line 181 (records user for cleanup)
    async def org(self, *members, mode=MfaMode.OFF, remember_days=0) -> int     # line 198
    def _no_jar(self) -> None                                         # line 232
    def emails(user) -> list  (staticmethod)                          # line 276 — reads module CAPTURED
    async def cleanup(self) -> None                                   # line 343
def _patch_settings(monkeypatch, *, enabled, secret) -> None          # line 369 — sets AUTHENTICATION_BACKENDS=BasicAuth only
async def _stop(auth, client) -> None                                 # line 398
# skip recipe to mirror: live fixture lines 432-442 (start failure / services unavailable / no vault_keyring)

# tests/fixtures/mfa.py
class _LockAwarePool: strict; acquires; acquires_inside_lock          # line 77
async def single_connection_authdb()                                  # line 103

# navigator_auth/auth.py
class AuthHandler:
    def __init__(self, ..., secure_cookies: bool = True, ..., backends=None, ..., enable_authdb: bool = True)  # lines 103-108
    # line 173: session storage built with use_cookies=self.secure_cookies — secure_cookies=False sets NO session
    #   cookie, which breaks the /oauth2/login -> /oauth2/authorize hop. The OAuth harness MUST use True.
    backends: dict  # auth.backends["BasicAuth"], auth.backends["Oauth2Provider"]

# navigator_auth/backends/oauth2/backend.py
OAUTH2_EVENT_COOKIE = "nav_oauth2_event"; OAUTH2_EVENT_KEY_PREFIX = "oauth2:event:"   # 178-179
class Oauth2Provider:
    client_storage; grant_storage                                     # set in on_startup 435-445 (grants: Redis always, code_backend.py:507)
    async def _issue_auth_event(...)                                  # 722 — key = prefix + sha256(handle).hexdigest()
    flow_store (property) -> IdentityFlowStore                        # 1277 — lazily built, NOT closed by on_cleanup
    async def auth_login_mfa(self, request)                           # 1944 — replay -> _render_login_error 401 (1987-1992)
    async def auth_login(self, request)                               # 1999 — form POST; 2FA on -> gate

# navigator_auth/identity/flow_store.py
class IdentityFlowStore:
    def __init__(self, pool)  -> self._pool                           # line 21-22
    async def get(self, key) -> Optional[dict]                        # line 28

# templates/oauth/mfa.html:18 — <input type="hidden" name="challenge" value="{{ challenge }}">
# navigator_auth/mfa/state.py:136-144 — OPTIONAL/OFF tenant + no TOTP -> MfaState.NONE (no factor); ENFORCED -> EMAIL
```

### Does NOT Exist
- ~~`tests/test_mfa_e2e.py::_start(app, backends=...)`~~ — `_start` takes no backends and pins BasicAuth; write `_start_oauth`.
- ~~`Oauth2Provider.on_cleanup` closing `_flow_store`~~ — `_stop_oauth` must disconnect `provider._flow_store._pool`.
- ~~a consent bypass flag~~ — consent is skipped only by an unrevoked grant covering the scopes (backend.py:1628-1648).
- ~~a JSON challenge body from `/oauth2/login`~~ — it renders HTML; read the challenge from the hidden input.
- ~~`Live.oauth_*` helpers~~ — created here, on `OAuthLive`.

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
    "sym:tests/test_mfa_e2e.py#_patch_settings",
    "sym:tests/test_mfa_e2e.py#_stop",
    "sym:tests/test_mfa_e2e.py#requires_fresh_factor",
    "sym:tests/fixtures/mfa.py#single_connection_authdb",
    "sym:tests/fixtures/mfa.py#_LockAwarePool",
    "sym:navigator_auth/auth.py#AuthHandler",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.auth_login",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.auth_login_mfa",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._issue_auth_event",
    "sym:navigator_auth/identity/flow_store.py#IdentityFlowStore"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
- `tests/test_mfa_e2e.py::live` (lines 421-451): settings patch, skip conditions, frozen TOTP clock,
  e-mail callback repoint, teardown order.
- `tests/test_password_recovery.py:1430-1472`: AC10 assertion shape (`asyncio.wait_for(..., 10)`,
  `acquires_inside_lock == []`).

### Key Constraints
- `AuthHandler(secure_cookies=True, ...)`: session cookies exist only when secure_cookies is True
  (auth.py:173). Cookies are always passed explicitly (`self._no_jar()` before every request);
  every OAuth request uses `allow_redirects=False`.
- After `_patch_settings(...)`, override `conf.AUTHENTICATION_BACKENDS` to `OAUTH_BACKENDS`.
- Set `_callbacks = None` on both backends after startup (production success callbacks reach
  services unavailable in tests — see `_start`, tests/test_mfa_e2e.py:391-393).
- AC4: `enable_authdb=False` and `app["authdb"] = single_connection_authdb` BEFORE startup; set
  `strict = True` and clear `acquires_inside_lock` only right before the two measured calls
  (startup and the test-data helpers acquire legitimately).
- Every new def that takes an imported fixture gets `# noqa: F811` (flake8 does not honour
  `# ruff: noqa`; baseline shows F811 in tests/test_mfa_e2e.py).
- Warnings are errors (pyproject `filterwarnings = ["error", ...]`). Live tests carry
  `filterwarnings("ignore::DeprecationWarning")` and
  `filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")` through `live_test`, like
  tests/test_mfa_e2e.py:76-81, so the existing mock tests keep strict warnings.
- Never print or log OTP codes, tokens, handles or cookies.
- A live failure that reveals a production defect: `xfail(strict=True, reason="issue:<id>")`, open a
  ledger issue, note it in the Completion Note — never patch production code here.

---

## Implementation Blueprint

### Steps (in order)
1. Update the module docstring — *why*: it would otherwise claim the module never needs Postgres/Redis.
2. Extend the import block at the top — *why*: imports mid-file trip flake8 E402.
3. Append the harness block, then the tests block — *why*: TASK-216 appends after these and reuses the harness.
4. Run the Validation Commands with live Postgres + Redis, then once with the harness forced to skip
   (e.g. `REDIS_AUTH_URL` unreachable is not required — confirming the skip recipe by reading is enough).

### `tests/test_mfa_review_fixes_oauth2.py` (MODIFY) — docstring
```python
# occurrences: 1 (verified: grep -c 'These tests drive ``Oauth2Provider`` with a real aiohttp router/request and a stubbed' tests/test_mfa_review_fixes_oauth2.py)
# REPLACE lines 3-5 (the paragraph starting with that anchor) with:
The first part drives ``Oauth2Provider`` with a real aiohttp router/request and a stubbed
``SecondFactorGate`` / MFA lease; it needs neither Postgres nor Redis. The "Live Postgres +
Redis" part (FEAT-114) drives a real ``AuthHandler(BasicAuth + Oauth2Provider)`` over HTTP and
skips when Postgres, Redis, the MFA services or the Vault keyring are unavailable. Settings are
patched with ``monkeypatch`` (restored automatically).
```

### `tests/test_mfa_review_fixes_oauth2.py` (MODIFY) — imports
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.types import TRUSTED_COOKIE' tests/test_mfa_review_fixes_oauth2.py)
# REPLACE `from navigator_auth.mfa.types import TRUSTED_COOKIE` (verified: line 27) with the block below, and add
# `import asyncio`, `import hashlib`, `import re`, `import secrets`, `import warnings` to the stdlib group,
# `import jwt`, `import pytest_asyncio`, `import redis.asyncio as aioredis` to the third-party group,
# `from aiohttp.test_utils import TestClient, TestServer, make_mocked_request` (replacing line 17),
# `from navigator_session import AUTH_SESSION_OBJECT, get_session` after `from aiohttp import web`.
from navigator_auth import AuthHandler
from navigator_auth.abac.context import EvalContext
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage
from navigator_auth.backends.oauth2.models import OAuthClient, OauthGrant
from navigator_auth.backends.oauth2.pkce import generate_challenge
from navigator_auth.conf import AUTH_MECHANISM_KEY
from navigator_auth.mfa.services import get_mfa_services
from navigator_auth.mfa.types import PROVIDER_EMAIL, PROVIDER_TOTP, TRUSTED_COOKIE, MfaMode
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
    single_connection_authdb,
)
from tests.test_mfa_e2e import CAPTURED, Live, _patch_settings, _stop, requires_fresh_factor
```
**Why**: one import block; `CAPTURED`/`Live.emails` are the e-mail OTP capture the `_capture_otp`
callback path (`tests.test_mfa_e2e._capture_otp`) writes to.

### `tests/test_mfa_review_fixes_oauth2.py` (MODIFY) — harness (append after the last test)
```python
# occurrences: 1 (verified: grep -c 'def test_mfa_template_escapes_authorize_parameters():' tests/test_mfa_review_fixes_oauth2.py)
# AFTER — append at end of file, below the body of `def test_mfa_template_escapes_authorize_parameters():` (line 301)

# ---------------------------------------------------------------------------
# Live Postgres + Redis (FEAT-114, issue:1a329591f638)
# ---------------------------------------------------------------------------

OAUTH_CLIENT_ID = "mfa-live-oauth-client"
OAUTH_REDIRECT = "https://app.example/cb"
OAUTH_BACKENDS = ("navigator_auth.backends.BasicAuth", "navigator_auth.backends.Oauth2Provider")
EVALCTX_PATH = "/_test/oauth/evalctx"
_CHALLENGE_INPUT = re.compile(r'name="challenge" value="([^"]*)"')


def live_test(func):
    """Mark a live async test with the warning filters tests/test_mfa_e2e.py uses module-wide."""
    func = pytest.mark.filterwarnings("ignore::DeprecationWarning")(func)
    func = pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")(func)
    return pytest.mark.asyncio(func)


async def _oauth_evalctx_view(request: web.Request) -> web.Response:
    """Test-only bearer route: the EvalContext the PDP builds, plus the raw session's assurance."""
    session = await get_session(request, new=False)
    raw = session.get(AUTH_SESSION_OBJECT) if session else None
    raw = raw if isinstance(raw, dict) else {}
    ctx = EvalContext(request, raw, raw, session)
    effective = ctx.userinfo if isinstance(ctx.userinfo, dict) else {}
    return web.json_response(
        {
            "mechanism": request.get(AUTH_MECHANISM_KEY),
            "mfa": bool(ctx.mfa),
            "amr": list(effective.get("amr") or []),
            "fresh": requires_fresh_factor(ctx),
            "session_mfa": bool(raw.get("mfa")),
            "session_amr": list(raw.get("amr") or []),
        }
    )


async def _start_oauth(app: web.Application, *, enable_authdb: bool = True) -> tuple[AuthHandler, TestClient]:
    """Start AuthHandler(BasicAuth + Oauth2Provider); swap in a MemoryClientStorage with one PKCE client."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(secure_cookies=True, backends=OAUTH_BACKENDS, enable_authdb=enable_authdb)
        auth.setup(app)
        client = TestClient(TestServer(app))
        await client.start_server()
    # FILL IN: _callbacks = None on auth.backends["BasicAuth"] and auth.backends["Oauth2Provider"];
    #   provider.client_storage = MemoryClientStorage() holding OAuthClient(client_id=OAUTH_CLIENT_ID,
    #   client_name="MFA live client", client_type="public", redirect_uris=[OAUTH_REDIRECT], default_scopes=["default"])
    return auth, client


async def _stop_oauth(auth: AuthHandler, client: TestClient) -> None:
    """Disconnect the provider's lazily built flow-store pool, then the standard live teardown."""
    # FILL IN: if provider._flow_store is not None: await provider._flow_store._pool.disconnect(); reset to None
    await _stop(auth, client)
```
**Why**: `secure_cookies=True` is required for the browser leg (auth.py:173); the evalctx route is
deliberately NOT in the exclude list so `_auth_middleware` publishes the bearer context (TASK-216).

### `tests/test_mfa_review_fixes_oauth2.py` (MODIFY) — `OAuthLive`, env, fixture, tests (append after the harness)
```python
class OAuthLive(Live):
    """Live app + OAuth2 browser-leg helpers (explicit cookies, never the client jar)."""

    @property
    def provider(self) -> Oauth2Provider:
        return self.auth.backends["Oauth2Provider"]

    def authorize_params(self) -> tuple[dict, str]:
        """Return (the 9 authorize parameters with a real S256 challenge, the code_verifier)."""
        verifier = secrets.token_urlsafe(48)
        params = {
            "client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT, "response_type": "code",
            "state": secrets.token_urlsafe(8), "scope": "default",
            "code_challenge": generate_challenge(verifier), "code_challenge_method": "S256",
            "nonce": secrets.token_urlsafe(8), "prompt": "login",
        }  # fmt: skip
        return params, verifier

    async def grant(self, user: dict) -> None:
        """Pre-seed a grant so /oauth2/authorize issues the code without the consent page."""
        await self.provider.grant_storage.save_grant(
            OauthGrant(user_id=user["user_id"], client_id=OAUTH_CLIENT_ID, scopes=["default"])
        )

    async def oauth_login(self, user: dict, params: dict, *, cookies: dict | None = None):
        """POST /oauth2/login (form); returns the raw response (no redirects followed)."""
        self._no_jar()
        form = {**params, "username": user["username"], "password": user["password_current"]}
        return await self.client.post("/oauth2/login", data=form, cookies=cookies, allow_redirects=False)

    async def oauth_mfa(self, params: dict, challenge: str, provider: str, code: str, *, remember: bool = False):
        """POST /oauth2/login/mfa (form); returns the raw response (no redirects followed)."""
        # FILL IN: self._no_jar(); form = {**params, "challenge", "provider", "code"} plus "remember_device": "1" when remember

    @staticmethod
    async def challenge_of(response) -> str:
        """The challenge token from the rendered oauth/mfa.html hidden input."""
        # FILL IN: match _CHALLENGE_INPUT in await response.text(); assert found

    async def mint(self, login_response, verifier: str) -> str:
        """302 from login -> GET /oauth2/authorize with its cookies -> ?code= -> POST /oauth2/token; return access_token."""
        # FILL IN: assert 302; cookies = {k: m.value for k, m in login_response.cookies.items()};
        #   GET login_response.headers["Location"] (allow_redirects=False, cookies) -> 302 to OAUTH_REDIRECT;
        #   code = parse_qs(urlparse(location).query)["code"][0];
        #   POST /oauth2/token data={grant_type, code, redirect_uri, client_id, code_verifier} -> 200 JSON

    async def evalctx(self, token: str) -> dict:
        """GET the test bearer route; returns its JSON (TASK-216)."""
        self._no_jar()
        response = await self.client.get(EVALCTX_PATH, headers={"Authorization": f"Bearer {token}"})
        assert response.status == 200, await response.text()
        return await response.json()


@asynccontextmanager
async def _oauth_env(monkeypatch, *, db, clock, factory, secret, authdb=None):
    """Yield a started OAuthLive (2FA on, live Postgres + Redis) or skip; always tear down."""
    # FILL IN: mirror tests/test_mfa_e2e.py::live 421-451 — _patch_settings(..., enabled=True, secret=secret);
    #   monkeypatch conf.AUTHENTICATION_BACKENDS = OAUTH_BACKENDS; CAPTURED.clear(); app = web.Application();
    #   app["abac"] = SimpleNamespace(policies=[]); app.router.add_get(EVALCTX_PATH, _oauth_evalctx_view);
    #   if authdb is not None: app["authdb"] = authdb; _start_oauth(app, enable_authdb=authdb is None) (skip on error);
    #   skip on unavailable services / missing app["vault_keyring"] (stop first); freeze TOTP clock + repoint the
    #   e-mail callback to "tests.test_mfa_e2e._capture_otp"; yield OAuthLive(...); finally cleanup, _stop_oauth, CAPTURED.clear()


@pytest_asyncio.fixture
async def oauth_live(monkeypatch, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock):  # noqa: F811
    """A real AuthHandler(BasicAuth + Oauth2Provider) app with 2FA on, on live Postgres + Redis."""
    async with _oauth_env(
        monkeypatch, db=mfa_db, clock=frozen_totp_clock, factory=mfa_user_factory, secret=mfa_secret
    ) as env:
        yield env
```

### `tests/test_mfa_review_fixes_oauth2.py` (MODIFY) — tests (append after the fixture)
```python
@live_test
async def test_oauth2_live_email_otp_single_delivery_and_replay(oauth_live):
    """FEAT-106 AC1/AC2 live: one e-mail OTP, MFA page without session, 302 with the 9 params, replay refused."""
    # FILL IN: user in an ENFORCED org; POST /oauth2/login -> 200, no-store, no Set-Cookie, no Location;
    #   exactly one live.emails(user) to user["email"], code not in repr; POST /oauth2/login/mfa (email code) ->
    #   302 to /oauth2/authorize with params exactly; repeat same POST -> 401, no Location, no event cookie


@live_test
async def test_oauth2_live_event_record(oauth_live):
    """FEAT-106 AC2 live: the event cookie names a Redis record with user_id, mfa true, amr [pwd, otp]."""
    # FILL IN: key = OAUTH2_EVENT_KEY_PREFIX + sha256(handle).hexdigest(); handle not in key;
    #   record = await live.provider.flow_store.get(key)


@live_test
async def test_oauth2_login_single_connection_pool(  # noqa: F811
    monkeypatch, single_connection_authdb, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock
):
    """FEAT-106 AC10 (OAuth rows): /oauth2/login and /oauth2/login/mfa finish < 10 s on a one-connection authdb."""
    # FILL IN: async with _oauth_env(..., authdb=single_connection_authdb) as live: enforced e-mail user;
    #   clear acquires_inside_lock; strict = True; asyncio.wait_for(login, 10) -> 200; wait_for(mfa, 10) -> 302;
    #   assert single_connection_authdb.acquires_inside_lock == []
```

### FILL IN checklist
- [ ] `_start_oauth` — callbacks off, MemoryClientStorage + client; bounded by spec §7 Patterns.
- [ ] `_stop_oauth` — flow-store pool disconnect; bounded by spec §7 Known Risks.
- [ ] `OAuthLive.oauth_mfa`, `challenge_of`, `mint` — bounded by AC2 and the Codebase Contract routes.
- [ ] `_oauth_env` — skip recipe and teardown mirror `live`; bounded by AC7.
- [ ] Three test bodies — bounded by AC1, AC2, AC3, AC4.

---

## Acceptance Criteria

- [ ] Spec AC1, AC2 (`test_oauth2_live_email_otp_single_delivery_and_replay`), AC3
      (`test_oauth2_live_event_record`) and AC4 (`test_oauth2_login_single_connection_pool`) pass on
      live Postgres + Redis.
- [ ] Spec AC7: the live tests skip (not fail) when the harness cannot start.
- [ ] The existing mock tests in the module still pass unchanged.
- [ ] `flake8 tests/test_mfa_review_fixes_oauth2.py` reports nothing.
- [ ] No file outside `tests/test_mfa_review_fixes_oauth2.py` changes (plus SDD state).

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_oauth2.py -q`
- `pytest tests/test_mfa_e2e.py -q`

---

## Test Specification

See the tests block of the Implementation Blueprint. Minimum assertions:

```python
# AC1: status 200, Cache-Control no-store, "Set-Cookie" not in headers, "Location" not in headers,
#      len(live.emails(user)) == 1, sent.email == user["email"], sent.code not in repr(sent)
# AC2: 302, urlparse(Location).path == "/oauth2/authorize", query == params exactly;
#      replay: status 401, "Location" not in headers, OAUTH2_EVENT_COOKIE not in response.cookies
# AC3: record["user_id"] == user["user_id"], record["mfa"] is True, record["amr"] == ["pwd", "otp"]
# AC4: 200 then 302, each under asyncio.wait_for(..., 10); acquires_inside_lock == []
```

---

## Agent Instructions

1. **Work in the feature worktree** — `parrot sdd worktree ensure --slug tests-test-mfa-review-fixes-oauth2-fixes --feature-id FEAT-114`.
2. **Read the spec** (§3 M1, §5 AC1–AC4, AC7, §7).
3. **Verify the Codebase Contract** (re-run the `grep -c` anchors).
4. **Update status** → `"in-progress"` in `sdd/tasks/index/tests-test-mfa-review-fixes-oauth2-fixes.json`; commit only that file.
5. **Implement** from the blueprint; complete every `# FILL IN:`.
6. **Verify** — Validation Commands with live services; `flake8` on the file.
7. **Commit the code** — stage only `tests/test_mfa_review_fixes_oauth2.py`.
8. **Close** — `parrot sdd task close TASK-215 tests-test-mfa-review-fixes-oauth2-fixes verified`.
9. **Fill in the Completion Note**, then commit the staged SDD state.

---

## Completion Note

**Completed by**: agent:sdd-fix:c9cd5387 (Claude Opus 5.5, /sdd-fix issue:1a329591f638)
**Date**: 2026-11-11
**Notes**: Implemented code commit `8474c82`. Live harness (`_start_oauth`, `_stop_oauth`,
`_oauth_evalctx_view`, `OAuthLive`, `_oauth_env`, `oauth_live`, `live_test`) plus three live tests,
all run against live Postgres + Redis (not skipped):
`test_oauth2_live_email_otp_single_delivery_and_replay` (AC1/AC2),
`test_oauth2_live_event_record` (AC3), `test_oauth2_login_single_connection_pool` (AC4 = FEAT-106
AC10 OAuth rows). Validation: `pytest tests/test_mfa_review_fixes_oauth2.py -q` → 15 passed;
`pytest tests/test_mfa_e2e.py -q` → 21 passed, 1 xfailed; `flake8` clean.
No production defect surfaced: the real gate makes no `acquire()` under the user lock on the OAuth path.

**Deviations from spec**:
- `# noqa: F811` sits on the parameter line of multi-line defs, because flake8 reports F811 there.
- Added a helper not in the blueprint: `_email_challenge`, shared by AC1 and AC3.
- `OAuthLive.cleanup` also deletes the pre-seeded Redis grants.
- The AC10 test also asserts that the measured calls really acquired from the one-connection
  pool, so it cannot pass vacuously.
