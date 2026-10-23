# TASK-111: Unit tests — `tests/unit/identity/test_external_token_capture.py`

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-103, TASK-104, TASK-106, TASK-107, TASK-108, TASK-109
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 7 and §4 "Unit Tests — `tests/unit/identity/test_external_token_capture.py`".

This task writes the **provider-agnostic** half of the test suite: twenty tests
covering Modules 1, 2, 4, 5, 6 and 8, plus the one regression test that pins
what the investigation actually found about session writes. The Azure-specific
tests (Modules 3 and the Azure side of 4) are TASK-112.

Two of these tests exist to pin invariants that are easy to break *silently*:

- `test_navigator_refresh_token_key_not_clobbered` — `userdata["refresh_token"]`
  is **Navigator's own** token and `auth.py:505-513` indexes it in Redis for 90
  days. Writing the provider's secret there would corrupt Navigator's refresh
  flow.
- `test_api_login_session_is_written_by_remember_not_load_session` — the session
  is created/refreshed by the backend's `remember()` → `new_session()`;
  `auth.py:494`'s `load_session` only re-reads it. This keeps the §1 (c)
  behaviour from silently regressing whichever way TASK-110 lands.

---

## Scope

Create `tests/unit/identity/test_external_token_capture.py` with exactly the
tests named in spec §4 for this file:

| Test | Module |
|---|---|
| `test_build_user_info_without_new_kwargs_is_unchanged` | 1 |
| `test_build_user_info_sets_id_token_and_expiry` | 1 |
| `test_build_user_info_never_writes_refresh_token` | 1 |
| `test_navigator_refresh_token_key_not_clobbered` | 1 |
| `test_vault_upstream_token_uses_passed_tokenresponse` | 2 |
| `test_vault_upstream_token_failure_does_not_raise` | 2 |
| `test_get_live_provider_token_returns_cached_when_fresh` | 4 |
| `test_get_live_provider_token_refreshes_when_expiring` | 4 |
| `test_get_live_provider_token_without_refresh_token_returns_none` | 4 |
| `test_capture_binds_verified_provider_account` | 2, 3 |
| `test_refresh_uses_login_account_not_newest_link` | 2, 4 |
| `test_refresh_rejects_missing_or_mismatched_binding` | 4 |
| `test_oauth2_resume_preserves_captured_grant` | 2 |
| `test_expires_in_is_seconds_remaining` | 5 |
| `test_expires_at_is_absolute_epoch` | 5 |
| `test_user_object_expires_in_is_seconds` | 5 |
| `test_expires_in_matches_oauth2_b1_convention` | 5 |
| `test_azure_flow_ttl_is_independent_of_max_age` | 8 |
| `test_azure_session_timeout_is_int` | 8 |
| `test_check_credentials_redacts_provider_tokens` | 6 |
| `test_api_login_session_is_written_by_remember_not_load_session` | 7 |

**NOT in scope**: `tests/test_azure_token_verifier.py` (TASK-112); the
`navigator-session` tests (TASK-110); the live-database proof of migration 004
(TASK-102's manual criterion); `docs/` (TASK-113).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/unit/identity/test_external_token_capture.py` | CREATE | the 21 tests above |

---

## Codebase Contract

### Verified Imports
```python
from unittest.mock import AsyncMock, MagicMock, patch     # verified: tests/unit/identity/test_okta_backend.py:2
import pytest                                             # verified: same, :4
from aiohttp.test_utils import make_mocked_request         # verified: same, :5
from .conftest import make_backend, FakeFlowStore          # verified: tests/unit/identity/conftest.py:39, :7
from navigator_auth.backends.external import ExternalAuth  # verified: navigator_auth/backends/external.py:80
from navigator_auth.identity.types import TokenResponse, mask_value   # verified: identity/types.py:8, :93
from navigator_auth.libs.expiry import expiry_fields       # created by TASK-107
from navigator_auth.conf import (
    AZURE_FLOW_TTL,            # created by TASK-109
    AZURE_SESSION_TIMEOUT,     # verified: conf.py:430 (becomes getint in TASK-109)
    IDENTITY_REFRESH_LEEWAY,   # verified: conf.py:545
)
from navigator_session import SESSION_TIMEOUT   # verified: conf.py:13 re-exports it
                                                #   from navigator_session; it is NOT
                                                #   defined in navigator_auth.conf
```

### Verified test-harness facts (this repo)
```python
# tests/unit/identity/conftest.py
class FakeFlowStore:  # dict-backed, single-use semantics                 # verified: :7-32
@pytest.fixture
def flow_store(): return FakeFlowStore()                                  # verified: :35-37
def make_backend(cls, flow_store=None, **attrs):                          # verified: :39
    backend = object.__new__(cls)          # bypasses __init__ entirely   # verified: :42
    backend.logger = MagicMock()                                          # verified: :43
    backend.scheme = "Bearer"; backend.session_key_property = "session_key"
    backend.session_id_property = "session_id"; backend.user_property = "user"   # verified: :46-49
    #  NOTE: does NOT set userid_attribute / username_attribute / _service_name
    #        / user_mapping — pass them via **attrs (see test_okta_backend.py:11-18)

# pyproject.toml [tool.pytest.ini_options]
addopts = ["--strict-config", "--strict-markers"]                         # verified: :102-105
filterwarnings = ["error", ...]                                           # verified: :113-114
#  => warnings are ERRORS. tests/test_azure_token_verifier.py:26 works around
#     one such case with `pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")`
#  => every async test needs an explicit `@pytest.mark.asyncio` (see
#     test_okta_backend.py:22) — there is no asyncio_mode=auto in the config.
```

### Verified signatures under test
```python
# navigator_auth/backends/external.py  (post TASK-103/104/106/107)
def build_user_info(self, userdata, token, mapping, *, id_token=None,
                    refresh_token=None, expires_at=None, provider_user_id=None) -> tuple   # :668
async def _vault_upstream_token(self, request, *, token=None) -> None                      # :454
async def capture_login_credential(self, request, token) -> None                           # TASK-104
async def get_live_provider_token(self, request, user_id, *, leeway=None) -> Optional[TokenResponse]  # TASK-106
async def refresh_provider_tokens(self, token) -> Optional[TokenResponse]                  # TASK-106
async def _resume_oauth2_authorize(self, request, flow_id, response)                       # :419
async def validate_user_info(self, request, user_id, userdata, token) -> dict              # :700

# navigator_auth/identity/store.py
async def save_linked_identity(self, user_id, provider, token, userinfo=None)   # :112
async def get_by_provider(self, user_id, provider)                              # :222 (newest-wins)
async def get_for_provider_account(self, user_id, provider, provider_user_id)   # TASK-104 (exact)
async def update_tokens(self, identity, token)                                  # :261
def decrypt_credential(self, identity) -> TokenResponse                         # :280

# navigator_auth/identity/types.py
def is_expiring(self, leeway: int = 0) -> bool    # False when expires_at is None   # :32-37

# navigator_auth/backends/oauth2/backend.py — the B1 reference shape
expires_in = int(exp_abs - now_utc.timestamp())                   # :1863, :1953, :2056
```

### Does NOT Exist (do not reference)
- **No** live Postgres or Redis fixture under `tests/unit/identity/` — every
  test there is mock-based (`conftest.py`, `test_identity_migrations.py`). Do
  **not** add a container or a real connection; double `IdentityStore` and the
  session.
- **No** `asyncio_mode = "auto"` in `pyproject.toml` — mark every async test.
- **No** real `IdentityCipher` keys in the test environment:
  `IdentityStore.__init__` builds one eagerly (`store.py:52-58`) and raises
  `ConfigError` without keys. Patch `IdentityStore` where it is imported
  (lazily, **inside** `_vault_upstream_token` / `get_live_provider_token`), not
  at module scope — `patch("navigator_auth.identity.store.IdentityStore")`
  reaches the lazy import, a module-attribute patch on `external` does not.
- **No** `AUTH_SESSION_OBJECT` value you should hardcode — import it
  (`from navigator_session import AUTH_SESSION_OBJECT`, as `external.py:21`
  does).

---

## Implementation Blueprint

### Steps (in order)
1. Block A: module header + shared fixtures. Build these first and reuse them;
   twenty tests with twenty ad-hoc fakes is how this file becomes unmaintainable.
2. Block B: the Module 1 tests. These are pure-function tests over
   `build_user_info` and need no async.
3. Block C: the Module 2 / 4 tests — the ones that need a session double and a
   patched `IdentityStore`.
4. Block D: the Module 5 / 6 / 8 tests and the Module 7 regression test.
5. Run `pytest tests/unit/identity/test_external_token_capture.py -v`, then the
   full `pytest tests/ -v` and diff against the `dev` baseline.

### Block A — module header and fixtures
```python
"""FEAT-103 — provider-credential capture, vaulting, refresh and the
expires_in/expires_at contract.

Provider-agnostic half of the suite; the Azure-specific tests live in
tests/test_azure_token_verifier.py (TASK-112).

Every test here is mock-based, matching the rest of tests/unit/identity/ —
no live Postgres, no live Redis, no real IdentityCipher.
"""
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request
from navigator_session import AUTH_SESSION_OBJECT

from navigator_auth.backends.external import ExternalAuth
from navigator_auth.identity.types import TokenResponse
from .conftest import make_backend


class _Backend(ExternalAuth):
    """Minimal concrete ExternalAuth — the class is abstract.

    Verified: external.py declares exactly five @abstractmethod members —
    authenticate (:350), auth_callback (:354), logout (:661),
    finish_logout (:665), check_credentials (:772).
    """

    async def authenticate(self, request):
        raise NotImplementedError

    async def auth_callback(self, request):
        raise NotImplementedError

    async def logout(self, request):
        raise NotImplementedError

    async def finish_logout(self, request):
        raise NotImplementedError

    async def check_credentials(self, request):
        raise NotImplementedError


def _make(**attrs):
    """An ExternalAuth instance wired for these tests.

    `make_backend` (conftest.py:39) bypasses __init__ and sets scheme,
    session_key_property, session_id_property and user_property only — so the
    attributes build_user_info reads must be passed here.
    """
    defaults = {
        "_service_name": "testprovider",
        "userid_attribute": "id",
        "username_attribute": "email",
        "user_attribute": "email",
        "user_mapping": {},
    }
    defaults.update(attrs)
    return make_backend(_Backend, **defaults)


class FakeSession(dict):
    """Session double: a dict with the .get/[] access external.py uses."""


@pytest.fixture
def session():
    return FakeSession({
        "user_id": 35,
        "auth_method": "testprovider",
        "auth_token": "AT.old",
        "token_type": "Bearer",
        "external_provider_user_id": "acct-A",
    })


@pytest.fixture
def request_with_db():
    request = make_mocked_request("GET", "/auth/testprovider/callback/")
    request.app["authdb"] = MagicMock()
    return request


@pytest.fixture
def full_grant():
    """The captured login grant, shaped like msal 1.38.0's result (spec §4)."""
    return TokenResponse(
        access_token="AT.graph",
        token_type="Bearer",
        refresh_token="RT.secret",
        id_token="ID.jwt",
        expires_in=419,                 # the measured lifetime, spec §6
        scopes=["User.Read", "Mail.Read"],
        provider_user_id="acct-A",
    )
```
**Why a `_Backend` subclass**: `ExternalAuth` declares five abstract methods
(verified above). `make_backend` (`conftest.py:42`) instantiates via
`object.__new__(cls)`, which in CPython **does** skip ABC's instantiation
check — so a bare `ExternalAuth` may work. The subclass is kept anyway because
a test that accidentally calls one of the five gets a clear
`NotImplementedError` instead of an `AttributeError` from a half-built object.
Do not remove it to save four lines.

### Block B — Module 1 tests
```python
class TestBuildUserInfoCapture:
    def test_build_user_info_without_new_kwargs_is_unchanged(self):
        """The old 3-argument call produces byte-identical userdata.

        This is the guard for the ELEVEN existing call sites (spec §6 blast
        radius) — it is the reason the capture arguments are optional.
        """
        # FILL IN — bounded by: call _make().build_user_info(userdata=..., token=...,
        # mapping=...) and assert the resulting dict's keys are EXACTLY
        # {<mapped keys>, "id", "session_key", "auth_method", "auth_token",
        # "token_type"} — i.e. none of the four new keys appear. Compare key
        # SETS, not values, so a mapping change elsewhere does not false-fail.

    def test_build_user_info_sets_id_token_and_expiry(self):
        """id_token and external_expires_at (ISO-8601) land in userdata."""
        # FILL IN — bounded by: pass id_token=..., expires_at=<aware datetime>;
        # assert userdata["id_token"] and that
        # datetime.fromisoformat(userdata["external_expires_at"]) round-trips to
        # the same instant (the key is a STRING by design — exchange.py:206-209
        # and basic.py:152 already use that name and type).

    def test_build_user_info_never_writes_refresh_token(self):
        """refresh_token sets only has_refresh_token; the secret never lands."""
        # FILL IN — bounded by: pass refresh_token="secret"; assert
        # userdata["has_refresh_token"] is True and that "secret" appears in NO
        # value of userdata (walk str(v) for every value, including nested).

    @pytest.mark.asyncio
    async def test_navigator_refresh_token_key_not_clobbered(self):
        """After validate_user_info, userdata["refresh_token"] is still
        NAVIGATOR's own token — the guard for auth.py:505-513's 90-day Redis
        index `auth:refresh_token:<tok>`.
        """
        # FILL IN — bounded by: patch self._idp.create_token to return
        # ("JWT", "NAV_RT", <exp>, "Bearer"), patch self.remember /
        # self._idp.get_user / self.create_user / self.get_userdata as needed,
        # call validate_user_info with a userdata that ALREADY carries
        # has_refresh_token=True, and assert the returned dict's
        # ["refresh_token"] == "NAV_RT". This test is about key collision, not
        # about the IdP — stub generously.
```

### Block C — Module 2 and 4 tests
```python
class TestVaulting:
    @pytest.mark.asyncio
    async def test_vault_upstream_token_uses_passed_tokenresponse(
        self, request_with_db, session, full_grant
    ):
        """save_linked_identity receives the refresh token and id_token, not a
        session-rebuilt partial."""
        # FILL IN — bounded by: patch
        # "navigator_session.get_session" (as imported INSIDE the method) to
        # return `session`, patch
        # "navigator_auth.identity.store.IdentityStore" with a MagicMock whose
        # return_value.save_linked_identity is an AsyncMock; call
        # _vault_upstream_token(request, token=full_grant); assert the token
        # object passed through is `full_grant` itself (identity, not equality)
        # and that its refresh_token/id_token are intact.

    @pytest.mark.asyncio
    async def test_vault_upstream_token_failure_does_not_raise(self, ...):
        """A raising IdentityStore is swallowed and logged (contract preserved,
        external.py:489-492 and vault/integration.py:11-13)."""
        # FILL IN — bounded by: make save_linked_identity raise; assert the call
        # returns None, does not raise, and backend.logger.warning was called.

    @pytest.mark.asyncio
    async def test_capture_binds_verified_provider_account(self, ...):
        """Capture saves the VERIFIED userinfo account id, and a missing id
        creates no row at all."""
        # FILL IN — bounded by: (a) a grant with provider_user_id set reaches
        # save_linked_identity; (b) a grant with provider_user_id=None or ""
        # results in ZERO save_linked_identity calls plus a logger.warning.
        # Spec Module 2: "never persist an unbound login grant".

    @pytest.mark.asyncio
    async def test_oauth2_resume_preserves_captured_grant(self, ...):
        """Callback then AS resume leaves the exact row, scopes, expiry and
        tokens — no partial second save."""
        # FILL IN — bounded by: call capture_login_credential(request, grant)
        # (which sets the CAPTURED_LOGIN_GRANT marker), then
        # _resume_oauth2_authorize(request, "flow-1", <a 302 response double>);
        # assert save_linked_identity was called EXACTLY ONCE, with the full
        # grant. A 302 is required — the method returns early for other statuses
        # (external.py:427-433).


class TestGetLiveProviderToken:
    @pytest.mark.asyncio
    async def test_get_live_provider_token_returns_cached_when_fresh(self, ...):
        """No refresh when is_expiring(leeway) is False."""
        # FILL IN — bounded by: a stored credential expiring in 1 hour, leeway
        # 120; assert refresh_provider_tokens is NOT called and the returned
        # token is the decrypted one.

    @pytest.mark.asyncio
    async def test_get_live_provider_token_refreshes_when_expiring(self, ...):
        """Expiring credential triggers refresh, update_tokens persists it, and
        the session's auth_token is updated."""
        # FILL IN — bounded by: expires_at = now + 30s, leeway 120; assert
        # refresh_provider_tokens called once, update_tokens called with the
        # rotated token, session["auth_token"] == the NEW access token, and
        # session["external_expires_at"] updated. Assert the ORDER too:
        # update_tokens must be awaited BEFORE the session is mutated (spec
        # Module 4 — the vault is the system of record).

    @pytest.mark.asyncio
    async def test_get_live_provider_token_without_refresh_token_returns_none(self, ...):
        """An EXPIRED credential with no refresh token returns None rather than
        raising; a FRESH one is still returned."""
        # FILL IN — two cases in one test, as the spec names it: (a) expires_at
        # in the past, refresh_token None -> None, no exception; (b) expires_at
        # an hour out, refresh_token None -> the token is returned. Note
        # is_expiring(leeway) is True for an expiring-but-valid token too, so
        # this test is what pins TASK-106's FILL IN decision.

    @pytest.mark.asyncio
    async def test_refresh_uses_login_account_not_newest_link(self, ...):
        """Log in as account A, link/refresh account B more recently, expire A:
        only A is read, refreshed and written to the session."""
        # FILL IN — bounded by: the store double must expose BOTH
        # get_by_provider (returning B, the newest) and
        # get_for_provider_account (returning A). Assert get_by_provider was
        # NEVER called, and that the session carries A's refreshed token. This
        # is the test for the CONFIRMED finding in spec §9.

    @pytest.mark.asyncio
    async def test_refresh_rejects_missing_or_mismatched_binding(self, ...):
        """Missing / deleted / disabled account, wrong local user, or wrong
        auth_method returns None without provider calls or session mutation."""
        # FILL IN — bounded by: parametrize the four cases (no
        # external_provider_user_id; get_for_provider_account -> None;
        # user_id != session user; session auth_method != _service_name). For
        # each, assert the return is None, refresh_provider_tokens was NOT
        # called, and the session dict is UNCHANGED (compare a copy taken
        # before the call).
```

### Block D — Modules 5, 6, 8 and the Module 7 regression
```python
class TestExpiryContract:
    def test_expires_in_is_seconds_remaining(self):
        """0 < expires_in <= SESSION_TIMEOUT and isinstance(expires_in, int)."""
        # FILL IN — bounded by: call expiry_fields(time.time() + N) directly and
        # also assert on at least one real publisher's output (e.g. noauth's
        # returned dict), so the test covers the wiring and not only the helper.

    def test_expires_at_is_absolute_epoch(self):
        """expires_at ≈ now + expires_in (±2 s)."""
        # FILL IN — bounded by the ±2 s tolerance the spec names.

    def test_user_object_expires_in_is_seconds(self):
        """usr.expires_in is int seconds-remaining and usr.expires_at carries
        the epoch, at all FOUR set sites (basic.py:259, troc.py:148,
        noauth.py:69, token.py:144)."""
        # FILL IN — bounded by: four sites means four assertions. Driving all
        # four real backends is heavy; if a site cannot be exercised without a
        # live IdP, assert on the code path you CAN reach and record in the
        # Completion Note exactly which of the four are covered by execution and
        # which by inspection. Do not claim four if you tested two.

    def test_expires_in_matches_oauth2_b1_convention(self):
        """The legacy login publishers and oauth2/backend.py's B1 path produce
        the same shape for the same exp — pins the convention instead of
        re-deriving it."""
        # FILL IN — bounded by: compute `int(exp_abs - now_utc.timestamp())` the
        # way backend.py:1863 does and assert it equals
        # expiry_fields(exp_abs)["expires_in"] (allow ±1 s for the two clock
        # reads). Assert the TYPE is int in both.


class TestAzureFlowTtlSplit:
    def test_azure_flow_ttl_is_independent_of_max_age(self):
        """setex on azure_auth_<state> uses AZURE_FLOW_TTL (600) while
        initiate_auth_code_flow still receives max_age=AZURE_SESSION_TIMEOUT."""
        # FILL IN — bounded by: patch msal + the redis pool on an AzureAuth
        # double, call authenticate() with no user/pwd (the redirect branch),
        # and assert the setex TTL argument is AZURE_FLOW_TTL while the
        # initiate_auth_code_flow kwargs carry max_age=AZURE_SESSION_TIMEOUT.
        # The two must differ by default (600 vs 120) — that difference IS the
        # assertion.

    def test_azure_session_timeout_is_int(self):
        """AZURE_SESSION_TIMEOUT is an int from conf.py, so azure.py no longer
        needs the int() wrapper."""
        # FILL IN — bounded by: assert isinstance(AZURE_SESSION_TIMEOUT, int)
        # and isinstance(AZURE_FLOW_TTL, int).


class TestCheckCredentialsRedaction:
    @pytest.mark.asyncio
    async def test_check_credentials_redacts_provider_tokens(self, ...):
        """The JSON body contains neither the raw access token nor the id_token."""
        # FILL IN — bounded by: this is a cross-backend guarantee (azure.py:585,
        # github.py:314, google.py:333). Prefer asserting the redaction on the
        # dict the site builds rather than booting three backends; if you can
        # only exercise one, say which in the Completion Note and assert the
        # other two by reading their source for the same block.


class TestSessionWriteInvariant:
    @pytest.mark.asyncio
    async def test_api_login_session_is_written_by_remember_not_load_session(self, ...):
        """Pins the invariant the investigation found: the session is
        created/refreshed by the backend's remember() -> new_session(), and
        auth.py:494's load_session only re-reads it.

        Keeps the spec §1 (c) behaviour from silently regressing whichever way
        TASK-110 (navigator-session's opt-in merge) lands.
        """
        # FILL IN — bounded by: spy on both. Assert remember()/new_session ran
        # BEFORE load_session, and that load_session's return value is not what
        # supplies auth_token. Do NOT assert the discard itself — TASK-110 may
        # legitimately change that; assert the ORDERING, which is the actual
        # invariant.
```

### FILL IN checklist
- [ ] Block B: four test bodies.
- [ ] Block C: nine test bodies.
- [ ] Block D: eight test bodies.
- [ ] Record in the Completion Note which of `test_user_object_expires_in_is_seconds`'s
      four sites and which of the three redaction sites are covered by
      execution versus inspection.

---

## Implementation Notes

### Key Constraints
- **`filterwarnings = ["error"]`** (`pyproject.toml:113-114`): a
  `DeprecationWarning` fails the test. `tests/test_azure_token_verifier.py:26`
  shows the per-module escape hatch
  (`pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")`) —
  use it only if a warning actually appears, and say why.
- **Mark every async test** with `@pytest.mark.asyncio`; there is no
  `asyncio_mode = auto`.
- **Patch the lazy imports at their source module.** `_vault_upstream_token`
  and `get_live_provider_token` import `IdentityStore` and `get_session`
  *inside* the function body, so
  `patch("navigator_auth.identity.store.IdentityStore")` works and
  `patch("navigator_auth.backends.external.IdentityStore")` does not.
- No live Postgres, Redis or real cipher keys.
- Never put a real token value in a fixture, not even an expired one. Use
  obvious placeholders (`"AT.graph"`, `"RT.secret"`, `"ID.jwt"`).

### References in Codebase
- `tests/unit/identity/test_okta_backend.py` — the closest template (backend
  double + `make_backend` + `make_mocked_request`).
- `tests/unit/identity/test_identity_store.py` — how this repo doubles the
  store.
- `tests/unit/identity/conftest.py` — `make_backend` and what it does **not**
  set.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/identity/test_external_token_capture.py -v` passes
- [ ] All 21 tests from spec §4 exist, with those exact names
- [ ] No test requires a live Postgres, Redis or cipher key
- [ ] `pytest tests/ -v` shows no new failures versus the `dev` baseline
- [ ] `ruff check tests/unit/identity/test_external_token_capture.py` clean
- [ ] The Completion Note is explicit about any assertion made by **inspection**
      rather than execution

---

## Test Specification

This task *is* the test specification; see spec §4 for the authoritative table
and the `msal_result_full` fixture shape (spec §4 "Test Data / Fixtures").

---

## Agent Instructions

1. **Read the spec** §4 in full, plus §3 Module 7.
2. **Check dependencies** — TASK-103, 104, 106, 107, 108, 109 in
   `sdd/tasks/completed/`. A test written against an unimplemented module is
   not a test.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve every `FILL IN`.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-111-tests-external-token-capture.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: 21 spec-named tests + extras (29 collected incl. parametrization, plus `test_vault_upstream_token_legacy_fallback_rebuilds_from_session`, `test_oauth2_resume_without_capture_keeps_legacy_save` control, `test_noauth_publisher_returns_seconds_not_epoch`). `pytest tests/unit/identity/test_external_token_capture.py`: 29 passed (artifacts/logs/TASK-111.log). Full suite 37 failed / 1549 passed; FAILED set identical to dev baseline. ruff clean on the file. All mock-based (no DB/Redis/cipher).
**Execution vs inspection**: test_user_object_expires_in_is_seconds -- EXECUTED for noauth.py only; basic.py, troc.py, token.py asserted BY INSPECTION of source (expiry_fields use, no raw `expires_in = exp`). Redaction: all three (azure, github, google) EXECUTED via real check_credentials with stubbed verify/build/validate. test_azure_flow_ttl EXECUTED via AzureAuth.authenticate with patched AZURE_FLOW_TTL/AZURE_SESSION_TIMEOUT. Session-write invariant EXECUTED via AuthHandler.api_login with spies (asserts order remember -> load_session). The B1 test also string-checks oauth2/backend.py source for the B1 expression.
Added `pytestmark` DeprecationWarning ignore (aiohttp/JSONResponse under filterwarnings=error).
**Deviations from spec**: none
