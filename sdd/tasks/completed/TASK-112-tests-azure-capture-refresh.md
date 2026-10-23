# TASK-112: Azure tests — MSAL capture, cache fallback and scope-preserving refresh

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-105, TASK-106
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 7 and §4 "Unit Tests — `tests/test_azure_token_verifier.py`
(extend)".

The Azure-specific half of the suite. These tests are what prove the two
claims the spec verified against the **installed** `msal 1.38.0` source rather
than from memory:

- the authorization_code result **does** carry `refresh_token` and `id_token`
  (`msal/application.py:155-166`, `msal/oauth2cli/oauth2.py:865-895`), so the
  result must win over the cache; and
- `AzureAuth.refresh_identity_tokens` would have downgraded a login grant to
  `AZURE_IDENTITY_SCOPES` (default `User.Read`), which is why TASK-106 added a
  separate, scope-preserving hook.

The file already exists and must keep passing in full — in particular
`test_check_credentials_audience_bound_regression` (`:241`), which spec §4
lists explicitly as a must-still-pass.

---

## Scope

Extend `tests/test_azure_token_verifier.py` with exactly the tests spec §4
names for it:

| Test | Module |
|---|---|
| `test_auth_callback_captures_refresh_and_id_token` | 3 |
| `test_auth_callback_refresh_token_from_cache_fallback` | 3 |
| `test_msal_normalizer_captures_id_and_prefers_result_refresh` | 3 |
| `test_azure_login_refresh_preserves_grant_scopes` | 3, 4 |
| `test_azure_missing_scope_fallback` | 3, 4 |
| `test_azure_refresh_reduced_grant_is_not_published` | 4 |

Plus the `msal_result_full` fixture from spec §4 "Test Data / Fixtures".

**NOT in scope**: the provider-agnostic tests (TASK-111); the
`navigator-session` tests (TASK-110); `test_azure_flow_ttl_is_independent_of_max_age`
and `test_azure_session_timeout_is_int` — spec §4 places those in TASK-111's
file; modifying any existing test in this file (if one must change, that is a
finding to report, not a quiet edit).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_azure_token_verifier.py` | MODIFY | add the fixture + six tests |

---

## Codebase Contract

### Verified Imports (already in the file)
```python
import base64, time                                          # verified: tests/test_azure_token_verifier.py:8-9
from unittest.mock import AsyncMock                           # verified: :10
import jwt as pyjwt                                           # verified: :12
import pytest                                                 # verified: :13
from aiohttp.test_utils import make_mocked_request             # verified: :14
from cryptography.hazmat.primitives import serialization       # verified: :15
from cryptography.hazmat.primitives.asymmetric import rsa      # verified: :16
from navigator_auth.backends import jwksutils                  # verified: :18
from navigator_auth.backends.azure import AzureAuth            # verified: :19
from navigator_auth.conf import AZURE_ADFS_CLIENT_ID, AZURE_ADFS_TENANT_ID   # verified: :20
from navigator_auth.exceptions import InvalidAuth              # verified: :21
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")        # verified: :26
KID = "azure-test-kid"                                         # verified: :28
ISSUER = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}/v2.0"    # verified: :29
GRAPH_PROFILE = {"id": "graph-oid-123", "userPrincipalName": "user@example.com",
                 "displayName": "Test User", "mail": "user@example.com"}     # verified: :30-35
@pytest.fixture(autouse=True)
def _clear_jwks_cache(): jwksutils.get_jwks.cache_clear()                    # verified: :37-41
```
Imports you will need to **add**: `msal`,
`from navigator_auth.identity.types import TokenResponse`, and
`from navigator_auth.conf import AZURE_IDENTITY_SCOPES` (verify the current
import block before editing).

### Verified signatures under test
```python
# navigator_auth/backends/azure.py  (post TASK-105 / TASK-106)
MSAL_RESERVED_SCOPES = frozenset({"openid", "profile", "offline_access"})   # TASK-105, module scope
def get_msal_app(self, token_cache: msal.SerializableTokenCache = None)     # verified: :116
def get_msal_client(self, token_cache=None)                                 # :126, gains the param in TASK-105
async def authenticate(self, request)                                       # verified: :135
    Default_SCOPE = ["User.ReadBasic.All"]                                  # verified: :146  (ROPC)
    SCOPE = ["https://graph.microsoft.com/.default"]                        # verified: :205  (callback)
async def auth_callback(self, request)                                      # verified: :223
@staticmethod
def _refresh_token_from_cache(cache) -> Optional[str]                       # verified: :304
    tokens = cache.find(msal.TokenCache.CredentialType.REFRESH_TOKEN)       # verified: :309
    for entry in tokens: secret = entry.get("secret")                       # verified: :310-312
@staticmethod
def _token_from_msal_result(result, cache, requested_scopes=None) -> TokenResponse   # :320, 3rd param from TASK-105
def identity_scopes(self) -> list: return AZURE_IDENTITY_SCOPES             # verified: :293-297
def get_identity_userid(self, userinfo) -> Optional[str]                    # verified: :299
    value = userinfo.get("id", userinfo.get("userPrincipalName"))           # verified: :300
async def refresh_identity_tokens(self, refresh_token) -> TokenResponse     # verified: :375
    result = app.acquire_token_by_refresh_token(refresh_token,
                                                scopes=self.identity_scopes())   # verified: :378-380
async def refresh_provider_tokens(self, token) -> Optional[TokenResponse]   # TASK-106

# navigator_auth/conf.py
AZURE_IDENTITY_SCOPES = [...]   # fallback "User.Read"                      # verified: :548
```

### The spec's fixture (spec §4 "Test Data / Fixtures") — use it verbatim
```python
@pytest.fixture
def msal_result_full():
    """An MSAL authorization_code result shaped like msal 1.38.0 returns it."""
    return {
        "token_type": "Bearer",
        "access_token": "AT.graph",
        "id_token": "ID.jwt",
        "refresh_token": "RT.secret",      # present on the auth-code grant
        "expires_in": 419,                 # measured lifetime, spec §6
        "scope": "User.Read Mail.Read",
        "id_token_claims": {"oid": "4e2aa0ea-...", "tid": "af176793-..."},
    }
```

### Does NOT Exist (do not reference)
- **No** network access in these tests. The file's own docstring (`:1-6`) says
  it mocks `AzureAuth.get` (Graph `/me`) with a canned profile — keep that.
  Never call a real Entra endpoint, and never put a real token in a fixture.
- **No** `asyncio_mode = auto` — mark every async test `@pytest.mark.asyncio`.
- **No** MSAL test double in the repo. You construct one: a `MagicMock` whose
  `acquire_token_by_auth_code_flow` / `acquire_token_by_username_password` /
  `acquire_token_by_refresh_token` return your fixture dicts, patched in via
  `AzureAuth.get_msal_app` / `get_msal_client`.
- **No** way to make a real `msal.SerializableTokenCache` hold a refresh token
  without going through MSAL's internals. For the cache-fallback test, double
  the cache object (`MagicMock` with a `find()` returning
  `[{"secret": "RT.from-cache"}]`) rather than trying to populate a real one —
  `_refresh_token_from_cache` only calls `.find(...)` and reads `"secret"`
  (`azure.py:309-312`).
- **No** `.default` in a *granted* scope list — it is a request selector. A
  test asserting that `"https://graph.microsoft.com/.default"` comes back in
  `scopes` is testing the wrong thing.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: the fixture and an MSAL-app doubling helper, appended to the
   existing file (do not restructure what is there).
2. Block B: the three Module 3 tests.
3. Block C: the three refresh tests.
4. Run `pytest tests/test_azure_token_verifier.py -v` — **all** of it,
   including `test_check_credentials_audience_bound_regression` (`:241`).

### Block A — fixture + MSAL double
```python
# AFTER — append at the end of tests/test_azure_token_verifier.py
# occurrences: n/a (append)

# --- FEAT-103: provider-credential capture -------------------------------

@pytest.fixture
def msal_result_full():
    """An MSAL authorization_code result shaped like msal 1.38.0 returns it."""
    return {
        "token_type": "Bearer",
        "access_token": "AT.graph",
        "id_token": "ID.jwt",
        "refresh_token": "RT.secret",      # present on the auth-code grant
        "expires_in": 419,                 # measured lifetime, spec §6
        "scope": "User.Read Mail.Read",
        "id_token_claims": {"oid": "4e2aa0ea-0000", "tid": "af176793-0000"},
    }


def _fake_cache(secret=None):
    """A SerializableTokenCache double.

    `_refresh_token_from_cache` (azure.py:304-317) only calls `.find(...)` and
    reads `entry["secret"]`, so a MagicMock is sufficient and avoids depending
    on MSAL's cache internals.
    """
    cache = MagicMock()
    cache.find.return_value = [{"secret": secret}] if secret else []
    return cache


#  NOTE: this file ALREADY has a `backend` fixture (verified: :118-123) that
#  builds a REAL AzureAuth(user_model=object) and stubs `.get` with
#  AsyncMock(return_value=GRAPH_PROFILE). Reuse it — do not write a second
#  backend helper, and do not switch to make_backend's __init__-bypassing
#  double, which would lose the real attribute wiring these tests need.
#
# FILL IN: for the tests that need extra wiring on top of the shared `backend`
# fixture (a redis pool double for auth_callback, a patched get_msal_app),
# add it per-test with monkeypatch — the pattern the existing tests in this
# file already use (see test_verify_id_token_ok, :129-132). Bounded by: do not
# modify the shared fixture, because every existing test depends on it.
```
**Why `_fake_cache` over a real cache**: `msal.SerializableTokenCache` has no
public API for inserting a refresh token; populating one means driving a real
grant or writing its internal JSON shape, both of which couple the test to MSAL
internals the spec explicitly does not want asserted. The production code's
contract with the cache is exactly two calls — honour that surface.

### Block B — Module 3 tests
```python
class TestMsalNormalizer:
    def test_msal_normalizer_captures_id_and_prefers_result_refresh(
        self, msal_result_full
    ):
        """The ID token is copied; when result and cache hold DIFFERENT refresh
        tokens, the result wins.

        Pins the msal 1.38.0 behaviour verified in spec §6: _clean_up strips
        only `refresh_in` and `_`-prefixed keys, so the authorization_code
        result keeps `refresh_token`.
        """
        # FILL IN — bounded by: call
        # AzureAuth._token_from_msal_result(msal_result_full,
        #     _fake_cache("RT.from-cache")) and assert
        # token.refresh_token == "RT.secret" (NOT "RT.from-cache"),
        # token.id_token == "ID.jwt", token.scopes == ["User.Read", "Mail.Read"],
        # and that token.raw does NOT contain "refresh_token" (azure.py keeps
        # that exclusion deliberately).

    @pytest.mark.asyncio
    async def test_auth_callback_captures_refresh_and_id_token(
        self, msal_result_full
    ):
        """A stubbed MSAL result containing refresh_token + id_token reaches
        build_user_info and _vault_upstream_token."""
        # FILL IN — bounded by: patch AzureAuth.get_msal_app to return an app
        # double whose acquire_token_by_auth_code_flow returns msal_result_full;
        # patch AzureAuth.get (Graph /me) with AsyncMock(return_value=GRAPH_PROFILE)
        # as the shared `backend` fixture already does (:122); patch the
        # redis pool so the flow record is found; spy on build_user_info and capture_login_credential. Assert
        # build_user_info received id_token="ID.jwt", refresh_token="RT.secret"
        # and a non-None expires_at, and that capture_login_credential got a
        # TokenResponse whose refresh_token is "RT.secret".

    @pytest.mark.asyncio
    async def test_auth_callback_refresh_token_from_cache_fallback(
        self, msal_result_full
    ):
        """A result WITHOUT refresh_token falls back to
        _refresh_token_from_cache."""
        # FILL IN — bounded by: pop "refresh_token" from the fixture, make the
        # cache double return "RT.from-cache", assert the captured grant carries
        # "RT.from-cache". The cache object the production code creates is
        # internal to auth_callback, so patch
        # AzureAuth._refresh_token_from_cache directly (it is a staticmethod)
        # rather than trying to inject a cache.
```

### Block C — refresh tests
```python
class TestAzureRefreshScopes:
    @pytest.mark.asyncio
    async def test_azure_login_refresh_preserves_grant_scopes(self):
        """A login grant holding User.Read + Mail.Read refreshes with BOTH,
        despite AZURE_IDENTITY_SCOPES being User.Read; reserved scopes are
        excluded.

        This is the test for the CONFIRMED finding in spec §9: Azure's
        refresh_identity_tokens (azure.py:378-380) requests
        self.identity_scopes() and would silently downgrade the grant.
        """
        # FILL IN — bounded by: build a stored TokenResponse with
        # scopes=["User.Read", "Mail.Read", "offline_access"]; patch
        # get_msal_app to return an app double; call
        # await backend.refresh_provider_tokens(token); assert the
        # acquire_token_by_refresh_token call's `scopes` kwarg is exactly
        # ["User.Read", "Mail.Read"] — offline_access EXCLUDED — and that it is
        # NOT AZURE_IDENTITY_SCOPES.

    @pytest.mark.asyncio
    async def test_azure_missing_scope_fallback(self):
        """Callback and ROPC capture their respective REQUESTED scopes when the
        result omits `scope`; refresh uses those scopes and retains them if its
        own response omits scope."""
        # FILL IN — bounded by: three assertions in one test, as the spec names
        # it. (a) a result with no "scope" + requested_scopes=
        # ["https://graph.microsoft.com/.default"] -> that is what lands (minus
        # reserved); (b) same with ["User.ReadBasic.All"] (the ROPC value,
        # azure.py:146); (c) a refresh whose response omits "scope" returns a
        # token still carrying the REQUESTED scopes, not an empty list.

    @pytest.mark.asyncio
    async def test_azure_refresh_reduced_grant_is_not_published(self):
        """A refresh that explicitly drops Mail.Read returns None and does NOT
        replace the session auth_token."""
        # FILL IN — bounded by: stored grant has EXPLICIT scopes
        # ["User.Read", "Mail.Read"]; the refresh response returns
        # "scope": "User.Read" only. Assert refresh_provider_tokens returns
        # None. Then drive get_live_provider_token with that setup and assert
        # session["auth_token"] is UNCHANGED and update_tokens was never called.
        # Note the `.default` caveat (spec §2 item 5): this test deliberately
        # uses an EXPLICIT grant, because a `.default` request cannot be
        # compared against returned permissions.
```

### FILL IN checklist
- [ ] Block A: the imports to add (`msal`, `MagicMock`, `TokenResponse`,
      `AZURE_IDENTITY_SCOPES`) — the file currently imports only `AsyncMock`
      from `unittest.mock` (verified: :10).
- [ ] Block A: the per-test wiring on top of the shared `backend` fixture.
- [ ] Block B: three test bodies.
- [ ] Block C: three test bodies.

---

## Implementation Notes

### Key Constraints
- The file sets `pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")`
  at `:26` for a pre-existing `auth_error`/aiohttp quirk. That applies
  module-wide, so your additions inherit it — do not add a second `pytestmark`.
- `_clear_jwks_cache` is `autouse=True` (`:37-41`); it will run for your tests
  too. Harmless, but do not rely on a warm JWKS cache.
- Do not modify an existing test. If one of them genuinely breaks because of
  TASK-105/TASK-106, that is a **finding** — report it in the Completion Note
  and raise it, rather than adjusting the assertion.
- Never log or embed a real token.

### References in Codebase
- `tests/test_azure_token_verifier.py:1-45` — the file's own conventions
  (RSA keypair, JWKS mocking, `AzureAuth.get` as `AsyncMock`).
- `tests/test_azure_token_verifier.py:241` —
  `test_check_credentials_audience_bound_regression`, the must-still-pass test.
- `tests/test_azure_token_verifier.py:118-123` — the shared `backend` fixture
  (a real `AzureAuth(user_model=object)` with `.get` stubbed), which these
  tests reuse.

---

## Acceptance Criteria

- [ ] `pytest tests/test_azure_token_verifier.py -v` passes in full, including
      the pre-existing `test_check_credentials_audience_bound_regression`
- [ ] All six tests from spec §4 exist, with those exact names, plus the
      `msal_result_full` fixture
- [ ] No existing test in the file was modified
- [ ] No network access and no real token values
- [ ] `ruff check tests/test_azure_token_verifier.py` clean

---

## Test Specification

This task *is* the test specification; spec §4 "Unit Tests —
`tests/test_azure_token_verifier.py` (extend)" is the authoritative table.

---

## Agent Instructions

1. **Read the spec** §4 (the Azure table and the fixture), §3 Module 3, and
   §6 "Verified third-party behaviour".
2. **Check dependencies** — TASK-105 and TASK-106 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve every `FILL IN`.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-112-tests-azure-capture-refresh.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Appended fixture + 6 spec-named tests and 3 extras (normalizer cache fallback, no-account-id binding, refresh-omits-scope) to tests/test_azure_token_verifier.py; added imports (MagicMock, patch, datetime, AZURE_IDENTITY_SCOPES, TokenResponse). No existing test modified. `pytest tests/test_azure_token_verifier.py`: 16 passed incl. test_check_credentials_audience_bound_regression (artifacts/logs/TASK-112.log); ruff clean. auth_callback tests stub MSAL app, redis pool and capture_login_credential (the vault write itself is covered in TASK-111). The reduced-grant test uses an EXPIRED stored credential so get_live_provider_token returns None; session auth_token asserted unchanged and update_tokens not awaited.
**Deviations from spec**: none
