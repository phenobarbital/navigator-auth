# TASK-105: Wire `AzureAuth` to capture the full MSAL grant

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-103, TASK-104
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 3, §2 item 1, §2 "New Public Interfaces", §9 (CONFIRMED review
findings).

Both Azure login paths read three keys out of the MSAL result and discard the
rest:

- `auth_callback` (`azure.py:223`): `token_type` (`:255`), `access_token`
  (`:256`) — no `id_token`, no `refresh_token`, no `expires_in`; and it builds
  the MSAL app with **no token cache** (`:240`), so even the cache fallback has
  nothing to read.
- the user/password (ROPC) branch of `authenticate` (`:135-176`): uses
  `get_msal_client()` (`:126`), which accepts no `token_cache` at all.

`_token_from_msal_result` (`:320-336`) already normalizes a result into a
`TokenResponse`, but its body is **incomplete** — it passes no `id_token=` and
reads the refresh token *only* from the cache (`:332`). Its sibling docstring
on `_refresh_token_from_cache` (`:304-307`) claims "MSAL never returns the
refresh token in the result dict", which is true only for
`acquire_token_silent`: spec §6 verified against installed `msal 1.38.0` that
`_clean_up` (`application.py:155-166`) strips only `refresh_in` and
`_`-prefixed keys, and `Client._obtain_token` (`oauth2cli/oauth2.py:865-895`)
pops `refresh_token` only from the cache-callback copy and only for
`grant_type == "refresh_token"`. **The authorization_code result keeps it.**

---

## Scope

- `navigator_auth/backends/azure.py`:
  - Extend `_token_from_msal_result` (`:320`): capture `id_token`, and prefer
    `result.get("refresh_token")` with the cache as fallback. Accept an
    explicit requested-scopes argument used when the result omits `scope`.
  - Fix the `_refresh_token_from_cache` docstring (`:304-307`) to say what is
    actually true.
  - `auth_callback`: pass a `msal.SerializableTokenCache()` into
    `get_msal_app` (`:116` already accepts one); build the `TokenResponse` via
    `_token_from_msal_result`; pass `id_token` / `refresh_token` /
    `expires_at` / `provider_user_id` into `build_user_info`; call
    `capture_login_credential(request, token)` after `validate_user_info`.
  - ROPC branch of `authenticate`: give it cache support — either add a
    `token_cache` parameter to `get_msal_client` (`:126`) or route it through
    `get_msal_app`, **without changing its grant** — then do the same capture.
  - Supply the actual requested scopes when the result omits them:
    `["https://graph.microsoft.com/.default"]` for the callback (`:205`),
    `["User.ReadBasic.All"]` for ROPC (`:146`).
  - Derive `provider_user_id` from the **verified Graph userinfo** via
    `get_identity_userid` (`azure.py:299`), never from a request parameter.

**NOT in scope**: `get_live_provider_token` / `refresh_provider_tokens`
(TASK-106); `AZURE_FLOW_TTL` / `max_age` (TASK-109 — coordinate, both touch
`azure.py`); redaction in `check_credentials` (TASK-108); the other providers
(spec §1 Non-Goals); tests (TASK-112).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/azure.py` | MODIFY | normalizer, both login paths, cache plumbing, docstring fix |

---

## Codebase Contract

### Verified Imports
```python
import msal                                    # verified: navigator_auth/backends/azure.py (used at :116-133)
from msal.authority import AuthorityBuilder    # verified: used at :108
import orjson                                  # verified: used at :234, :259
from ..identity.types import TokenResponse     # verified: used as return type at :321
from ..exceptions import AuthException, InvalidAuth   # verified: used at :328, :543
from ..conf import (AZURE_ADFS_CLIENT_ID, AZURE_ADFS_CLIENT_SECRET,
                    AZURE_ADFS_TENANT_ID, AZURE_ADFS_DOMAIN,
                    AZURE_SESSION_TIMEOUT, AZURE_PUBLIC)   # verified: used at :102-124, :212, :217
from ..conf import AZURE_IDENTITY_SCOPES       # verified: lazily imported at :294
from ..libs.json import json_decoder           # verified: used at :162
```

### Verified Signatures
```python
# navigator_auth/backends/azure.py
class AzureAuth(ExternalAuth):                                           # verified: :75
    def get_msal_app(self, token_cache: msal.SerializableTokenCache = None):   # verified: :116
        return msal.ConfidentialClientApplication(..., token_cache=token_cache)    # verified: :118-124
    def get_msal_client(self):                                           # verified: :126  (NO token_cache param)
        return msal.ClientApplication(AZURE_ADFS_CLIENT_ID, authority=authority,
                                      client_credential=AZURE_ADFS_CLIENT_SECRET,
                                      validate_authority=True)           # verified: :128-133
    async def authenticate(self, request):                               # verified: :135
        Default_SCOPE = ["User.ReadBasic.All"]                           # verified: :146
        app = self.get_msal_client()                                     # verified: :148
        accounts = app.get_accounts(username=user); result = app.acquire_token_silent(...)  # verified: :150-153
        result = app.acquire_token_by_username_password(user, pwd, Default_SCOPE)           # verified: :156
        client_info = json_decoder(decode_part(result["client_info"]))   # verified: :160-162
        access_token = result["access_token"]                            # verified: :165
        data = await self.get(url=self.userinfo_uri, token=access_token, token_type="Bearer")  # verified: :166-170
        data = {**data, **client_info}                                   # verified: :171
        userdata, uid = self.build_user_info(userdata=data, token=access_token,
                                             mapping=self.user_mapping)  # verified: :172-174
        data = await self.validate_user_info(request, uid, userdata, access_token)   # verified: :176
        return self.home_redirect(request, token=data["token"], token_type=self.scheme)  # verified: :178
        SCOPE = ["https://graph.microsoft.com/.default"]                 # verified: :205
        app = self.get_msal_app()                                        # verified: :206
        flow = app.initiate_auth_code_flow(scopes=SCOPE, redirect_uri=redirect_uri,
                 domain_hint=AZURE_ADFS_DOMAIN, max_age=int(AZURE_SESSION_TIMEOUT))   # verified: :208-213
        await redis.setex(f"azure_auth_{state}", AZURE_SESSION_TIMEOUT, json_encoder(flow))  # verified: :217
    async def auth_callback(self, request):                              # verified: :223
        app = self.get_msal_app()                                        # verified: :240
        result = app.acquire_token_by_auth_code_flow(auth_code_flow=flow,
                                                    auth_response=auth_response)     # verified: :243
        token_type = result["token_type"]                                # verified: :255
        access_token = result["access_token"]                            # verified: :256
        client_info = orjson.loads(decode_part(result["client_info"]))   # verified: :257-259
        data = await self.get(url=self.userinfo_uri, token=access_token, token_type=token_type)  # verified: :262-266
        data = {**data, **client_info}                                   # verified: :268
        userdata, uid = self.build_user_info(userdata=data, token=access_token,
                                             mapping=self.user_mapping)  # verified: :269
        data = await self.validate_user_info(request, uid, userdata, access_token)   # verified: :270
        return self.home_redirect(request, token=token, token_type=token_type,
                                  uri=internal_redirect)                 # verified: :281
    def identity_scopes(self) -> list: return AZURE_IDENTITY_SCOPES      # verified: :293-297
    def get_identity_userid(self, userinfo: dict):                       # verified: :299
        value = userinfo.get("id", userinfo.get("userPrincipalName"))    # verified: :300
        return str(value) if value is not None else None                 # verified: :301
    @staticmethod
    def _refresh_token_from_cache(cache) -> Optional[str]:               # verified: :304-317
        tokens = cache.find(msal.TokenCache.CredentialType.REFRESH_TOKEN)   # verified: :309
    @staticmethod
    def _token_from_msal_result(result: dict, cache) -> TokenResponse:   # verified: :320-336
        if "error" in result or "access_token" not in result: raise AuthException(...)   # verified: :323-326
        scope = result.get("scope"); scopes = scope.split() if isinstance(scope, str) else list(scope or [])  # verified: :327-328
        return TokenResponse(access_token=result["access_token"],
            token_type=result.get("token_type", "Bearer"),
            refresh_token=AzureAuth._refresh_token_from_cache(cache),    # verified: :332  <- cache ONLY
            expires_in=result.get("expires_in"), scopes=scopes,
            raw={k: v for k, v in result.items() if k != "refresh_token"})   # verified: :329-336
        #  NOTE: NO `id_token=` argument anywhere in this call.
    async def exchange_code_for_tokens(self, request, flow) -> TokenResponse:   # verified: :363
        cache = msal.SerializableTokenCache(); app = self.get_msal_app(token_cache=cache)  # verified: :366-367
        return self._token_from_msal_result(result, cache)               # verified: :373
    async def refresh_identity_tokens(self, refresh_token) -> TokenResponse:    # verified: :375

# navigator_auth/backends/external.py (after TASK-103 / TASK-104)
def build_user_info(self, userdata, token, mapping, *, id_token=None,
                    refresh_token=None, expires_at=None, provider_user_id=None) -> tuple
async def capture_login_credential(self, request, token: TokenResponse) -> None
```

### Verified third-party behaviour (`msal 1.38.0`, in `.venv`)
```python
# msal/application.py
_decorate_scope(..., reserved_scope=frozenset(['openid','profile','offline_access']))  # verified: :832-834
decorated = scope_set | reserved_scope                                                 # verified: :851
#  => offline_access is ALWAYS requested. NO scope change is needed to get a refresh token.
def _clean_up(result): return {k: result[k] for k in result
        if k != "refresh_in" and not k.startswith('_')}                                # verified: :155-166
#  => id_token / id_token_claims / refresh_token all SURVIVE into the result dict.
# msal/oauth2cli/oauth2.py
if grant_type == RT and RT in _resp and not also_save_rt: _resp.pop(RT, None)           # verified: :876-879
return resp   # the ORIGINAL resp, unmodified                                          # verified: :895
#  => the authorization_code result KEEPS refresh_token.
```

### Does NOT Exist (do not reference)
- **No** `token_cache` parameter on `get_msal_client` (`azure.py:126-133`) —
  that is precisely the gap this task closes for the ROPC path.
- **No** `AZURE_REFRESH_SCOPES` / `AZURE_OFFLINE_ACCESS` setting, and none is
  needed: MSAL adds `offline_access` itself (verified above).
- **No** `id_token` argument in the current `_token_from_msal_result` call to
  `TokenResponse`.
- **No** `msal.PublicClientApplication` use in this backend — `get_msal_app`
  builds a `ConfidentialClientApplication` and `get_msal_client` a
  `ClientApplication`. Do not swap either class.
- **No** `expires_at` in the MSAL result: it returns `expires_in` (seconds) and
  `TokenResponse.__post_init__` (`identity/types.py:26-30`) derives
  `expires_at` from it. Pass `token.expires_at` downstream, not a hand-computed
  datetime.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: fix the `_refresh_token_from_cache` docstring. Do this first and
   separately — it is the claim that caused the incomplete normalizer, and
   leaving it in place invites the next reader to re-introduce the bug.
2. Block B: complete `_token_from_msal_result`. Add `id_token`, prefer the
   result's refresh token, and accept `requested_scopes` for the
   result-omits-`scope` case.
3. Block C: `auth_callback` — cache + capture. Note the `app = self.get_msal_app()`
   anchor appears **3 times** in this file, so the block quotes surrounding
   context.
4. Block D: `get_msal_client(token_cache=None)` + the ROPC capture.
5. Run `pytest tests/test_azure_token_verifier.py -v` — in particular the
   pre-existing `test_check_credentials_audience_bound_regression` (`:241`).

### Block A — `navigator_auth/backends/azure.py` (docstring fix)
```python
# REPLACE — the `_refresh_token_from_cache` docstring
# occurrences: 1 (verified: grep -c 'MSAL never returns the refresh token' navigator_auth/backends/azure.py)
        """Read a refresh token out of an MSAL token cache.

        Verified against msal 1.38.0: the ``authorization_code`` and
        ``refresh_token`` grants DO return ``refresh_token`` in the result dict
        (``_clean_up`` strips only ``refresh_in`` and ``_``-prefixed keys,
        ``application.py:155-166``). Only ``acquire_token_silent`` hides it.
        This helper is therefore a FALLBACK for results that omit it, not the
        primary source — see ``_token_from_msal_result``.
        """
```
**Why**: the old docstring is the load-bearing false claim behind the
incomplete normalizer (spec §9, CONFIRMED). Correcting it is part of the fix,
not documentation polish.

### Block B — `navigator_auth/backends/azure.py` (`_token_from_msal_result`)
```python
# REPLACE — the whole `_token_from_msal_result` static method (azure.py:319-336, decorator at :319)
# occurrences: 1 (verified: grep -c 'def _token_from_msal_result' navigator_auth/backends/azure.py)
    @staticmethod
    def _token_from_msal_result(
        result: dict,
        cache: msal.SerializableTokenCache,
        requested_scopes: Optional[list] = None,
    ) -> TokenResponse:
        """Normalize an MSAL result dict into a ``TokenResponse``.

        Args:
            result: Raw MSAL result from any grant.
            cache: The cache the MSAL app was built with; used only as a
                refresh-token fallback.
            requested_scopes: Scopes this grant actually asked for, used when
                the result omits ``scope``. MSAL-reserved scopes
                (``openid``/``profile``/``offline_access``) are dropped — MSAL
                adds them itself and Entra rejects them in a scopes list.

        Raises:
            AuthException: when the result carries an error or no access token.
        """
        if "error" in result or "access_token" not in result:
            error = result.get("error", "unknown_error")
            desc = result.get("error_description", "")
            raise AuthException(f"azure: {error}: {desc}")
        scope = result.get("scope")
        scopes = scope.split() if isinstance(scope, str) else list(scope or [])
        if not scopes and requested_scopes:
            scopes = [
                s for s in requested_scopes if s not in MSAL_RESERVED_SCOPES
            ]
        return TokenResponse(
            access_token=result["access_token"],
            token_type=result.get("token_type", "Bearer"),
            # msal 1.38.0 returns refresh_token on the authorization_code and
            # refresh_token grants; the cache is only a fallback (see
            # _refresh_token_from_cache).
            refresh_token=(
                result.get("refresh_token")
                or AzureAuth._refresh_token_from_cache(cache)
            ),
            id_token=result.get("id_token"),
            expires_in=result.get("expires_in"),
            scopes=scopes,
            raw={k: v for k, v in result.items() if k != "refresh_token"},
        )
```
```python
# AFTER — insert below the line `from ..identity.types import TokenResponse` (module imports)
# FILL IN: place this constant at module scope next to the other module-level
# names — bounded by "reserved scopes are excluded" (spec §4
# test_azure_login_refresh_preserves_grant_scopes) and by msal's own
# `reserved_scope` frozenset (application.py:833).
#: MSAL adds these itself (application.py:832-851); they must never appear in
#: a scopes list we send back to Entra.
MSAL_RESERVED_SCOPES = frozenset({"openid", "profile", "offline_access"})
```
**Why**: `raw` still excludes `refresh_token` — that exclusion is deliberate
and predates this task: `raw` is persisted/logged in places the secret must not
reach. The refresh token travels in the typed `refresh_token` field only.
`requested_scopes` is a parameter rather than a per-call-site post-hoc patch so
that both login paths and `exchange_code_for_tokens` (`:363`, which passes
nothing and keeps today's behaviour) share one rule.

### Block C — `navigator_auth/backends/azure.py` (`auth_callback`)
```python
# REPLACE — the MSAL app construction inside auth_callback. The bare line
#   `app = self.get_msal_app()` has 3 occurrences in this file
#   (verified: grep -c 'app = self.get_msal_app()' navigator_auth/backends/azure.py -> 3),
#   so match on the surrounding two lines, which are unique:
# occurrences: 1 (verified: grep -c 'internal_redirect = flow.pop' navigator_auth/backends/azure.py)
            cache = msal.SerializableTokenCache()
            app = self.get_msal_app(token_cache=cache)
            internal_redirect = flow.pop("internal_redirect", None)
```
```python
# REPLACE — the capture block inside auth_callback, from `token_type = result["token_type"]`
#           down to and including the `validate_user_info` call
# occurrences: 1 (verified: grep -c 'token_type = result\["token_type"\]' navigator_auth/backends/azure.py)
                grant = self._token_from_msal_result(
                    result,
                    cache,
                    requested_scopes=["https://graph.microsoft.com/.default"],
                )
                token_type = grant.token_type
                access_token = grant.access_token
                client_info = {}
                if "client_info" in result:
                    # It happens when client_info and profile are in request
                    client_info = orjson.loads(decode_part(result["client_info"]))
                # getting user information:
                try:
                    data = await self.get(
                        url=self.userinfo_uri,
                        token=access_token,
                        token_type=token_type,
                    )
                    # build user information:
                    data = {**data, **client_info}
                    # FEAT-103 Module 3: the external account id comes from the
                    # VERIFIED Graph profile, never from a request parameter.
                    grant.provider_user_id = self.get_identity_userid(data)
                    userdata, uid = self.build_user_info(
                        userdata=data,
                        token=access_token,
                        mapping=self.user_mapping,
                        id_token=grant.id_token,
                        refresh_token=grant.refresh_token,
                        expires_at=grant.expires_at,
                        provider_user_id=grant.provider_user_id,
                    )
                    data = await self.validate_user_info(
                        request, uid, userdata, access_token
                    )
                    # Vault the full grant AFTER the session exists — the
                    # ciphered write keys on the local user_id.
                    await self.capture_login_credential(request, grant)
                except Exception as err:
                    logging.exception(f"Azure: Error getting User information: {err}")
                    return self.failed_redirect(
                        request, error="ERROR_USER_NOT_FOUND",
                        message=f"Error getting User information: {err}"
                    )
```
**Why**: the `_token_from_msal_result` call replaces the raw `result[...]`
reads, so a malformed result now raises `AuthException` in one place instead of
`KeyError` in two. `capture_login_credential` sits **inside** the existing
`try` so a vault problem cannot escape the callback — and it is best-effort
internally anyway (TASK-104), making this belt and braces.
**FILL IN: confirm whether the existing `if "token_type" not in result:` error
branch (`:244-254`) should be left ahead of the normalizer or folded into it**
— bounded by "a failed login must keep the backend's own `failed_redirect`
response", i.e. the user-visible error pages must not change.

### Block D — `navigator_auth/backends/azure.py` (ROPC path)
```python
# REPLACE — the whole `get_msal_client` method
# occurrences: 1 (verified: grep -c 'def get_msal_client' navigator_auth/backends/azure.py)
    def get_msal_client(self, token_cache: msal.SerializableTokenCache = None):
        """Public-client app used by the user/password (ROPC) grant.

        Takes an optional ``token_cache`` so the ROPC login can capture the
        refresh token, mirroring ``get_msal_app`` (``:116``). The grant itself
        is unchanged.
        """
        authority = self._issuer if self._issuer else self.authority
        return msal.ClientApplication(
            AZURE_ADFS_CLIENT_ID,
            authority=authority,
            client_credential=AZURE_ADFS_CLIENT_SECRET,
            validate_authority=True,
            token_cache=token_cache,
        )
```
```python
# REPLACE — the ROPC app construction
# occurrences: 1 (verified: grep -c 'app = self.get_msal_client()' navigator_auth/backends/azure.py)
            cache = msal.SerializableTokenCache()
            app = self.get_msal_client(token_cache=cache)
```
```python
# REPLACE — the ROPC capture block, from `if "access_token" in result:` through
#           the `validate_user_info` call and the home_redirect
# occurrences: 1 (verified: grep -c 'if "access_token" in result:' navigator_auth/backends/azure.py)
                    if "access_token" in result:
                        grant = self._token_from_msal_result(
                            result, cache, requested_scopes=Default_SCOPE
                        )
                        access_token = grant.access_token
                        data = await self.get(
                            url=self.userinfo_uri,
                            token=access_token,
                            token_type="Bearer",
                        )
                        data = {**data, **client_info}
                        grant.provider_user_id = self.get_identity_userid(data)
                        userdata, uid = self.build_user_info(
                            userdata=data,
                            token=access_token,
                            mapping=self.user_mapping,
                            id_token=grant.id_token,
                            refresh_token=grant.refresh_token,
                            expires_at=grant.expires_at,
                            provider_user_id=grant.provider_user_id,
                        )
                        # also, user information:
                        data = await self.validate_user_info(
                            request, uid, userdata, access_token
                        )
                        await self.capture_login_credential(request, grant)
                        # Redirect User to HOME
                        return self.home_redirect(
                            request, token=data["token"], token_type=self.scheme
                        )
```
**Why**: `Default_SCOPE` (`:146`) is `["User.ReadBasic.All"]` — a *different*
grant from the callback's `.default`, which is exactly why the requested-scopes
value is per-call-site and not a constant. Spec §4's
`test_azure_missing_scope_fallback` asserts each path captures its own.
**FILL IN: the `acquire_token_silent` branch (`:150-153`) also produces a
`result`** — decide whether a cache-hit login captures too, bounded by the fact
that `acquire_token_silent` does **not** return `refresh_token` (verified, msal
`oauth2.py:876-879`), so capture there would vault a grant whose
`has_refresh_token` is False unless the cache supplies it.

### FILL IN checklist
- [ ] Block B: final placement of `MSAL_RESERVED_SCOPES` at module scope.
- [ ] Block C: whether the `"token_type" not in result` error branch stays
      ahead of the normalizer.
- [ ] Block D: whether the `acquire_token_silent` cache-hit path captures.

---

## Implementation Notes

### Key Constraints
- Never log a token value. Use `mask_value` (`identity/types.py:93`) if a
  diagnostic is genuinely needed (spec §7).
- `msal.SerializableTokenCache()` is created per request, never shared — the
  backends are process-wide singletons (see the FEAT-095 note at
  `azure.py:195-199` about exactly this class of bug).
- Do not change `max_age` or the `setex` TTL here; that is TASK-109. Both tasks
  edit `azure.py`, so **sequence them, do not run them concurrently** (spec
  Worktree Strategy).
- `exchange_code_for_tokens` (`:363`) and `refresh_identity_tokens` (`:375`)
  already call `_token_from_msal_result` with two positional arguments — the
  new third parameter must stay optional so they are unaffected.

### References in Codebase
- `navigator_auth/backends/azure.py:363-375` — `exchange_code_for_tokens`, the
  existing cache-aware pattern to copy.
- `navigator_auth/backends/external.py:611` — `finish_identity_link`, the
  full-grant vault write.

---

## Acceptance Criteria

- [ ] A stubbed MSAL result containing `refresh_token` + `id_token` reaches
      `build_user_info` and the vault write
- [ ] A result **without** `refresh_token` falls back to
      `_refresh_token_from_cache`
- [ ] When result and cache hold different refresh tokens, the **result** wins
- [ ] `id_token` is copied into the `TokenResponse`
- [ ] Both login paths capture their own requested scopes when the result omits
      `scope`, with MSAL-reserved scopes excluded
- [ ] `provider_user_id` comes from the verified Graph profile; a profile with
      neither `id` nor `userPrincipalName` results in **no** vault row
- [ ] `pytest tests/test_azure_token_verifier.py -v` passes, including the
      pre-existing `test_check_credentials_audience_bound_regression` (`:241`)
- [ ] `ruff check navigator_auth/backends/azure.py` clean

---

## Test Specification

Tests live in TASK-112:
`test_auth_callback_captures_refresh_and_id_token`,
`test_auth_callback_refresh_token_from_cache_fallback`,
`test_msal_normalizer_captures_id_and_prefers_result_refresh`,
`test_azure_missing_scope_fallback` (spec §4).

---

## Agent Instructions

1. **Read the spec** §3 Module 3, §2 item 1, and §6 "Verified third-party
   behaviour".
2. **Check dependencies** — TASK-103 and TASK-104 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve every `FILL IN`.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-105-azure-token-capture-wiring.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Blocks A-D applied. FILL INs: MSAL_RESERVED_SCOPES placed at module scope just above `class AzureAuth`; the `"token_type" not in result` error branch stays AHEAD of the normalizer (user-visible failed_redirect pages unchanged); the acquire_token_silent cache-hit path does NOT capture (it never returns a refresh_token, and the existing code does nothing with a silent hit anyway). Smoke check of the normalizer printed `r i ['User.Read'] True`. pytest test_azure_token_verifier + tests/unit/identity: 139 passed (artifacts/logs/TASK-105.log); ruff azure.py clean. Behavioural tests are TASK-112.
**Deviations from spec**: none
