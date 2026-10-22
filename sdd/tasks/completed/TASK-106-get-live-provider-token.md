# TASK-106: On-demand refresh — `get_live_provider_token` + `refresh_provider_tokens`

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-104, TASK-105
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 4, §2 item 5, §2 "New Public Interfaces", G4.

Capturing the grant (TASK-103/104/105) is not enough to solve the operational
problem. Measured in spec §6: the Entra access token lives **419 s (7.0 min)**
while a Navigator session lives `SESSION_TIMEOUT = 360000 s` (100 h) — a
~850× asymmetry. Without a refresh path, `session["auth_token"]` is dead
minutes after login and the only cure is a re-login.

This task adds the on-demand helper. Two CONFIRMED review findings constrain
it (spec §9):

- `IdentityStore.get_by_provider` (`store.py:222`) returns **the newest**
  enabled account, so a naive implementation can silently refresh and publish
  *another* linked account's credential. Use
  `get_for_provider_account` (TASK-104) instead.
- `AzureAuth.refresh_identity_tokens` (`azure.py:375-384`) requests
  `self.identity_scopes()` → `AZURE_IDENTITY_SCOPES` (`conf.py:548`, default
  `User.Read`), which would **downgrade** a login grant that held, say,
  `Mail.Read`. Hence a separate, credential-aware `refresh_provider_tokens`
  hook that preserves the stored grant's scopes.

---

## Scope

- `navigator_auth/backends/external.py`:
  - `async def get_live_provider_token(request, user_id, *, leeway=IDENTITY_REFRESH_LEEWAY)
    -> Optional[TokenResponse]`: validate the authenticated session's local
    user, `auth_method` and `external_provider_user_id` binding → read the
    exact credential via `get_for_provider_account` → `decrypt_credential` →
    `is_expiring(leeway)` → `refresh_provider_tokens` → `update_tokens` →
    update `session["auth_token"]` and `session["external_expires_at"]`.
  - `async def refresh_provider_tokens(token: TokenResponse) -> TokenResponse`:
    generic hook; the default delegates to the existing
    `refresh_identity_tokens(token.refresh_token)` (`:576`).
- `navigator_auth/backends/azure.py`: override `refresh_provider_tokens` to
  request the **stored grant's** scopes, excluding MSAL-reserved ones; retain
  the requested scopes when the refresh response omits `scope`; return `None`
  (i.e. refuse to publish) when the refresh comes back with an explicitly
  **reduced** permission set.
- `navigator_auth/conf.py`: nothing to add — `IDENTITY_REFRESH_LEEWAY` already
  exists (`:545`, `getint`, default 120).

**NOT in scope**: a middleware that refreshes on every request (spec §1
Non-Goals — this is an on-demand helper); changing `refresh_identity_tokens`
(`external.py:576`, `azure.py:375`) — both stay backward-compatible for the
identity-link flow; changing `get_by_provider`'s newest-wins semantics;
deprecating direct `session["auth_token"]` reads (spec §7, follow-up); tests
(TASK-111 and TASK-112).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/external.py` | MODIFY | `get_live_provider_token` + generic `refresh_provider_tokens` |
| `navigator_auth/backends/azure.py` | MODIFY | `refresh_provider_tokens` override preserving grant scopes |

---

## Codebase Contract

### Verified Imports
```python
from typing import Any, Optional                   # verified: external.py:8
from navigator_session import AUTH_SESSION_OBJECT   # verified: external.py:21
from ..identity.types import TokenResponse          # verified: external.py:27
from ..conf import IDENTITY_REFRESH_LEEWAY          # DOES NOT EXIST in external.py's conf import block
                                                    #   (external.py:28-39) — add it, or import lazily
                                                    #   inside the method as `authorize_identity` does
                                                    #   with IDENTITY_LINK_TTL (external.py:527)
from ..identity.store import IdentityStore          # verified: lazily imported at external.py:465, :612
import msal                                         # verified: azure.py (used at :116-133)
```

### Verified Signatures
```python
# navigator_auth/conf.py
IDENTITY_REFRESH_LEEWAY = config.getint("IDENTITY_REFRESH_LEEWAY", fallback=120)   # verified: :545
AZURE_IDENTITY_SCOPES = [...]            # fallback "User.Read"                    # verified: :548

# navigator_auth/identity/types.py
@dataclass
class TokenResponse:                                                   # verified: :8
    access_token: str; token_type: str = "Bearer"; refresh_token: Optional[str]
    id_token: Optional[str]; expires_in: Optional[int]
    expires_at: Optional[datetime]; scopes: list; provider_user_id: Optional[str]; raw: dict  # :16-24
    def __post_init__(self)                       # derives expires_at from expires_in  # :26-30
    def is_expiring(self, leeway: int = 0) -> bool:                    # verified: :32
        if self.expires_at is None: return False   # <-- NO expiry == NOT expiring     # :34-35
        return self.expires_at <= datetime.now(timezone.utc) + timedelta(seconds=leeway)  # :36-37

# navigator_auth/identity/store.py
async def get_for_provider_account(self, user_id, provider, provider_user_id) -> Optional[UserIdentity]   # TASK-104
async def update_tokens(self, identity: UserIdentity, token: TokenResponse) -> UserIdentity:  # verified: :261
    #  re-seals access_token (and refresh_token ONLY when token.refresh_token is truthy)  # verified: :266-269
    #  sets token_type, expires_at, refreshed_at, key_version; scopes ONLY if token.scopes  # verified: :270-276
def decrypt_credential(self, identity) -> TokenResponse:               # verified: :280
    #  Raises IdentityCredentialError if any stored token fails to open  # verified: :281-287

# navigator_auth/backends/external.py
async def refresh_identity_tokens(self, refresh_token: str) -> "TokenResponse":   # verified: :576
    token = TokenResponse.from_oauth_response(payload)                            # verified: :588
    if not token.refresh_token: token.refresh_token = refresh_token               # verified: :589-591
def get_identity_userid(self, userinfo: dict) -> Optional[str]:                   # verified: :515

# navigator_auth/backends/azure.py
async def refresh_identity_tokens(self, refresh_token: str) -> TokenResponse:     # verified: :375
    cache = msal.SerializableTokenCache(); app = self.get_msal_app(token_cache=cache)  # verified: :376-377
    result = app.acquire_token_by_refresh_token(refresh_token,
                                                scopes=self.identity_scopes())    # verified: :378-380
    token = self._token_from_msal_result(result, cache)                           # verified: :381
    if not token.refresh_token: token.refresh_token = refresh_token               # verified: :382-383
    return token                                                                  # verified: :384
def identity_scopes(self) -> list: return AZURE_IDENTITY_SCOPES                   # verified: :293-297

# navigator_auth/backends/abstract.py
session_key_property: str = SESSION_KEY        # == "id"                           # verified: :71
```

### Session keys this helper reads (written by TASK-103)
```python
session["auth_method"]                  # must equal self._service_name
session["external_provider_user_id"]    # the exact account binding; missing => None
session["auth_token"]                   # updated on a successful refresh
session["external_expires_at"]          # updated on a successful refresh (ISO-8601)
session["user_id"] or session[AUTH_SESSION_OBJECT]["user_id"]   # local user; see external.py:474-477
```

### Does NOT Exist (do not reference)
- **No** `ExternalAuth.get_live_provider_token` and **no**
  `refresh_provider_tokens` — this task creates both.
- **No** middleware or request hook that calls them; they are on-demand.
- **No** `IdentityStore.refresh()` / `.ensure_live()` convenience method.
- **No** `TokenResponse.is_expired()` — the only predicate is
  `is_expiring(leeway)`, and it returns **False** when `expires_at is None`
  (`types.py:34-35`). A credential with no recorded expiry is therefore treated
  as *not* expiring; do not invert that.
- **No** `.default` semantics in a *granted* scope list: `.default` is a
  request selector, so comparing the string `"https://graph.microsoft.com/.default"`
  against returned permissions always "loses". Compare explicit granted
  permissions only (spec §2 item 5).

---

## Implementation Blueprint

### Steps (in order)
1. Block A: the generic `refresh_provider_tokens` hook in `external.py`. It
   goes first so the Azure override has something to override.
2. Block B: `get_live_provider_token`. The ordering inside it is a design
   decision the spec fixes: **validate binding → read → decide → refresh →
   persist → update session**. Never update the session before `update_tokens`
   succeeds, or a crash leaves the session advertising a credential the vault
   does not hold.
3. Block C: the Azure override.
4. Run `pytest tests/unit/identity/ tests/test_azure_token_verifier.py -v`.

### Block A — `navigator_auth/backends/external.py` (generic hook)
```python
# AFTER — insert below the end of `async def refresh_identity_tokens` (external.py:576-591),
#         before `async def get_identity_userinfo`
# occurrences: 1 (verified: grep -c 'async def get_identity_userinfo' navigator_auth/backends/external.py)
    async def refresh_provider_tokens(
        self, token: "TokenResponse"
    ) -> Optional["TokenResponse"]:
        """Refresh a LOGIN grant, preserving what that grant was issued for.

        Distinct from :meth:`refresh_identity_tokens`, which refreshes an
        identity-LINK credential and is free to use ``identity_scopes()``. A
        login grant may hold scopes the identity flow never asks for, and
        silently downgrading them breaks the consumer that needed them.

        The default implementation delegates to ``refresh_identity_tokens``,
        which keeps every backend that has not been adapted working exactly as
        before. Backends whose refresh is scope-sensitive override this
        (``AzureAuth``).

        Args:
            token: The decrypted stored credential, including ``scopes``.

        Returns:
            The rotated credential, or ``None`` when the refresh cannot be
            completed or its result must not replace the stored grant.
        """
        if not token.refresh_token:
            return None
        return await self.refresh_identity_tokens(token.refresh_token)
```
**Why**: `Optional` in the return type — spec §2 requires "a required refresh
that cannot complete" to yield `None` rather than raise, because the caller is
a consumer that wants a token, not an error page. The generic default
deliberately ignores `token.scopes`: the generic OAuth2 `refresh_token` grant
(`external.py:576-591`) sends no `scope` parameter at all, so there is nothing
to downgrade.

### Block B — `navigator_auth/backends/external.py` (`get_live_provider_token`)
```python
# AFTER — insert below the method added by Block A
    async def get_live_provider_token(
        self,
        request: web.Request,
        user_id: Any,
        *,
        leeway: Optional[int] = None,
    ) -> Optional["TokenResponse"]:
        """Return a non-expired provider credential, refreshing if needed.

        The session's provider access token (``session["auth_token"]``) can
        outlive its usefulness by a factor of hundreds — a measured 7-minute
        Entra token inside a 100-hour session (spec §6). A consumer that needs
        to call the provider calls this instead of reading the session key.

        Args:
            request: The authenticated request.
            user_id: Local Navigator user id. MUST match the session's own
                local user; a mismatch returns ``None``.
            leeway: Refresh when the credential expires within this many
                seconds. Defaults to ``IDENTITY_REFRESH_LEEWAY``
                (``conf.py:545``, 120).

        Returns:
            A live ``TokenResponse``, or ``None`` when the account binding is
            missing or mismatched, no credential is stored, or a required
            refresh cannot complete.

        Note:
            Never falls back to another linked account, however recently it was
            linked or refreshed — ``get_by_provider``'s newest-wins selection
            is deliberately NOT used here.
        """
        from navigator_session import get_session
        from ..identity.store import IdentityStore
        from ..conf import IDENTITY_REFRESH_LEEWAY

        if leeway is None:
            leeway = IDENTITY_REFRESH_LEEWAY
        try:
            session = await get_session(request, new=False)
            if not session:
                return None
            if session.get("auth_method") != self._service_name:
                self.logger.warning(
                    f"{self._service_name}: get_live_provider_token called on a "
                    f"session authenticated by {session.get('auth_method')!r}."
                )
                return None
            session_user = session.get("user_id")
            if session_user is None:
                session_obj = session.get(AUTH_SESSION_OBJECT) or {}
                session_user = session_obj.get("user_id")
            if session_user is None or str(session_user) != str(user_id):
                self.logger.warning(
                    f"{self._service_name}: user_id does not match the session."
                )
                return None
            provider_user_id = session.get("external_provider_user_id")
            if not provider_user_id:
                # A legacy session predating FEAT-103 carries no binding.
                # Guessing an account is worse than requiring a re-login.
                self.logger.warning(
                    f"{self._service_name}: session has no external account "
                    "binding; re-login required."
                )
                return None
            store = IdentityStore(request.app["authdb"])
            identity = await store.get_for_provider_account(
                session_user, self._service_name, provider_user_id
            )
            if identity is None:
                return None
            token = store.decrypt_credential(identity)
            if not token.is_expiring(leeway):
                return token
            refreshed = await self.refresh_provider_tokens(token)
            if refreshed is None:
                # FILL IN: decide whether a STILL-VALID-but-expiring token is
                # returned here instead of None — bounded by spec §5's "a fresh
                # access token remains usable without a refresh token" and by
                # test_get_live_provider_token_without_refresh_token_returns_none,
                # which expects None for an EXPIRED credential and a token for a
                # fresh one. is_expiring(leeway) is True for both cases, so this
                # branch must distinguish them (hint: is_expiring(0)).
                return None
            await store.update_tokens(identity, refreshed)
            session["auth_token"] = refreshed.access_token
            if refreshed.expires_at is not None:
                session["external_expires_at"] = refreshed.expires_at.isoformat()
            session["has_refresh_token"] = bool(refreshed.refresh_token)
            return refreshed
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"{self._service_name}: cannot obtain a live provider token: {err}"
            )
            return None
```
**Why each ordering decision**:
- The three binding checks come **before** any store access, so a mismatched
  caller never even reads another user's ciphered row.
- `str(...) != str(...)` because `user_id` arrives as an int from some
  backends and a string from others (`build_user_info` writes
  `userdata[self.session_key_property] = userid` unconverted, `external.py:693`).
- `update_tokens` **before** the session writes: the vault is the system of
  record. If it fails, the exception handler returns `None` and the session
  still points at the old (dead) token, which is recoverable; the reverse is
  not.
- `decrypt_credential` can raise `IdentityCredentialError` ("the identity must
  be re-linked", `store.py:281-287`); the broad catch turns that into `None`,
  which is the documented contract.
- The session is mutated in place; `navigator-session`'s middleware persists it
  when `is_changed` (`middleware.py:45-57`), so no explicit save call.

### Block C — `navigator_auth/backends/azure.py` (override)
```python
# AFTER — insert below the end of `async def refresh_identity_tokens` (azure.py:375-384),
#         before `async def logout`
# occurrences: 1 (verified: grep -c 'async def logout(self, request):' navigator_auth/backends/azure.py)
    async def refresh_provider_tokens(
        self, token: TokenResponse
    ) -> Optional[TokenResponse]:
        """Refresh an Azure LOGIN grant without downgrading its scopes.

        ``refresh_identity_tokens`` (``:375``) asks for
        ``AZURE_IDENTITY_SCOPES`` (``conf.py:548``, default ``User.Read``),
        which is correct for an identity LINK and wrong for a login grant that
        may hold more. This override requests the stored grant's own scopes,
        minus the MSAL-reserved ones MSAL adds itself.

        Returns:
            The rotated credential, or ``None`` when the refresh fails or comes
            back with an explicitly REDUCED permission set (which must not
            replace the session credential).
        """
        if not token.refresh_token:
            return None
        requested = [
            s for s in (token.scopes or []) if s not in MSAL_RESERVED_SCOPES
        ]
        if not requested:
            requested = self.identity_scopes()
        cache = msal.SerializableTokenCache()
        app = self.get_msal_app(token_cache=cache)
        result = app.acquire_token_by_refresh_token(
            token.refresh_token, scopes=requested
        )
        refreshed = self._token_from_msal_result(
            result, cache, requested_scopes=requested
        )
        if not refreshed.refresh_token:
            # Entra did not rotate: keep using the current one.
            refreshed.refresh_token = token.refresh_token
        # FILL IN: reduced-grant detection — compare the EXPLICIT granted
        # permissions of `token.scopes` against `refreshed.scopes` and return
        # None when any explicitly-held permission is missing. Bounded by spec
        # §2 item 5: "`.default` is a request selector, so compare explicit
        # granted permissions where available, not the selector string against
        # returned permissions", and by
        # test_azure_refresh_reduced_grant_is_not_published, which removes
        # Mail.Read from a previously explicit grant and expects None plus an
        # UNCHANGED session auth_token.
        return refreshed
```
**Why**: `requested` falls back to `identity_scopes()` only when the stored
grant recorded **no** scopes at all — a legacy row from before TASK-105's
scope capture. That is the one case where the old downgrade behaviour is the
best available, and it is logged by the generic caller rather than silently
preferred.
`MSAL_RESERVED_SCOPES` is the module constant TASK-105 adds; do not redefine it.

### FILL IN checklist
- [ ] Block B: distinguishing "expiring but still valid, no refresh available"
      (return the token) from "already expired, no refresh available"
      (return `None`).
- [ ] Block C: the reduced-grant comparison, handling `.default` as a selector.

---

## Implementation Notes

### Key Constraints
- **Never select another account.** This is the whole point of
  `get_for_provider_account`. `get_by_provider` (`store.py:222-245`) sorts by
  `refreshed_at`/`created_at` descending and returns `rows[0]` — using it here
  reintroduces the CONFIRMED finding in spec §9.
- `update_tokens` (`store.py:261-278`) only re-seals `refresh_token` when the
  new token carries one, and only replaces `scopes` when non-empty. Relying on
  that is correct; do not pre-blank either field.
- With 7-minute tokens and `IDENTITY_REFRESH_LEEWAY=120`, a Graph-using session
  refreshes roughly every 5 minutes (spec §7). The leeway is operator-tunable
  precisely so this can be backed off without a release — do not hardcode it.
- Never log a token value; `mask_value` (`identity/types.py:93`) exists for
  diagnostics.

### References in Codebase
- `navigator_auth/identity/store.py:261-278` — `update_tokens`, the rotation
  persistence path.
- `navigator_auth/backends/external.py:611` — `finish_identity_link`, which
  already does read → decrypt → store in the link flow.
- `navigator_auth/backends/oauth2/backend.py` — refresh rotation/reuse
  precedent (TASK-026 in that spec), for the "persist before publish" ordering.

---

## Acceptance Criteria

- [ ] No `refresh_provider_tokens` call when `is_expiring(leeway)` is False
- [ ] An expiring credential triggers the refresh, `update_tokens` persists it,
      and `session["auth_token"]` / `session["external_expires_at"]` are updated
- [ ] An **expired** credential with no refresh token returns `None` without
      raising; a **fresh** credential is still returned
- [ ] Log in as account A, link/refresh account B more recently, expire A: only
      A is read, refreshed and written to the session
- [ ] A missing / deleted / disabled account, a wrong local user, or a wrong
      `auth_method` returns `None` with **no** provider call and **no** session
      mutation
- [ ] An Azure login grant holding `User.Read` + `Mail.Read` refreshes with
      both, despite `AZURE_IDENTITY_SCOPES` being `User.Read`; reserved scopes
      are excluded
- [ ] A refresh that explicitly drops `Mail.Read` returns `None` and leaves
      `session["auth_token"]` untouched
- [ ] `pytest tests/unit/identity/ tests/test_azure_token_verifier.py -v` passes
- [ ] `ruff check navigator_auth/backends/external.py navigator_auth/backends/azure.py` clean

---

## Test Specification

Tests live in TASK-111 (`test_get_live_provider_token_returns_cached_when_fresh`,
`test_get_live_provider_token_refreshes_when_expiring`,
`test_get_live_provider_token_without_refresh_token_returns_none`,
`test_refresh_uses_login_account_not_newest_link`,
`test_refresh_rejects_missing_or_mismatched_binding`) and TASK-112
(`test_azure_login_refresh_preserves_grant_scopes`,
`test_azure_refresh_reduced_grant_is_not_published`) — spec §4.

---

## Agent Instructions

1. **Read the spec** §3 Module 4, §2 item 5, and §9's CONFIRMED findings about
   `get_by_provider` and `AZURE_IDENTITY_SCOPES`.
2. **Check dependencies** — TASK-104 and TASK-105 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve both `FILL IN`s.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-106-get-live-provider-token.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Blocks A-C applied. FILL INs: (1) when refresh yields None (or raises), a credential that is expiring-within-leeway but not yet expired (`not is_expiring(0)`) is returned as-is; an already-expired one yields None. A refresh exception is caught inside so this fallback applies to it too. (2) Azure reduced-grant: `_explicit_permissions` drops MSAL-reserved scopes and `.default` selectors and strips resource prefixes (case-insensitive); None is returned if any held explicit permission is missing from the refreshed grant. Hand-run smoke (artifacts/logs/TASK-106.log): refresh requested ['User.Read','Mail.Read'] (no openid; not AZURE_IDENTITY_SCOPES); dropping Mail.Read -> None; full grant -> rotated token with refresh token retained. pytest identity+azure verifier: 139 passed; ruff azure.py clean, external.py only the 2 pre-existing F841. Real tests are TASK-111/112.
**Deviations from spec**: `leeway` signature is `Optional[int]=None` resolving to IDENTITY_REFRESH_LEEWAY (as in the task blueprint) rather than a module-level default in the spec's sketch.
