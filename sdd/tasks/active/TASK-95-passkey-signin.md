# TASK-95: Passkey sign-in — `login/options` and `PasskeyAuth.authenticate`

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 5, §2 Overview items 5–6, §7 R1/R4/R8, AC4, AC6, AC7, AC8, AC10)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-93, TASK-90, TASK-91
**Assigned-to**: unassigned

---

## Context

This is the core of the feature. `login/options` starts a ceremony:
- **username-first** is the default (Q9): known users get their `allowCredentials`, and unknown
  users get same-shaped decoys (E5);
- **usernameless** gets an empty list, for conditional UI.

The assertion then arrives through the **unchanged** `POST /api/v1/login` with
`X-Auth-Method: PasskeyAuth` and reaches `PasskeyAuth.authenticate`. That method runs the 10-step
verification of spec §2.5, then `open_session(..., extra=...)`.

TASK-91 must be merged: `open_session` supplies the `is_active` rejection (E9) and the
`mfa`/`amr` JWT keys (AC6).

---

## Scope

- Replace the TASK-93 stubs `login_options` and `authenticate`, and add `_check_tenant`, in `navigator_auth/backends/passkey.py`.
- `login_options`, which is public:
  1. resolve the RP;
  2. read the optional JSON body `{username}`;
  3. **username-first**: look the user up through `self._idp.get_user(username)` (`UserNotFound` → unknown).
     - Known user with credentials for the RP: `allowCredentials` = those credentials, `expected_user_id = user_id`.
     - Otherwise: `allowCredentials` = `self._decoy_ids(rp, username)` and `decoy=True`.
     - **Always** do the DB lookup, so timing stays comparable (R4);
  4. **usernameless** (no or empty username): `allowCredentials = []`;
  5. `challenge_id = secrets.token_urlsafe(32)`; save under `("login", challenge_id)`;
  6. return `{"challenge_id", "publicKey": <options JSON object>}`.
- `authenticate(request)`, in the spec §2.5 order:
  1. `challenge_id, credential = await self.get_payload(request)` (fails fast, no I/O);
  2. `state = _pop_challenge("login", challenge_id)` (E1/E2);
  3. load the credential by `rawId`. Missing, or `cred.rp_id != state.rp_id`, is a uniform 401 (E3/E4);
  4. if `state.expected_user_id` is set, `cred.user_id` must equal it;
  5. if `userHandle` is present, it must equal `store.get_handle(cred.user_id, cred.rp_id)`;
  6. `verify_authentication_response(expected_rp_id=state.rp_id, expected_origin=state.origin,
     credential_public_key=cred.public_key, credential_current_sign_count=cred.sign_count,
     require_user_verification=(setting == "required"))`.
     - 0/0 is accepted (E6, R8).
     - A regression is rejected **and logged at warning level** with the credential id in
       base64url; the credential stays usable (E7, Q4).
     - With UV required, a missing UV is rejected (E8);
  7. `update_usage(sign_count, backed_up)`;
  8. `user = await self._idp.user_from_id(cred.user_id)`;
  9. `_check_tenant(user, rp)`, where `rp = self._resolver.by_rp_id(state.rp_id)`;
  10. `return await self.open_session(request, user, extra={...})`.
     - `auth_method="passkey"`, `mfa=<UV>`, `amr=["hwk","user"]` (or `["hwk"]` without UV),
       `org_id`, `client_id` and `passkey_rp_id`.
     - The inactive-user `FailedAuth(403)` propagates (E9).
- Every verification failure is the same `InvalidAuth("Passkey: invalid credential", status=401)` (E4).
  Redis or DB errors after step 1 are wrapped in `AuthException` (R1).
- `_check_tenant`: when `auth_conf.PASSKEY_TENANT_ATTRIBUTE` is set **and** the user has that
  attribute, require it to equal `rp.org_id`; otherwise skip (Q-T). A mismatch is a uniform 401.
- Write `tests/test_passkey_signin.py`, the live integration tests listed below.

**NOT in scope**: management (TASK-96), the login-page JS (TASK-97), and any change to `auth.py` (AC14).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/passkey.py` | MODIFY | `login_options`, `authenticate`, `_check_tenant` |
| `tests/test_passkey_signin.py` | CREATE | Live sign-in and edge-case tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`, plus the files created by TASKS 87 to 94.

### Verified Imports
```python
import secrets, json                                     # stdlib
from ..exceptions import AuthException, InvalidAuth, UserNotFound   # exceptions.py:3, :42, :32
from ..responses import JSONResponse                     # responses.py:75
# py_webauthn via self._webauthn — names verified by TASK-86 (spec §6):
#   generate_authentication_options, verify_authentication_response, options_to_json,
#   helpers.base64url_to_bytes / bytes_to_base64url, helpers.structs.PublicKeyCredentialDescriptor,
#   helpers.structs.UserVerificationRequirement,
#   helpers.exceptions.InvalidAuthenticationResponse; result attrs new_sign_count,
#   credential_backed_up, user_verified (CONFIRM against TASK-86's block).
```

### Existing Signatures to Use
```python
class IdentityProvider:                                  # backends/idp/__init__.py:39
    async def user_from_id(self, uid: int) -> Identity   # :124 — raises UserNotFound
    async def get_user(self, login: str) -> Identity     # :146 — raises UserNotFound
class BasicAuth:
    async def open_session(self, request, user, extra=None, expiration=None) -> dict   # basic.py:171
    #   extra merged into userdata + AUTH_SESSION_OBJECT; _JWT_EXTRA_KEYS (after TASK-91) =
    #   ("auth_method","auth_origin","external_expires_at","mfa","amr") mirrored into the JWT;
    #   raises FailedAuth(403) for inactive users (TASK-91).
# TASK-93 helpers: get_payload, _pop_challenge, _save_challenge, _decoy_ids, self._resolver
#   (.resolve(request), .by_rp_id(rp_id)), self._store (TASK-88).
# auth.py — api_login (:470) → get_auth_backend by X-Auth-Method (:343) → _backend_auth (:386):
#   UserNotFound→401; InvalidAuth/Forbidden/FailedAuth → ForbiddenAccess(status=err.status).
#   Header-less fallback loop (:484-490) — must never see a non-Auth exception (R1).
# abac/context.py:28 _resolve_tenant reads userinfo["org_id"/"client_id"] (step 3) — fed by extra.
```

### Does NOT Exist
- A passkey-specific login route. Verification goes **only** through `POST /api/v1/login`.
- `IdentityProvider.get_credential` and friends. Use `self._store`.
- `org_id` on `models.User`. That is why the tenant check is optional.

---

## Implementation Blueprint

### Steps (in order)
1. `login_options`: implement the three branches. Response shape must be identical for known and
   unknown users. Compare in a test that the key sets match and that `allowCredentials` holds
   `PASSKEY_DECOY_CREDENTIALS` entries for unknown users.
2. `authenticate`: implement the steps strictly in order. Keep all failure raises inside one
   helper `_fail(reason_for_log)`: it logs the specific reason at info or warning level and raises
   the uniform 401. That way the response never varies (E4), but operators can still debug.
3. `_check_tenant`.
4. Write the live tests. Reuse `passkey_app` from TASK-94 and `soft_authenticator`. Enroll through
   the real endpoints first.

### `navigator_auth/backends/passkey.py` — MODIFY (replace the TASK-93 stubs)
```python
    def _fail(self, log_reason: str, *, warning: bool = False) -> InvalidAuth:
        """Log the specific reason, return the uniform 401 (E4)."""
        (self.logger.warning if warning else self.logger.info)(f"Passkey: {log_reason}")
        return InvalidAuth("Passkey: invalid credential", status=401)

    async def login_options(self, request: web.Request) -> web.Response:
        """Start a sign-in ceremony: username-first (default) or usernameless (C4, E5)."""
        rp = self._resolver.resolve(request)
        # FILL IN: optional JSON body → username (strip; empty ⇒ usernameless).
        # FILL IN: username-first — user lookup (UserNotFound/None ⇒ unknown, other errors ⇒
        #          AuthException), list_credentials(user_id, rp.rp_id); known+creds ⇒ allow=creds,
        #          expected_user_id; else allow=self._decoy_ids(rp, username), decoy=True.
        # FILL IN: options = generate_authentication_options(rp_id=rp.rp_id,
        #          allow_credentials=[descriptor...], user_verification=<setting>)
        challenge_id = secrets.token_urlsafe(32)
        # FILL IN: _save_challenge("login", challenge_id, ChallengeState(challenge=b64url(options.challenge),
        #          rp_id=rp.rp_id, origin=rp.origin, expected_user_id=..., decoy=...))
        # FILL IN: return JSONResponse({"challenge_id": challenge_id,
        #          "publicKey": json.loads(options_to_json(options))})
        raise NotImplementedError

    async def authenticate(self, request: web.Request) -> dict:
        """Verify a WebAuthn assertion, then open a Basic-style session (spec §2.5 steps 1–10)."""
        challenge_id, credential = await self.get_payload(request)          # 1 (no I/O)
        state = await self._pop_challenge("login", challenge_id)            # 2
        # FILL IN 3–5: raw_id = base64url_to_bytes(credential["rawId"]) (bad b64 ⇒ _fail);
        #   cred = await self._store.get_credential(raw_id); None or cred.rp_id != state.rp_id ⇒ _fail;
        #   state.expected_user_id and cred.user_id != it ⇒ _fail;
        #   userHandle present and != await self._store.get_handle(cred.user_id, cred.rp_id) ⇒ _fail.
        # FILL IN 6: verified = verify_authentication_response(...); InvalidAuthenticationResponse ⇒
        #   if it is a sign-count regression: _fail(..., warning=True) (E7, Q4 — credential untouched);
        #   else _fail. Wrap store/Redis errors in AuthException (R1).
        # FILL IN 7: await self._store.update_usage(cred.credential_id,
        #   sign_count=verified.new_sign_count, backed_up=verified.credential_backed_up)
        # FILL IN 8–9: user = await self._idp.user_from_id(cred.user_id) (UserNotFound ⇒ _fail);
        #   rp = self._resolver.by_rp_id(state.rp_id); self._check_tenant(user, rp)
        uv = False  # FILL IN: bool(verified.user_verified)
        extra = {
            "auth_method": "passkey",
            "mfa": uv,
            "amr": ["hwk", "user"] if uv else ["hwk"],
            # FILL IN: "org_id": rp.org_id, "client_id": rp.client_id, "passkey_rp_id": rp.rp_id
        }
        return await self.open_session(request, user, extra=extra)          # 10 (E9 propagates)

    def _check_tenant(self, user, rp: RelyingParty) -> None:
        """When PASSKEY_TENANT_ATTRIBUTE is set and present on user, require == rp.org_id (Q-T)."""
        attr = auth_conf.PASSKEY_TENANT_ATTRIBUTE
        if not attr:
            return
        # FILL IN: value via Mapping.get / getattr; missing ⇒ return; str(value) != str(rp.org_id)
        #          ⇒ raise self._fail(f"tenant mismatch for user {...}") — bounded by AC10.
```
**Why**:
- Popping the challenge before loading the credential makes every attempt consume it (E1).
- Checking `rp_id` on the stored credential against the challenge's RP is what stops cross-tenant
  replay (AC4).
- `open_session` is reused, never copied. It brings the JWT, `jti` recording, the refresh token,
  the callbacks, and the `is_active` rejection.

### `tests/test_passkey_signin.py` — CREATE (bodies are FILL IN; spec §4 names)
```python
"""FEAT-101 TASK-95 — passkey sign-in, live (Postgres + Redis)."""
import pytest

from tests.fixtures.passkey import passkey_app, passkey_rp_config, soft_authenticator  # noqa: F401

pytestmark = pytest.mark.asyncio(loop_scope="module")

# Each test: enroll via register/* (TASK-94), then login/options → make_assertion → POST /api/v1/login
async def test_login_usernameless_success(passkey_app, soft_authenticator): ...      # C4, AC6 (body + JWT mfa/amr/jti + cookie)
async def test_login_username_first_known(passkey_app, soft_authenticator): ...      # other user's credential → 401
async def test_login_username_first_unknown_shape(passkey_app, soft_authenticator): ...  # E5, AC7
async def test_challenge_replay(passkey_app, soft_authenticator): ...                # E1
async def test_challenge_expired(passkey_app, soft_authenticator, monkeypatch): ...  # E2 (TTL=1 + wait, or delete key)
async def test_origin_mismatch(passkey_app, soft_authenticator): ...                 # E3 (cdj origin; other rp_id)
async def test_unknown_credential_uniform_401(passkey_app, soft_authenticator): ...  # E4 (same body/status as bad sig)
async def test_sign_count_zero_accepted(passkey_app, soft_authenticator): ...        # E6
async def test_sign_count_regression_rejected_logged(passkey_app, soft_authenticator, caplog): ...  # E7, Q4
async def test_uv_required(passkey_app, soft_authenticator): ...                     # E8
async def test_inactive_user_rejected(passkey_app, soft_authenticator): ...          # E9 → 403
async def test_user_handle_mismatch(passkey_app, soft_authenticator): ...
async def test_tenant_attribute_check(passkey_app, soft_authenticator, monkeypatch): ...  # AC10
async def test_session_carries_tenant(passkey_app, soft_authenticator): ...          # AC10 + EvalContext
async def test_fallback_loop_unaffected(passkey_app): ...                            # E11: Basic login, no header
```

### FILL IN checklist
- [ ] `login_options` branches, identical response shape, and the timing-equalising lookup.
- [ ] `authenticate` steps 3 to 9, with uniform failures and R1 wrapping.
- [ ] Regression detection and the warning log (E7).
- [ ] `_check_tenant`.
- [ ] All 15 live tests.

---

## Acceptance Criteria

- [ ] AC4: a credential is never accepted for a different `rp_id`; verification uses the RP stored in the challenge.
- [ ] AC6: the login returns the `BasicAuth` body (including `refresh_token`), plus `auth_method="passkey"`, `mfa` and `amr`, and sets the session cookie. The JWT carries `auth_method`, `mfa`, `amr` and a recorded `jti`.
- [ ] AC7: username-first is the default; the response shape for unknown users matches known users; usernameless works.
- [ ] AC8: each of E1, E2, E4, E6, E7, E8, E9 and E11 has a passing test.
- [ ] AC10: the session carries the RP's `org_id`/`client_id`, and the optional tenant check rejects a mismatch with 401.
- [ ] `pytest tests/test_passkey_signin.py tests/test_basic_auth.py -v` passes. `auth.py` is unchanged (AC14).
- [ ] `ruff check navigator_auth/backends/passkey.py tests/test_passkey_signin.py` shows no new findings.

---

## Test Specification

See above (spec §4 Integration Tests).

---

## Agent Instructions

1. Read the spec (Module 5, §2.5, §2.6, R1, R4, R8) and TASK-86's verified py_webauthn block.
2. Confirm TASKS 93, 90 and 91 are in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
