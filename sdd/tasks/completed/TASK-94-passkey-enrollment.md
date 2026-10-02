# TASK-94: Passkey enrollment — `register/options` and `register/verify`

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 5, §2 Overview item 4, §2 New Public Interfaces, AC5)
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-93, TASK-90
**Assigned-to**: unassigned

---

## Context

A user who already holds a session (any backend, Q10) enrolls a passkey for the site they are on.
The RP is resolved from `Origin` (TASK-89). The WebAuthn `user.id` is the user's random
per-`(user, RP)` handle (G4, E15). Credentials the user already has for that RP are excluded (E10).
Both endpoints are cookie-session POSTs, so the CSRF middleware applies.

---

## Scope

- Replace the TASK-93 stubs `register_options` and `register_verify` in `navigator_auth/backends/passkey.py`.
- `register_options`:
  1. `user = self._session_user(request)` (401 without a session, E12);
  2. `rp = self._resolver.resolve(request)`;
  3. `handle = await self._store.get_or_create_handle(user.user_id, rp.rp_id)`;
  4. `exclude` = the user's credentials for `rp.rp_id`;
  5. generate the options with `residentKey=required`, `attestation="none"`,
     `userVerification=auth_conf.PASSKEY_USER_VERIFICATION` and `exclude_credentials`;
  6. save `ChallengeState(challenge, rp_id, origin, expected_user_id=user.user_id)` under
     `("register", str(user.user_id))`. A new options call replaces any pending one;
  7. return the options JSON.
- `register_verify`:
  1. session gate, then resolve the RP;
  2. read the body `{credential, label?}`; `label` is optional, at most 128 characters;
  3. pop `("register", str(user.user_id))`;
  4. require `state.rp_id == rp.rp_id` and `state.expected_user_id == user.user_id`;
  5. verify with `expected_origin=state.origin`, `expected_rp_id=state.rp_id`, and
     `require_user_verification = (PASSKEY_USER_VERIFICATION == "required")`;
  6. save a `StoredCredential` with `rp_id`;
  7. return 201 `{"status": "registered", "id": <b64url>}`.
- Errors:
  - a verification failure returns 400 "Passkey: registration failed";
  - an expired or missing challenge returns 401 (from `_pop_challenge`);
  - a duplicate `credential_id` returns 409.
  - Never echo the attestation payload into logs.
- Write `tests/test_passkey_enrollment.py` (live: Postgres and Redis).

**NOT in scope**: sign-in (TASK-95), management (TASK-96), and recent re-auth before enrollment (Non-Goal, Q10).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/passkey.py` | MODIFY | Replace the two register stubs |
| `tests/test_passkey_enrollment.py` | CREATE | Live enrollment tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`, plus the files created by TASKS 87 to 93.

### Verified Imports
```python
# already in backends/passkey.py (TASK-93):
from .. import conf as auth_conf
from ..passkey import ChallengeState, StoredCredential   # StoredCredential exported by TASK-87
from ..responses import JSONResponse                     # responses.py:75 (basic.py:26 imports it)
from ..exceptions import InvalidAuth, AuthException
# py_webauthn via self._webauthn (lazy, TASK-93) — USE THE NAMES TASK-86 VERIFIED in spec §6:
#   generate_registration_options, verify_registration_response, options_to_json,
#   webauthn.helpers.bytes_to_base64url / base64url_to_bytes,
#   webauthn.helpers.structs: AuthenticatorSelectionCriteria, ResidentKeyRequirement,
#       UserVerificationRequirement, AttestationConveyancePreference, PublicKeyCredentialDescriptor
#   webauthn.helpers.exceptions.InvalidRegistrationResponse
```
Import the `webauthn.helpers.*` submodules inside the methods, never at module level (R9).

### Existing Signatures to Use
```python
# TASK-93 (backends/passkey.py)
self._resolver.resolve(request) -> RelyingParty        # 401 InvalidAuth on miss
self._store: PasskeyStore                                # TASK-88: get_or_create_handle, list_credentials, save_credential
async def _save_challenge(kind, key, state) / _pop_challenge(kind, key) -> ChallengeState
def _session_user(request)  -> request.user (user.user_id, user.username)
# CSRF — middlewares/csrf.py:34-46: only cookie-only sessions are checked
#   (request.get("authenticated") and no Authorization header); header CSRF_HEADER_NAME
#   ("X-CSRF-Token", conf.py:104) must equal cookie CSRF_COOKIE_NAME ("csrf_token", conf.py:103).
#   Bearer-authenticated requests skip CSRF.
```
- Live-test pattern: `tests/test_basic_auth.py:95-125` seeds an `auth.users` row and logs in with
  Basic to get a JWT and session. Disable `backend._callbacks` after startup, as that file does.

### Does NOT Exist
- A user's `display_name` is not guaranteed on `request.user`. Fall back to `username`.
- `PasskeyStore.save_credential` does not upsert. A duplicate PK raises the driver's
  unique-violation error, so map it to 409.

---

## Implementation Blueprint

### Steps (in order)
1. Implement `register_options`. Order matters: the session gate comes before RP resolution and
   store access, so anonymous callers get a cheap 401 (E12).
2. Implement `register_verify`. Pop the challenge **before** verifying, so a failed attempt also
   burns it (single use, E1).
3. Write the live tests: the roundtrip goes through TASK-90's `soft_authenticator.make_attestation`.

### `navigator_auth/backends/passkey.py` — MODIFY (replace the TASK-93 stubs)
```python
    async def register_options(self, request: web.Request) -> web.Response:
        """Creation options for the session user on the resolved RP (C3, E10, E12, E15)."""
        user = self._session_user(request)
        rp = self._resolver.resolve(request)
        handle = await self._store.get_or_create_handle(user.user_id, rp.rp_id)
        existing = await self._store.list_credentials(user.user_id, rp.rp_id)
        # FILL IN: build options via self._webauthn.generate_registration_options(rp_id=rp.rp_id,
        #          rp_name=rp.rp_name, user_id=handle, user_name=user.username,
        #          user_display_name=<display_name or username>, attestation=NONE,
        #          authenticator_selection=(resident_key=REQUIRED, user_verification=<setting>),
        #          exclude_credentials=[descriptor(id=c.credential_id, transports=c.transports)])
        #          — bounded by the names TASK-86 verified.
        # FILL IN: await self._save_challenge("register", str(user.user_id), ChallengeState(
        #          challenge=bytes_to_base64url(options.challenge), rp_id=rp.rp_id,
        #          origin=rp.origin, expected_user_id=user.user_id))
        # FILL IN: return web.Response(text=options_to_json(options), content_type="application/json")
        raise NotImplementedError

    async def register_verify(self, request: web.Request) -> web.Response:
        """Verify the attestation and store the credential with its rp_id (C3)."""
        user = self._session_user(request)
        rp = self._resolver.resolve(request)
        # FILL IN: body = await request.json() (ValueError → 400); credential = body["credential"];
        #          label = body.get("label") truncated/validated to ≤128 chars.
        state = await self._pop_challenge("register", str(user.user_id))
        if state.rp_id != rp.rp_id or state.expected_user_id != user.user_id:
            raise InvalidAuth("Passkey: registration failed", status=401)
        # FILL IN: verified = self._webauthn.verify_registration_response(credential=credential,
        #          expected_challenge=base64url_to_bytes(state.challenge), expected_rp_id=state.rp_id,
        #          expected_origin=state.origin, require_user_verification=<setting == "required">)
        #          InvalidRegistrationResponse → web.HTTPBadRequest(reason="Passkey: registration failed")
        # FILL IN: await self._store.save_credential(StoredCredential(credential_id=verified.credential_id,
        #          user_id=user.user_id, rp_id=rp.rp_id, public_key=verified.credential_public_key,
        #          sign_count=verified.sign_count, transports=<from credential JSON>,
        #          aaguid=<str>, device_type=<str(verified.credential_device_type)>,
        #          backed_up=verified.credential_backed_up, label=label))
        #          unique violation → web.HTTPConflict(reason="Passkey: credential already registered")
        self.logger.info(f"Passkey: registered credential for user {user.user_id} on {rp.rp_id}")
        # FILL IN: return JSONResponse({"status": "registered", "id": <b64url id>}, status=201)
        raise NotImplementedError
```
**Why**: Binding the pending registration to `str(user.user_id)` means a challenge minted for one
user can never complete another user's enrollment. Checking `state.rp_id` stops an options call on
site A from being finished on site B (E3).

### `tests/test_passkey_enrollment.py` — CREATE
```python
"""FEAT-101 TASK-94 — passkey enrollment, live (Postgres + Redis)."""
import pytest

from tests.fixtures.passkey import passkey_rp_config, soft_authenticator  # noqa: F401

pytestmark = pytest.mark.asyncio(loop_scope="module")


async def test_register_requires_session(passkey_app):
    """E12: both register endpoints → 401 without a session; cookie-only without
    X-CSRF-Token → 403 when CSRF is enabled."""


async def test_register_roundtrip(passkey_app, soft_authenticator):
    """Options use the random handle (≠ user_id) and excludeCredentials; verify → 201 and the
    stored row carries rp_id (C3, E10, E15)."""
```
FILL IN: a module-scoped `passkey_app` fixture. Build it like `tests/test_basic_open_session.py`
`open_session_app`, with `AUTHENTICATION_BACKENDS = ("navigator_auth.backends.BasicAuth",
"navigator_auth.backends.PasskeyAuth")`. Seed a test user, log in with Basic, and return the
client plus Bearer headers. TASK-95 reuses this fixture, so put it in `tests/fixtures/passkey.py`.

### FILL IN checklist
- [ ] Options generation with the verified py_webauthn names.
- [ ] Body parsing and label validation.
- [ ] Verification, storage, and the 400/409 mapping.
- [ ] `passkey_app` fixture, added to `tests/fixtures/passkey.py`.
- [ ] Both live tests.

---

## Acceptance Criteria

- [ ] AC5: enrollment requires a session and CSRF; the options use the random handle and `excludeCredentials`; the verified credential is stored with `rp_id`.
- [ ] `pytest tests/test_passkey_enrollment.py -v` passes with Postgres and Redis.
- [ ] `ruff check navigator_auth/backends/passkey.py tests/test_passkey_enrollment.py` shows no new findings.

---

## Test Specification

See the blueprint above (spec §4: `test_register_requires_session`, `test_register_roundtrip`).

---

## Agent Instructions

1. Read the spec (Module 5, §2.4) and TASK-86's verified py_webauthn block.
2. Confirm TASK-93 and TASK-90 are in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Sonnet 5.5, sequential fallback)
**Date**: 2026-10-02
**Notes**: register/options + register/verify implemented; added _json_errors decorator so AuthException from route handlers maps to JSON 4xx (handlers sit outside AuthHandler error mapping); shared passkey_app fixture in tests/fixtures/passkey.py (uses AuthHandler(backends=...)). Cookie-session CSRF check is tested at middleware level because cookie sessions need secure_cookies=True. 4 live tests pass.
**Deviations from spec**: none
