# TASK-147: End-to-end integration tests (spec §4 Integration table) + acceptance sweep

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-140, TASK-141, TASK-142, TASK-143, TASK-144, TASK-145, TASK-146
**Assigned-to**: unassigned

---

## Context

Every earlier task proves its own module with unit tests. This task proves the **assembled feature**
over HTTP, against a real `AuthHandler` + `BasicAuth` app on **live Redis and Postgres**, and closes
spec **AC2** ("all integration tests in §4 pass") plus the repository-wide checks no single module
can own: AC3 (no regression on existing login paths), AC4 (no new runtime dependency), AC5 (refined
by D5), AC14 (no secret in logs) and AC20 (2FA off ⇒ unchanged login path). It ends with a
traceability table mapping **every** spec AC (AC1–AC34) to the test(s) that prove it, so `/sdd-done`
can verify the feature mechanically.

This task writes **tests only**. If a test exposes a bug, fix it in the owning module only when the
fix is small and obviously within that module's contract; otherwise record it in the Completion Note
and stop — never weaken an assertion to make it pass.

---

## Scope

- Create `tests/test_mfa_e2e.py` implementing all 15 rows of spec §4 **Integration Tests**:
  1. `test_login_email_otp_end_to_end`
  2. `test_login_totp_end_to_end`
  3. `test_enforce_tenant_no_lockout`
  4. `test_totp_enrolment_closes_email_path`
  5. `test_remember_me_skips_otp_not_password`
  6. `test_password_change_revokes_trusted_devices`
  7. `test_recovery_completion_revokes_trusted_devices`
  8. `test_tenant_hardening_revokes_devices_relaxing_does_not`
  9. `test_abac_policy_can_require_fresh_factor`
  10. `test_cross_tenant_isolation`
  11. `test_pending_challenge_invalid_after_recovery`
  12. `test_email_challenge_invalid_after_totp_confirmation`
  13. `test_verify_security_transition_races`
  14. `test_mfa_verify_finalizes_session`
  15. `test_superuser_last_factor_recovery`
- Add the sweep tests: `test_2fa_disabled_login_unchanged` (AC20), `test_no_session_minting_reference_in_mfa_package`
  (AC5/D5), `test_no_forbidden_runtime_dependency` (AC4 belt-and-braces), `test_no_secret_in_logs` (AC14),
  `test_api_login_backend_loop_and_explicit_backend_same_envelope` (AC32 over HTTP),
  `test_redis_outage_refuses_verification` (AC12 over HTTP).
- Write the AC1–AC34 traceability table into this task's Completion Note when done (template below).

**NOT in scope**:
- New production features or refactors. Small in-contract bug fixes only (see Context).
- Re-testing unit behaviour already owned by TASK-129..TASK-146 beyond what an end-to-end path needs.
- Browser/WebAuthn ceremonies: `webauthn` is not installed (spec §6). Passkey rows are inserted directly
  into `auth.user_credentials` where a test needs a "registered passkey".

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_mfa_e2e.py` | CREATE | live end-to-end suite + AC sweep |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11). Every `navigator_auth.mfa.*` / `handlers.mfa` symbol is
> from TASK-129..TASK-146 (contract §3) — verify each with `grep -n` before writing the test that uses it.

### Verified Imports

```python
import asyncio
import logging
import re
import tomllib                                   # stdlib (Python 3.11 venv)
import warnings
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import navigator_auth.conf as conf               # AUTHENTICATION_BACKENDS override (tests/test_basic_open_session.py:66-69)
from navigator_auth import AuthHandler           # verified tests/test_basic_open_session.py:71
from navigator_auth.handlers.users.passwd import set_basic_password   # verified passwd.py:12
from navigator_auth.mfa.services import MFA_APP_KEY, get_mfa_services  # TASK-138
from navigator_auth.mfa.policy import apply_tenant_policy              # TASK-135
from navigator_auth.mfa.types import MfaMode, TRUSTED_COOKIE           # TASK-129
from navigator_auth.mfa.store import CHALLENGE_KEY_PREFIX              # TASK-131
from tests.fixtures.mfa import (  # noqa: F401                          # TASK-130
    frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, otp_callback_spy,
)
```

### Live app pattern (verified `tests/test_basic_open_session.py:58-126`)

```python
original_backends = conf.AUTHENTICATION_BACKENDS
conf.AUTHENTICATION_BACKENDS = ("navigator_auth.backends.BasicAuth",)
app = web.Application()
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    auth = AuthHandler(secure_cookies=False)
    auth.setup(app)
backend = auth.backends["BasicAuth"]          # backends are keyed by class name (auth.py:240-250)
...
conf.AUTHENTICATION_BACKENDS = original_backends   # restore in teardown
```

### Settings imported by value — patch every importer

`AUTH_BASIC_2FA_ENABLED`, `AUTH_OTP_SECRET`, `AUTH_OTP_EMAIL_CALLBACK`, `AUTH_MFA_NOTIFY_CALLBACK` are module
constants copied at import time (`from navigator_auth.conf import X`). Patching `navigator_auth.conf.X`
alone does nothing for modules that already imported it. Before `auth.setup(app)`, list importers with
`grep -rn "AUTH_BASIC_2FA_ENABLED\|AUTH_OTP_SECRET\|AUTH_OTP_EMAIL_CALLBACK\|AUTH_MFA_NOTIFY_CALLBACK" navigator_auth/`
and `monkeypatch.setattr(<module>, "<NAME>", value)` on each (at least `navigator_auth.conf`,
`navigator_auth.backends.basic`, `navigator_auth.handlers` / `handlers.mfa`, `navigator_auth.mfa.services`).
The e-mail callback is a dotted path: point it at a module-level function in this test file
(`"tests.test_mfa_e2e._capture_otp"`) that appends the `OtpNotificationPayload` to a list.

### Live data (verified 2026-11-11)

- `auth.users`: only `username` lacks a default among NOT NULL columns; `user_id bigint`.
- `auth.organizations(org_id bigserial, organization NOT NULL, org_slug NOT NULL, …)`;
  `auth.organization_users(user_id, org_id)` PK `(user_id, org_id)`, both FKs `ON DELETE CASCADE`.
- `auth.user_credentials` exists only after `ensure_passkey_tables(pool)` (`passkey/migrations.py:43`).
- `auth.user_vault_secrets` exists (vault); the vault KeyRing comes from `setup_vault_keyring(app)`
  (`vault/integration.py:29`, run inside `auth_startup` at `auth.py:188`) and needs `VAULT_MASTER_KEY_v{N}` /
  `VAULT_ACTIVE_KEY_ID` in the environment — skip TOTP tests cleanly when `app.get("vault_keyring")` is None.

### ABAC facts for row 9 (verified `navigator_auth/abac/context.py:82-147`)

`EvalContext` exposes first-class `auth_method` and `mfa` keys (`:137-141`) but **no first-class `amr`**;
`amr` reaches policies only inside `ctx["userinfo"]` (the session's `AUTH_SESSION_OBJECT`, into which
`open_session` merges `extra`, `basic.py:215-219`). See row 9 below.

### Does NOT Exist (Anti-Hallucination)

- ~~fakeredis~~ (not installed, must not be added) — use live Redis; `broken_redis_pool` style for outages.
- ~~a password-reset-by-email that auto-logs in~~ — recovery never returns a token (D15 of FEAT-098, `handler.py:325`).
- ~~a first-class `amr` key in `EvalContext`~~ — see row 9.
- ~~a "logout everywhere" endpoint~~ — D22.
- ~~`webauthn`~~ in this environment — no passkey ceremonies.

---

## Implementation Blueprint

### `tests/test_mfa_e2e.py` — CREATE (four blocks; one file)

**Block 1 — module header, skips, app fixture.**
```python
"""FEAT-106 TASK-147 — end-to-end 2FA over HTTP on live Redis + Postgres (spec §4 Integration)."""
import asyncio
import logging
import re
import tomllib
import warnings
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import navigator_auth.conf as conf
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, otp_callback_spy,
)

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
]
CAPTURED: list = []


def _capture_otp(payload) -> None:
    """AUTH_OTP_EMAIL_CALLBACK target: keep the payload, never print it."""
    CAPTURED.append(payload)


@pytest_asyncio.fixture
async def mfa_app(monkeypatch, mfa_db, mfa_redis_pool, mfa_secret):
    """Real AuthHandler(BasicAuth) with AUTH_BASIC_2FA_ENABLED patched on everywhere."""
    # FILL IN: patch the settings on every importer (see Codebase Contract), override
    #   conf.AUTHENTICATION_BACKENDS, build app + AuthHandler(secure_cookies=False).setup(app),
    #   start TestServer/TestClient (on_startup runs → MfaServices built), assert
    #   get_mfa_services(app).available, yield SimpleNamespace(client, app, auth, backend);
    #   teardown: close client, restore backends, CAPTURED.clear(). Skip when Postgres/Redis unreachable.
```

**Block 2 — helpers (users, orgs, policy, login, verify).**
```python
async def _login(client, username: str, password: str, cookies: dict | None = None):
    """POST /api/v1/login (JSON); returns (status, body)."""
    # FILL IN: client.post("/api/v1/login", json={"username": ..., "password": ...}, cookies=cookies)
    #   (BasicAuth.get_payload reads JSON keys username_attribute/pwd_atrribute — basic.py:139-146).

async def _verify(client, challenge: str, provider: str, code: str, remember: bool = False):
    """POST /auth/mfa/verify; returns the aiohttp response (body + Set-Cookie)."""
    # FILL IN — body shape per TASK-140: {"challenge", "provider", "code", "remember_device"?}.

# FILL IN fixtures/helpers:
#  - `tenant(mfa_db)`: create an organization + membership rows; teardown deletes the org (cascade).
#  - `set_policy(app, org_id, mode, remember_days)`: await apply_tenant_policy(db_pool=…, security=…,
#      trusted_devices=…, org_id=…, mode=…, remember_days=…, actor="e2e") using the app's services.
#  - `user_with_password(mfa_user_factory, plain)`: a user whose auth.users.password =
#      set_basic_password(plain) (set via UPDATE if the factory does not).
#  - `enrol_totp(client, session_headers, password)`: enroll → confirm with a code from
#      TOTPProvider.match_step-compatible generation (cryptography TOTP over the returned secret_b32,
#      frozen_totp_clock) → returns (secret, backup_codes).
#  - `insert_passkey(mfa_db, user_id)`: ensure_passkey_tables + INSERT a minimal user_credentials row.
```

**Block 3 — the 15 integration rows** (one `@pytest.mark.asyncio` test each; FILL IN bodies,
assertions are fixed):
```python
# 1  test_login_email_otp_end_to_end — enforced tenant, ordinary user, no TOTP: login ⇒ 401
#    {"mfa_required": True, "challenge", "providers": ["email"], "preferred": "email", "expires_in"},
#    no "token"/"refresh_token"/"session_id" keys, no session cookie (AC6); CAPTURED has one payload
#    whose repr hides the code; verify(provider="email", code=payload.code) ⇒ 200 with token; decoded
#    JWT has mfa=True and amr == ["pwd", "otp"] (D11, AC1/AC2).
# 2  test_login_totp_end_to_end — enrol + confirm, logout, login ⇒ 401 preferred "totp", providers
#    without "email"; verify with a fresh TOTP code ⇒ 200, amr == ["pwd", "totp"].
# 3  test_enforce_tenant_no_lockout — preflight-eligible tenant (ordinary users with e-mail, a superuser
#    WITH a passkey row or TOTP): run the pre-flight (TASK-146 main(["--org-id", N]) == 0), set ENFORCED,
#    every ordinary user completes login via e-mail; the superuser is offered no "email" (AC8).
# 4  test_totp_enrolment_closes_email_path — after confirmation, verify(provider="email") on a new
#    challenge is refused (401) even with a valid-looking code, and "email" ∉ providers (AC9).
# 5  test_remember_me_skips_otp_not_password — TOTP user, remember_days=30: verify(remember=True) sets
#    TRUSTED_COOKIE (HttpOnly, Secure, SameSite=Lax); second login with the cookie + right password ⇒
#    200 without challenge, amr == ["pwd", "trusted_device"], mfa=True (AC17, AC19), and a NEW cookie
#    value (rotation); same cookie + WRONG password ⇒ 401/403 (never skips the password); replaying the
#    first cookie ⇒ family revoked, next login challenged (R8).
# 6  test_password_change_revokes_trusted_devices — POST /api/v2/user/set_password, then the cookie
#    no longer skips the OTP (AC18).
# 7  test_recovery_completion_revokes_trusted_devices — drive the FEAT-098 three-step flow
#    (/api/v1/password-recovery → token from the recovery callback → /confirm); the cookie no longer
#    skips the OTP (AC18).
# 8  test_tenant_hardening_revokes_devices_relaxing_does_not — OPTIONAL→ENFORCED revokes the cookie;
#    issue a new one; ENFORCED→OPTIONAL keeps it working (AC18, D18); both changes leave audit rows (AC23).
# 9  test_abac_policy_can_require_fresh_factor — trusted-device session: EvalContext built for that
#    session has ctx["mfa"] is True, "trusted_device" in ctx["userinfo"]["amr"], and neither "otp" nor
#    "totp" in it; a policy requiring a fresh factor (FILL IN: if the PDP's declarative conditions can
#    read userinfo.amr, declare it in YAML; otherwise express it as the documented Python check over
#    ctx["userinfo"]["amr"]) denies it while an OTP-verified session is allowed. Record in the
#    Completion Note which form was possible (EvalContext has no first-class `amr`).
# 10 test_cross_tenant_isolation — user in tenant A (OFF) is not challenged although tenant B is
#    ENFORCED; X-Org-Id / X-Client-Id headers naming B change nothing (AC22, R14); a TOTP seed enrolled
#    for user U does not verify for user V (AAD binding) (AC25 side).
# 11 test_pending_challenge_invalid_after_recovery — obtain an e-mail challenge + code, complete password
#    recovery, then verify with the OLD challenge + valid code ⇒ 401 stale, no session (AC30).
# 12 test_email_challenge_invalid_after_totp_confirmation — e-mail challenge issued, user confirms TOTP
#    in another session, verify(old challenge, email code) ⇒ 401 (AC30).
# 13 test_verify_security_transition_races — asyncio.gather(verify(valid), recovery confirm): either the
#    verify succeeded and its session/jti is revoked afterwards, or it failed; never a usable session
#    issued after recovery committed (AC30, AC31). Repeat 10× to shake ordering.
# 14 test_mfa_verify_finalizes_session — successful verify: session cookie set, session readable via
#    GET /api/v1/user/session with the token, Redis has auth:refresh_token:<rt>; failed verify creates
#    neither (AC32 finalize side).
# 15 test_superuser_last_factor_recovery — enforced superuser with TOTP only: DELETE /auth/mfa/totp ⇒ 409;
#    admin disenrol (ABAC allowed via the real mfa_admin_access pack + an actor in security_admin) ⇒ the
#    superuser's BasicAuth login ⇒ 403 strong_factor_required (no challenge, no e-mail); after the audited
#    operator procedure (remove is_superuser, log in via e-mail, enrol TOTP, restore is_superuser) login
#    works with TOTP (AC33).
```

**Block 4 — sweep tests.**
```python
# test_2fa_disabled_login_unchanged — app built with AUTH_BASIC_2FA_ENABLED False: MFA_APP_KEY ∉ app,
#   no route under /auth/mfa, login ⇒ 200 with the same key set as a baseline captured from the same
#   flow on this branch with the flag off, no TRUSTED_COOKIE (AC20).
# test_no_session_minting_reference_in_mfa_package — walk navigator_auth/mfa/**/*.py and *.sql; assert no
#   match of re.compile(r"remember\(|create_token|open_session") (AC5 refined by D5).
# test_no_forbidden_runtime_dependency — tomllib-parse pyproject.toml [project].dependencies; none of
#   pyotp, qrcode, aiosmtplib, twilio, sendgrid, fakeredis (AC4; the authoritative check is the git
#   diff command in Test Specification).
# test_no_secret_in_logs — caplog.set_level(logging.DEBUG) across flows 1, 2 and 5; assert caplog.text
#   contains none of: the e-mail code, the challenge token, secret_b32, the enrollment token, any backup
#   code, either trusted-device cookie value (AC14).
# test_api_login_backend_loop_and_explicit_backend_same_envelope — login once without and once with
#   X-Auth-Method: BasicAuth ⇒ both 401 with identical key sets, no session (AC32, R2).
# test_redis_outage_refuses_verification — swap the services' store pool for an unreachable pool after
#   issuing a challenge ⇒ verify ⇒ refusal (401/503), no session (AC12).
```

### Steps (in order)

1. Confirm all dependencies are in `sdd/tasks/completed/`; read `handlers/mfa.py` for the exact request/response
   shapes and route names, and `tests/fixtures/mfa.py` for fixture names.
2. Build `mfa_app` (Block 1) and make a trivial test pass: login with 2FA on, tenant OFF ⇒ 200.
3. Implement rows 1, 2, 14 first (they exercise the whole happy path), then 4, 5, 10, then the
   invalidation rows 6, 7, 8, 11, 12, then 3, 9, 13, 15.
4. Add the sweep tests.
5. Run the Test Specification block. Then fill the traceability table in the Completion Note.

### FILL IN checklist

- [ ] `mfa_app` fixture (settings patched on every importer, skip when stores unreachable)
- [ ] helpers: tenant, set_policy, user_with_password, enrol_totp, insert_passkey, _login, _verify
- [ ] rows 1–15
- [ ] six sweep tests
- [ ] AC traceability table in the Completion Note

---

## Acceptance Criteria

- [ ] **AC-1** All 15 spec §4 Integration rows exist under their exact spec names in `tests/test_mfa_e2e.py` and pass on live Redis + Postgres; they skip (not fail) when either store is unreachable.
- [ ] **AC-2** The six sweep tests pass.
- [ ] **AC-3** `pytest tests/test_mfa_*.py -v` passes (spec AC1) and the AC3 regression command passes unchanged.
- [ ] **AC-4** `git diff dev -- pyproject.toml` shows no change to `[project].dependencies` (spec AC4).
- [ ] **AC-5** The refined AC5 grep prints nothing (D5).
- [ ] **AC-6** The Completion Note contains the AC1–AC34 traceability table with every row resolved to at least one passing test (or an explicit, justified gap).
- Spec ACs closed: **AC1**, **AC2**, **AC3**, **AC4**, **AC5**, **AC12**, **AC14**, **AC20**; end-to-end evidence for AC6–AC11, AC13, AC15–AC19, AC22–AC33.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_e2e.py -v
pytest tests/test_mfa_*.py -v                                                    # spec AC1
pytest tests/test_basic_auth.py tests/test_passkey_signin.py tests/test_eval_context_auth_method.py -v   # spec AC3
git diff dev -- pyproject.toml                                                   # spec AC4: no dependency change
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1   # spec AC5 (D5)
ruff check tests/test_mfa_e2e.py
```

### AC traceability template (copy into the Completion Note and fill the last column)

Locate each test with `grep -rn "def <name>" tests/`. Owning task per contract §0.

| Spec AC | Proven by (test → owning task) | Status |
|---|---|---|
| AC1 | `pytest tests/test_mfa_*.py` (all MFA unit suites) | |
| AC2 | rows 1–15 of `tests/test_mfa_e2e.py` (147) | |
| AC3 | regression command above (147) | |
| AC4 | `git diff` command + `test_no_forbidden_runtime_dependency` (147) | |
| AC5 | refined grep + `test_no_session_minting_reference_in_mfa_package` (147) | |
| AC6 | `test_mfa_required_payload_has_no_token` (138), `test_api_login_mfa_required_creates_no_session` (139), row 1 | |
| AC7 | `test_api_login_mfa_required_does_not_try_next_backend` (139) | |
| AC8 | `test_enforced_floor_is_email_without_enrolment` (135), row 3 | |
| AC9 | `test_strong_factor_closes_email`, `test_registered_passkey_closes_email` (135), row 4 | |
| AC10 | `test_passkey_signin_never_challenged` (138/139) | |
| AC11 | `test_token_exchange_never_challenged` (138/139) | |
| AC12 | `test_strict_limiter_fails_closed` (131), `test_redis_outage_refuses_verification` (147) | |
| AC13 | `test_totp_accepts_skew_window`, `test_totp_rejects_outside_window`, `test_totp_replay_rejected` (136) | |
| AC14 | `test_notification_payload_repr_redacted` (137), `test_mfa_models_frozen_and_redacted` (129), `test_no_secret_in_logs` (147) | |
| AC15 | `test_preflight_blocks_users_without_email`, `test_preflight_blocks_superuser_without_strong_factor` (146) | |
| AC16 | `test_admin_disenroll_requires_mfa_action`, `test_admin_disenroll_changes_nothing_but_otp` (142) | |
| AC17 | `test_trusted_device_not_offered_to_email_state` (133/138), row 5 | |
| AC18 | rows 6, 7, 8; `test_admin_disenroll_revokes_trusted_devices` (142); TOTP enrol/disenrol (141) | |
| AC19 | row 5 | |
| AC20 | `test_2fa_disabled_login_unchanged` (147) | |
| AC21 | docs build / review of `docs/two_factor_auth.rst` (148) | |
| AC22 | `test_policy_read_is_per_login_not_cached`, `test_resolver_ignores_tenant_headers` (135), row 10 | |
| AC23 | `test_factor_transitions_write_durable_audit` (141/142/135), transition tests (144) | |
| AC24 | `test_missing_mfa_tables_refuse_login` (130/138) | |
| AC25 | `test_totp_seed_read_without_session` (136), row 10 | |
| AC26 | `test_admin_disenroll_rejects_foreign_tenant` (142) | |
| AC27 | `test_deleting_last_passkey_reopens_email` (135/144) | |
| AC28 | `test_vault_rejects_mfa_namespace` (143) | |
| AC29 | `test_totp_enrollment_requires_fresh_auth`, `test_totp_pending_seed_isolated` (136/141) | |
| AC30 | `test_stale_challenge_rejected` (140), rows 11, 12, 13 | |
| AC31 | `test_challenge_retry_budget`, `test_concurrent_verify_consumes_once`, `test_expiry_during_verification` (131/140) | |
| AC32 | `test_explicit_backend_mfa_response` (139), row 14, `test_api_login_backend_loop_and_explicit_backend_same_envelope` | |
| AC33 | `test_enforced_superuser_requires_strong_factor_at_login` (138/140), row 15, `test_disenroll_superuser_last_factor_refused` (141) | |
| AC34 | `test_mfa_models_frozen_and_redacted` (129) | |

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §4 (both tables), §5 (all ACs), §3 "Security contracts".
2. **Check dependencies** — TASK-140..TASK-146 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint; never weaken an assertion — record real gaps instead.
5. **Verify** every acceptance criterion; fill the traceability table.
6. **Move this file** to `sdd/tasks/completed/TASK-147-mfa-integration-tests.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done — include the filled AC traceability table)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
