---
type: feature
base_branch: dev
projects: [mfa]
tags: [mfa, security, performance, ledger-fix]
docs:
  policy: none
  pages: []
e2e:
  policy: optional
  scenario_ids: []
---

# Feature Specification: MFA management and evaluation review fixes

**Feature ID**: FEAT-116
**Date**: 2026-11-11
**Status**: approved
**Authorization**: User requested sdd-fix for observations #13–#15; scope is planner group fixgroup:38f0b189795c.
**Parent**: FEAT-106 (complete)
**Actor**: agent:sdd-fix:9cf36a7d

## 1. Motivation and scope

Fix incorrect TOTP attempts_remaining, repeated factor queries and blocking sync callbacks, plus the related issues grouped by planner version 1. Preserve authentication/refusal semantics, transaction safety, per-request freshness and the user-confirmed policy that self-service password changes preserve sessions. No unrelated ledger issues are included.

All seven issues were successfully claimed. Some descriptions are stale: enrollment tests now exist and several storage failures already map to 503. Require current-code evidence and regression tests, not duplicate implementation. The bundled operational issue must not be closed if any subfinding lacks resolution/evidence.

## 2. Architecture

Reuse one connection and request-local factor facts through MfaServices evaluation. Management context delegates to the same evaluator. Signed pending enrollments bind the current context digest; confirmation communicates the atomic attempt budget without breaking existing bool callers. Management proof checks use the existing fixed-window limiters before secrets are checked. Sync I/O callbacks run in the executor while async callbacks remain on the event loop. No cross-request factor cache or new dependency.

## 3. Module Breakdown and Interface Contracts

### TASK-217: Read MFA factor facts once per evaluation

**Discovered-from**: `issue:313bd68c8049`

Introduce request-local factor facts (typed Pydantic model or explicit typed arguments) and reuse them through state_of, has_strong_factor and available_providers. Preserve existing public calls by optional keyword-only facts or a shared state evaluation helper. Fetch TOTP once; probe/count passkeys at most once when needed; backup count once. Do not cache across requests. Preserve enforced-superuser refusal and email eligibility. Add query-count and policy-matrix tests, including fresh facts on the next call.

Files: `navigator_auth/mfa/state.py`, `navigator_auth/mfa/services.py`, `tests/test_mfa_policy_state.py`, `tests/test_mfa_review_fixes_services.py`.

### TASK-218: Use shared MFA evaluation for management context

**Discovered-from**: `issue:f46f232584fd`

Replace duplicated _security_context logic with services.evaluate(record, conn=conn), adapting its return to the existing tuple. Map MFARefused to its existing fail-closed HTTP status/error shape. Preserve session-authenticated enrollment access for users entitled to enroll; test enforced-superuser without strong factor explicitly against the approved shared evaluation contract. Avoid nested connection acquisition.

Files: `navigator_auth/handlers/mfa.py`, `tests/test_mfa_review_fixes_management.py`.

### TASK-219: Return accurate TOTP attempt budgets and bind enrollment context

**Discovered-from**: `issue:7778420320ec`

Persist EnrollmentAuthorization.context_digest in signed PendingEnrollment fields. Pass current digest from handler confirmation and compare before installing a seed; stale or legacy context-less pending enrollments must be rejected. Preserve bool confirm_enrollment compatibility using a separate detailed-result method or typed exception carrying failure budget; never return a truthy failed result to bool callers. Propagate the exact atomic register_enrollment_failure result to attempts_remaining, including exhausted budget 0 and absent enrollment distinction. Never store outcome on shared provider mutable state. Test first failure 4 of 5, exhaustion, replay, session/user mismatch, context drift and valid confirmation. Update all affected existing test doubles explicitly.

Files: `navigator_auth/handlers/mfa.py`, `navigator_auth/mfa/totp.py`, `navigator_auth/mfa/store.py`, `navigator_auth/mfa/types.py`, `tests/test_mfa_enrollment_security.py`, `tests/test_mfa_challenge_store.py`.

### TASK-220: Rate-limit session-authenticated MFA management proofs

**Discovered-from**: `issue:ad8553389bda`

Apply existing user_limiter using mgmt:<uid> and ip_limiter before every password or factor proof in enroll_totp, disenroll_totp and backup_codes. Share the management namespace across these routes. Refusal returns 429 rate_limited and performs no password check, proof consumption or state mutation. Retain confirm enrollment's separate limiter. Test user and IP refusal, wrong password/proof consuming budget, and allowed paths. Do not change limiter parsing (separate unclaimed issue).

Files: `navigator_auth/handlers/mfa.py`, `tests/test_mfa_review_fixes_management.py`, `tests/test_mfa_enrollment_security.py`.

### TASK-221: Return 503 for MFA management storage outages

**Discovered-from**: `issue:6537c3016b67`

Inspect current catches first: some paths already catch MfaStorageError. Ensure disenroll_totp and backup_codes consistently return 503 mfa_unavailable for dependency failures, including pre-proof reads, proof consumption, transaction body and commit. Preserve explicit HTTP refusals. Add fault-injection regressions proving no successful envelope or partial committed credential state. Do not hide programmer errors with an indiscriminate success fallback.

Files: `navigator_auth/handlers/mfa.py`, `tests/test_mfa_review_fixes_management.py`.

### TASK-222: Finish MFA callback and operational review followups

**Discovered-from**: `issue:607e5356c449`

Audit every subfinding in the claimed issue body against current code, recording already-fixed evidence. Offload synchronous notification callbacks with asyncio.to_thread (I/O only); await returned awaitables on the event loop, preserve exception containment and cancellation. Test event-loop progress and timeout with a blocked callback and release it during cleanup. Keep async callbacks on-loop. Document that timed-out sync work may finish later. Complete MfaChallengeStore docstrings and type hints. Invalidate backup codes in the same transaction on self-disenrollment. Verify Redis command requirements against current store (Lua replaced GETDEL; KEEPTTL still used); document actual minimum and perform non-destructive startup capability/version validation, failing closed with unavailable services. Document per-user budget exhaustion tradeoff. Strengthen schema readiness probes for required columns/indexes, with missing-schema tests. Reconcile stale AC5 docs/test regex. Consolidate duplicated _field helpers only within the listed MFA files using an existing compatible helper after checking None/default semantics. For session issuance under transaction locks, verify present compensation and add fault-injected commit-failure coverage; implement safe cleanup or transactional ordering that prevents usable orphan credentials, preserving policy-race protection and single-use challenges. If safe resolution needs new design decisions or unlisted files, report the exact limitation rather than closing this bundled issue partially.

Files: `navigator_auth/mfa/notify.py`, `navigator_auth/mfa/store.py`, `navigator_auth/mfa/services.py`, `navigator_auth/mfa/migrations.py`, `navigator_auth/mfa/login.py`, `navigator_auth/mfa/state.py`, `navigator_auth/mfa/totp.py`, `navigator_auth/mfa/email_otp.py`, `navigator_auth/mfa/security.py`, `navigator_auth/handlers/mfa.py`, `docs/two_factor_auth.rst`, `tests/test_mfa_email_provider.py`, `tests/test_mfa_migrations.py`, `tests/test_mfa_review_fixes_gate.py`, `tests/test_mfa_review_fixes_docs.py`, `tests/test_mfa_review_fixes_management.py`, `tests/test_mfa_challenge_store.py`.

### TASK-223: Complete enrollment security regression evidence

**Discovered-from**: `issue:64aa9130a1e1`

The current file already has the previously missing named tests. Verify their behavior against real Postgres/Redis and extend meaningful gaps revealed by the preceding tasks. Cover fresh password and existing strong-factor proof, isolated pending seed, single-use confirmation, stale email challenge after confirmation and durable audit. Add explicit context-drift and accurate-budget assertions if preceding tasks do not fully cover them. Do not replace live integration tests with tautologies or mark skipped service-dependent runs as passed.

Files: `tests/test_mfa_enrollment_security.py`.

## 4. Test Specification

Use the existing live MFA fixtures for enrollment and transaction behavior. Unit query-count tests must call the real evaluator/state code and count actual DB-boundary calls. Callback tests must demonstrate another coroutine progresses while sync delivery is blocked. Fault injection covers transaction commit, limiter refusal and unavailable stores.

### Validation Contract

tests:
  - tests/test_mfa_policy_state.py
  - tests/test_mfa_review_fixes_services.py
  - tests/test_mfa_review_fixes_management.py
  - tests/test_mfa_enrollment_security.py
  - tests/test_mfa_challenge_store.py
  - tests/test_mfa_email_provider.py
  - tests/test_mfa_migrations.py
  - tests/test_mfa_review_fixes_gate.py
  - tests/test_mfa_review_fixes_docs.py
markers: none

## 5. Acceptance Criteria

- AC1: Failed TOTP confirmation reports exact remaining attempts; exhaustion and absent tokens differ.
- AC2: Enrollment context drift cannot install a seed; signed context is checked alongside user/session/version.
- AC3: Factor reads are reused per evaluation without weakening the policy matrix or caching across requests.
- AC4: Management endpoints rate-limit before proof/password checks and map storage outages to 503.
- AC5: Sync callbacks cannot block the event loop; async callback/error/timeout behavior remains supported.
- AC6: Store methods have docstrings and complete type hints; actual Redis prerequisites are documented and checked.
- AC7: Every subfinding in issue:607e5356c449 has concrete resolution or is explicitly reported unresolved; never falsely close the bundle.
- AC8: The five previously missing enrollment scenarios run meaningfully; existing implemented coverage is retained.

## 6. Codebase Contract

Verified current definitions: MfaServices.evaluate(user, *, conn=None), _evaluate(user, conn); MfaStateMachine.state_of/has_strong_factor/available_providers; MfaHandler._security_context returns policy/state/strong/digest; TOTPProvider.confirm_enrollment(..., *, conn=None) returns bool; MfaChallengeStore.register_enrollment_failure(token) returns int; PendingEnrollment currently omits context_digest. StrictRateLimiter.check(key) returns bool; BackupCodeStore.invalidate_all(user_id, *, conn=None) exists. invoke_callback(path, payload, *, label) supports sync/async callbacks. No factor snapshot or detailed confirmation-result API exists yet.

## 7. Risks and Worktree Strategy

Create feat-FEAT-116-handlers-mfa-tech-debt via parrot sdd worktree ensure. Implement tasks in dependency order; serialize overlapping handler/store writers. Tests use the main shared venv with worktree PYTHONPATH. Live service unavailability is a validation blocker, never a pass. Existing migrations and callback return conventions require compatibility tests. Keep logs in artifacts/logs. No application changes on dev.

