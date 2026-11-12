# TASK-219: Return accurate TOTP attempt budgets and bind enrollment context

**Feature**: FEAT-116 — MFA management and evaluation review fixes
**Spec**: `sdd/specs/handlers-mfa-tech-debt.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-218
**Assigned-to**: unassigned
**Discovered-from**: `issue:7778420320ec`

## Context

User requested observations #13–#15. This task belongs to the seven-issue group selected by planner version 1; the issue is claimed by agent:sdd-fix:9cf36a7d. Verify stale descriptions against current code. Do not claim other issues.

## Scope

Persist EnrollmentAuthorization.context_digest in signed PendingEnrollment fields. Pass current digest from handler confirmation and compare before installing a seed; stale or legacy context-less pending enrollments must be rejected. Preserve bool confirm_enrollment compatibility using a separate detailed-result method or typed exception carrying failure budget; never return a truthy failed result to bool callers. Propagate the exact atomic register_enrollment_failure result to attempts_remaining, including exhausted budget 0 and absent enrollment distinction. Never store outcome on shared provider mutable state. Test first failure 4 of 5, exhaustion, replay, session/user mismatch, context drift and valid confirmation. Update all affected existing test doubles explicitly.

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/mfa.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/totp.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/store.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/types.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_enrollment_security.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_challenge_store.py` | MODIFY | Scoped implementation or regression evidence |

## Codebase Contract (Anti-Hallucination)

Verified files and anchors are reproduced below from the current checkout. Use imports already present in each module; asyncio.to_thread is standard library and is allowed for blocking I/O callbacks. Reverify signatures after dependencies land. The spec section 6 lists the existing public contracts. Do not introduce new third-party dependencies.

### Does NOT Exist

- No request-local factor snapshot or detailed enrollment result API exists before this feature.
- No synchronous callback timeout can interrupt code running inline on the event loop.

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {
      "path": "navigator_auth/handlers/mfa.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/totp.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/store.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/types.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_enrollment_security.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_challenge_store.py",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/handlers/mfa.py#_error",
    "sym:navigator_auth/mfa/totp.py#mfa_seed_context",
    "sym:navigator_auth/mfa/store.py#_hash_token",
    "sym:navigator_auth/mfa/types.py#MfaModel",
    "sym:tests/test_mfa_enrollment_security.py#Record",
    "sym:tests/test_mfa_challenge_store.py#test_canonical_json_is_stable"
  ]
}
```

## Implementation Blueprint

1. Read the claimed issue body and spec acceptance criteria; compare them to current code to avoid reimplementing already-fixed findings.
2. Reverify the anchors below and consumed APIs after dependencies land. Keep changes inside the declared scope.
3. Implement the precise behavior described in Scope, preserving public contracts and fail-closed semantics. For the enrollment API, prefer a separate detailed method while retaining the bool wrapper.
4. Extend the listed tests to exercise real behavior and failure paths, then run the validation commands. Record service prerequisites and actual results.
5. Commit implementation and finalize this task with exact-HEAD evidence using parrot sdd task finalize; never mark it complete with untested or partially resolved scope.

### `navigator_auth/handlers/mfa.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _error(code: str, status: int, **extra: Any) -> web.Response:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/totp.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def mfa_seed_context(user_id: int, provider: str = PROVIDER_TOTP, key: str = TOTP_VAULT_KEY) -> VaultContext:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/store.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _hash_token(token: str) -> str:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/types.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class MfaModel(BaseModel):
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_enrollment_security.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class Record(dict):
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_challenge_store.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def test_canonical_json_is_stable():
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### Completion checklist

- [ ] Scoped behavior implemented and no unfinished code placeholders remain.
- [ ] Imports and callers verified, tests executed, results retained under artifacts/logs.
- [ ] All issue subfindings resolved or reported explicitly unresolved.

## Acceptance Criteria

- Scope behavior is implemented with no weakening of MFA authorization/refusal or token/session binding.
- Regression tests cover the relevant success and failure paths and pass against the worktree source.
- Any pre-existing fix used as resolution has reproducible code and test evidence.

## Validation Commands

- `pytest tests/test_mfa_enrollment_security.py -q`
- `pytest tests/test_mfa_challenge_store.py -q`

## Completion Note

- Task: TASK-219
- Feature: handlers-mfa-tech-debt
- Implementation SHA: b60c40afb96c12cd33145bd295afbffc874d216d
- Closed at (UTC): 2026-11-11T23:10:29+00:00
- Fix commits: none

| Metric | Value |
|---|---|
| validation_refs | 1 |
| fix_commits | 0 |
| review | TASK-219-review.md |
| validation | Host executed tests; inspect TASK-219-host.log |
