# TASK-218: Use shared MFA evaluation for management context

**Feature**: FEAT-116 — MFA management and evaluation review fixes
**Spec**: `sdd/specs/handlers-mfa-tech-debt.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-217
**Assigned-to**: unassigned
**Discovered-from**: `issue:f46f232584fd`

## Context

User requested observations #13–#15. This task belongs to the seven-issue group selected by planner version 1; the issue is claimed by agent:sdd-fix:9cf36a7d. Verify stale descriptions against current code. Do not claim other issues.

## Scope

Replace duplicated _security_context logic with services.evaluate(record, conn=conn), adapting its return to the existing tuple. Map MFARefused to its existing fail-closed HTTP status/error shape. Preserve session-authenticated enrollment access for users entitled to enroll; test enforced-superuser without strong factor explicitly against the approved shared evaluation contract. Avoid nested connection acquisition.

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/mfa.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_review_fixes_management.py` | MODIFY | Scoped implementation or regression evidence |

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
      "path": "tests/test_mfa_review_fixes_management.py",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/handlers/mfa.py#_error",
    "sym:tests/test_mfa_review_fixes_management.py#test_backup_regeneration_requires_proof"
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

### `tests/test_mfa_review_fixes_management.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
async def test_backup_regeneration_requires_proof(env):
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

- `pytest tests/test_mfa_review_fixes_management.py -q`

## Completion Note

- Task: TASK-218
- Feature: handlers-mfa-tech-debt
- Implementation SHA: 8c72e6aa381da5e03852d21bb9bd67b561e267d7
- Closed at (UTC): 2026-11-11T23:05:01+00:00
- Fix commits: none

| Metric | Value |
|---|---|
| validation_refs | 1 |
| fix_commits | 0 |
| review | TASK-218-review.md |
| validation | Host executed tests; inspect TASK-218-host.log |
