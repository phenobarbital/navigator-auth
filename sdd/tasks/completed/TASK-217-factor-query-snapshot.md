# TASK-217: Read MFA factor facts once per evaluation

**Feature**: FEAT-116 — MFA management and evaluation review fixes
**Spec**: `sdd/specs/handlers-mfa-tech-debt.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:313bd68c8049`

## Context

User requested observations #13–#15. This task belongs to the seven-issue group selected by planner version 1; the issue is claimed by agent:sdd-fix:9cf36a7d. Verify stale descriptions against current code. Do not claim other issues.

## Scope

Introduce request-local factor facts (typed Pydantic model or explicit typed arguments) and reuse them through state_of, has_strong_factor and available_providers. Preserve existing public calls by optional keyword-only facts or a shared state evaluation helper. Fetch TOTP once; probe/count passkeys at most once when needed; backup count once. Do not cache across requests. Preserve enforced-superuser refusal and email eligibility. Add query-count and policy-matrix tests, including fresh facts on the next call.

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/state.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/services.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_policy_state.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_review_fixes_services.py` | MODIFY | Scoped implementation or regression evidence |

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
      "path": "navigator_auth/mfa/state.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/services.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_policy_state.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_review_fixes_services.py",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/state.py#_field",
    "sym:navigator_auth/mfa/services.py#MfaServices",
    "sym:tests/test_mfa_policy_state.py#_ScriptedConn",
    "sym:tests/test_mfa_review_fixes_services.py#_Redis"
  ]
}
```

## Implementation Blueprint

1. Read the claimed issue body and spec acceptance criteria; compare them to current code to avoid reimplementing already-fixed findings.
2. Reverify the anchors below and consumed APIs after dependencies land. Keep changes inside the declared scope.
3. Implement the precise behavior described in Scope, preserving public contracts and fail-closed semantics. For the enrollment API, prefer a separate detailed method while retaining the bool wrapper.
4. Extend the listed tests to exercise real behavior and failure paths, then run the validation commands. Record service prerequisites and actual results.
5. Commit implementation and finalize this task with exact-HEAD evidence using parrot sdd task finalize; never mark it complete with untested or partially resolved scope.

### `navigator_auth/mfa/state.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _field(user: Any, name: str, default: Any = None) -> Any:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/services.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class MfaServices:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_policy_state.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class _ScriptedConn:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_review_fixes_services.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class _Redis:
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

- `pytest tests/test_mfa_policy_state.py -q`
- `pytest tests/test_mfa_review_fixes_services.py -q`

## Completion Note

- Task: TASK-217
- Feature: handlers-mfa-tech-debt
- Implementation SHA: e46bb19efd999590b98d86508cc489a62463899c
- Closed at (UTC): 2026-11-11T23:01:13+00:00
- Fix commits: none

| Metric | Value |
|---|---|
| validation_refs | 1 |
| fix_commits | 0 |
| review | TASK-217-review.md |
| validation | Host executed tests; inspect TASK-217-host.log |
