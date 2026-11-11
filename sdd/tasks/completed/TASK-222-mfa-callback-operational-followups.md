# TASK-222: Finish MFA callback and operational review followups

**Feature**: FEAT-116 — MFA management and evaluation review fixes
**Spec**: `sdd/specs/handlers-mfa-tech-debt.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-221
**Assigned-to**: unassigned
**Discovered-from**: `issue:607e5356c449`

## Context

User requested observations #13–#15. This task belongs to the seven-issue group selected by planner version 1; the issue is claimed by agent:sdd-fix:9cf36a7d. Verify stale descriptions against current code. Do not claim other issues.

## Scope

Audit every subfinding in the claimed issue body against current code, recording already-fixed evidence. Offload synchronous notification callbacks with asyncio.to_thread (I/O only); await returned awaitables on the event loop, preserve exception containment and cancellation. Test event-loop progress and timeout with a blocked callback and release it during cleanup. Keep async callbacks on-loop. Document that timed-out sync work may finish later. Complete MfaChallengeStore docstrings and type hints. Invalidate backup codes in the same transaction on self-disenrollment. Verify Redis command requirements against current store (Lua still calls GETDEL; KEEPTTL is also used); document actual minimum and perform non-destructive startup capability/version validation, failing closed with unavailable services. Document per-user budget exhaustion tradeoff. Strengthen schema readiness probes for required columns/indexes, with missing-schema tests. Reconcile stale AC5 docs/test regex. Consolidate duplicated _field helpers only within the listed MFA files using an existing compatible helper after checking None/default semantics. For session issuance under transaction locks, verify present compensation and add fault-injected commit-failure coverage; implement safe cleanup or transactional ordering that prevents usable orphan credentials, preserving policy-race protection and single-use challenges. If safe resolution needs new design decisions or unlisted files, report the exact limitation rather than closing this bundled issue partially.

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/notify.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/store.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/services.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/migrations.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/login.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/state.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/totp.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/email_otp.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/mfa/security.py` | MODIFY | Scoped implementation or regression evidence |
| `navigator_auth/handlers/mfa.py` | MODIFY | Scoped implementation or regression evidence |
| `docs/two_factor_auth.rst` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_email_provider.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_migrations.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_review_fixes_gate.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_review_fixes_docs.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_review_fixes_management.py` | MODIFY | Scoped implementation or regression evidence |
| `tests/test_mfa_challenge_store.py` | MODIFY | Scoped implementation or regression evidence |

| `tests/test_mfa_verify.py` | MODIFY | Existing login test doubles or narrow AC5 documentation correction |
| `tests/test_mfa_basic_auth_hook.py` | MODIFY | Existing login test doubles or narrow AC5 documentation correction |
| `sdd/specs/basicauth-otp-2fa.spec.md` | MODIFY | Existing login test doubles or narrow AC5 documentation correction |

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
      "path": "navigator_auth/mfa/notify.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/store.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/services.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/migrations.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/login.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/state.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/totp.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/email_otp.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/mfa/security.py",
      "action": "MODIFY"
    },
    {
      "path": "navigator_auth/handlers/mfa.py",
      "action": "MODIFY"
    },
    {
      "path": "docs/two_factor_auth.rst",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_email_provider.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_migrations.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_review_fixes_gate.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_review_fixes_docs.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_review_fixes_management.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_challenge_store.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_verify.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_basic_auth_hook.py",
      "action": "MODIFY"
    },
    {
      "path": "sdd/specs/basicauth-otp-2fa.spec.md",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/notify.py#invoke_callback",
    "sym:navigator_auth/mfa/store.py#_hash_token",
    "sym:navigator_auth/mfa/services.py#MfaServices",
    "sym:navigator_auth/mfa/migrations.py#render_sql",
    "sym:navigator_auth/mfa/login.py#LoginChallenge",
    "sym:navigator_auth/mfa/state.py#_field",
    "sym:navigator_auth/mfa/totp.py#mfa_seed_context",
    "sym:navigator_auth/mfa/email_otp.py#hash_code",
    "sym:navigator_auth/mfa/security.py#_canonical_bytes",
    "sym:navigator_auth/handlers/mfa.py#_error",
    "sym:tests/test_mfa_email_provider.py#capture",
    "sym:tests/test_mfa_migrations.py#_FakeConn",
    "sym:tests/test_mfa_review_fixes_gate.py#_record",
    "sym:tests/test_mfa_review_fixes_docs.py#_normalized",
    "sym:tests/test_mfa_review_fixes_management.py#test_backup_regeneration_requires_proof",
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

### `navigator_auth/mfa/notify.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
async def invoke_callback(path: Optional[str], payload: MfaModel, *, label: str) -> bool:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/store.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _hash_token(token: str) -> str:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/services.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class MfaServices:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/migrations.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def render_sql(sql: str) -> str:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/login.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class LoginChallenge:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/state.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _field(user: Any, name: str, default: Any = None) -> Any:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/totp.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def mfa_seed_context(user_id: int, provider: str = PROVIDER_TOTP, key: str = TOTP_VAULT_KEY) -> VaultContext:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/email_otp.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def hash_code(code: str, secret: bytes) -> str:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/mfa/security.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _canonical_bytes(fields: dict) -> bytes:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `navigator_auth/handlers/mfa.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _error(code: str, status: int, **extra: Any) -> web.Response:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `docs/two_factor_auth.rst` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
Two-factor authentication for BasicAuth
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_email_provider.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def capture(payload):
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_migrations.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
class _FakeConn:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_review_fixes_gate.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _record(**over) -> MfaChallenge:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_review_fixes_docs.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
def _normalized(path: Path) -> str:
```
Inspect the complete surrounding implementation before editing; apply only the scope above. Preserve unrelated behavior.

### `tests/test_mfa_review_fixes_management.py` (MODIFY)

Verified anchor (1 exact-line occurrence):
```text
async def test_backup_regeneration_requires_proof(env):
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

- `pytest tests/test_mfa_email_provider.py -q`
- `pytest tests/test_mfa_migrations.py -q`
- `pytest tests/test_mfa_review_fixes_gate.py -q`
- `pytest tests/test_mfa_review_fixes_docs.py -q`
- `pytest tests/test_mfa_review_fixes_management.py -q`
- `pytest tests/test_mfa_challenge_store.py -q`

### Contract amendment during implementation

The commit-before-session boundary requires updating existing security doubles in test_mfa_verify.py and test_mfa_basic_auth_hook.py. Run both files as regressions. Correct only the stale AC5 session-call grep in the original FEAT-106 spec, as explicitly covered by issue:607e5356c449.

- `pytest tests/test_mfa_verify.py tests/test_mfa_basic_auth_hook.py -q`

## Completion Note

- Task: TASK-222
- Feature: handlers-mfa-tech-debt
- Implementation SHA: 66f5ae85fd9d16243f584d2b9bbf1c4c1ca6123b
- Closed at (UTC): 2026-11-11T23:48:21+00:00
- Fix commits: none

| Metric | Value |
|---|---|
| validation_refs | 1 |
| fix_commits | 0 |
| review | TASK-222-review.md |
| validation | Host executed tests; inspect TASK-222-host.log |
