# TASK-98: Passkey operator docs, changelog and final verification

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 9 docs, §7 R2, AC15, AC16)
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-96, TASK-97
**Assigned-to**: unassigned

---

## Context

This is the closing task. It ships the operator documentation that AC16 requires, completes the
changelog, and runs the feature-wide verification command from AC15.

---

## Scope

- Create `docs/passkey.rst`. It covers:
  - enabling the backend (`AUTHENTICATION_BACKENDS`, `pip install navigator-auth[passkey]`, Redis ≥ 6.2);
  - every `PASSKEY_*` setting with its default;
  - the `PASSKEY_RELYING_PARTIES` JSON format, with one entry per tenant site, exact origins, and
    the ALB note (R7);
  - the endpoint table from spec §2 "New Public Interfaces";
  - client JS for enrollment, which must send `X-CSRF-Token` from the `csrf_token` cookie for
    cookie sessions;
  - client JS for username-first and conditional-UI sign-in through `POST /api/v1/login` + `X-Auth-Method: PasskeyAuth`;
  - the session and JWT claims `auth_method`, `mfa` and `amr`;
  - the ABAC keys `auth_method` and `mfa`;
  - the optional `PASSKEY_TENANT_ATTRIBUTE`;
  - known limitations: no attestation verification, no Related Origin Requests, count-based decoy inference (R4).
- Add `passkey` to the `docs/index.rst` toctree after `token_exchange`.
- `CHANGELOG.md` "Unreleased": a FEAT-101 entry for the new backend, the optional extra, and the
  `is_active` behaviour change. The R2 note comes from TASK-91; extend it rather than duplicating it.
- Run the AC15 command and the existing suites, and record the results in the Completion Note.

**NOT in scope**: version bump. The release process owns that; the spec targets 0.29.0.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `docs/passkey.rst` | CREATE | Operator doc |
| `docs/index.rst` | MODIFY | Toctree entry |
| `CHANGELOG.md` | MODIFY | FEAT-101 entry |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Existing Signatures to Use
```rst
.. docs/index.rst — toctree (verified :34-50)
   settings
   token_exchange        ← insert `passkey` BELOW this line (occurrences of "   token_exchange": 1)
   password_recovery
```
- Style precedents: `docs/token_exchange.rst` (backend doc for FEAT-096) and `docs/password_recovery.rst`. Copy their heading structure.
- `CHANGELOG.md` starts with `# Unreleased`, followed by bullet entries. Add the entry at the top of that list.
- CSRF names: `CSRF_COOKIE_NAME="csrf_token"` and `CSRF_HEADER_NAME="X-CSRF-Token"` (`conf.py:103-104`).
  Bearer-authenticated requests skip CSRF (`middlewares/csrf.py:34-36`).

### Does NOT Exist
- `docs/passkey.rst`, or any passkey mention in the docs.
- A Markdown docs tree. The docs are Sphinx `.rst`.

---

## Implementation Blueprint

### Steps (in order)
1. Write `docs/passkey.rst`, using `token_exchange.rst` as the template. Take the setting names
   and defaults from `navigator_auth/conf.py` as implemented, not from memory.
2. Add the toctree line and the changelog entry.
3. Run the verification commands below, and paste the summary lines into the Completion Note.

### `docs/passkey.rst` — CREATE (outline)
```rst
Passkey (WebAuthn) Authentication
=================================

.. FILL IN each section from the implemented code (conf.py, backends/passkey.py):

Overview
--------
Installation
------------
Configuration
-------------
Relying parties (per tenant)
----------------------------
Endpoints
---------
Client integration
------------------
Enrollment (CSRF)
~~~~~~~~~~~~~~~~~
Sign-in (username-first and conditional UI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Session, JWT and ABAC
---------------------
Limitations
-----------
```

### `docs/index.rst` — MODIFY
```rst
.. AFTER `   token_exchange` (verified: docs/index.rst:40; occurrences: 1)
   passkey
```

### Verification commands
```bash
source .venv/bin/activate
pytest tests/test_passkey_*.py tests/test_basic_auth.py tests/test_basic_open_session.py \
       tests/test_token_exchange_backend.py tests/test_oauth2_upstream_idp.py \
       tests/test_oauth2_auth_login_inactive.py tests/test_eval_context_auth_method.py \
       tests/unit/test_user_is_active.py -v
ruff check navigator_auth/passkey navigator_auth/backends/passkey.py navigator_auth/backends/basic.py \
           navigator_auth/backends/abstract.py navigator_auth/abac/context.py navigator_auth/conf.py
git diff --stat origin/dev -- navigator_auth/auth.py   # must be empty (AC14)
```

### FILL IN checklist
- [ ] Doc sections written against the real implementation.
- [ ] Changelog entry.
- [ ] Verification results recorded.

---

## Acceptance Criteria

- [ ] AC16: `docs/passkey.rst` documents the `PASSKEY_*` settings, the RP map format, and the client JS, including the enrollment CSRF header.
- [ ] AC15: the pytest command above passes, and `ruff` shows no new findings on the touched files.
- [ ] AC14: `auth.py` is unmodified.
- [ ] The Sphinx build, if available (`make -C docs html`), shows no new warnings for `passkey.rst`.

---

## Test Specification

No new tests. This task runs the full feature verification above.

---

## Agent Instructions

1. Read the spec (§5 Acceptance Criteria, AC14 to AC16).
2. Confirm TASK-96 and TASK-97 are in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.
7. The feature is then ready for `/sdd-done FEAT-101`.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Verification output**:
**Deviations from spec**: none
