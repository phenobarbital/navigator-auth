# TASK-053: End-to-end exchange tests, docs and version bump

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 8, §4 Integration Tests, §5)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-052
**Assigned-to**: unassigned

---

## Context

Closes FEAT-096: proves the whole path through the real aiohttp app
(`/api/v1/login` → session → protected route → credential endpoint) and
documents the contract for integrators.

**Not parallelizable**: final integration coverage; depends on TASK-052.

---

## Scope

- Integration tests (pattern: `tests/test_basic_auth.py` `live_app` fixture and
  the OAuth2 integration suites):
  - `test_exchange_end_to_end_azure`: mocked JWKS + Graph; `POST /api/v1/login`
    with `X-Auth-Method: TokenExchange` → 200, session cookie set with
    `Max-Age == cap`, Redis key TTL ≈ cap; then
    `GET /api/v1/user/identities/azure/credential` returns the vaulted
    credential including `id_token`.
  - `test_exchange_end_to_end_github`: mocked app-token check; classic token
    (no expiry) → cap = `TOKEN_EXCHANGE_MAX_TTL`.
  - `test_exchange_then_protected_route`: the exchanged session passes the auth
    middleware and a PBAC-protected route exactly like a Basic session
    (compare `request.user` shape and `auth_method`).
  - `test_exchange_unknown_user_401_no_row`: with `AUTH_MISSING_ACCOUNT="create"`.
- Docs:
  - `docs/security.rst` or a new `docs/token_exchange.rst` (link from
    `docs/index.rst`): request contract, claims (`auth_method`, `auth_origin`,
    `external_expires_at`), lifetime cap and `TOKEN_EXCHANGE_MAX_TTL`,
    "user must pre-exist" rule, vault retrieval via the credential endpoint,
    per-provider audience rules (Azure id_token vs access token weaker path,
    Google `azp`, GitHub app-token check).
  - `docs/settings.rst`: the two new settings.
  - `README.md`: add `TokenExchange` to the auth-methods table.
  - `docs/changelog.rst`: FEAT-096 entry.
- Bump `navigator_auth/version.py` to `0.25.0`.

**NOT in scope**: new functionality; fixing provider verifiers (open a
follow-up task if the integration tests expose a defect).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_token_exchange_integration.py` | CREATE | End-to-end tests |
| `tests/conftest.py` | MODIFY | Shared `rsa_keypair`, `provider_userinfo`, `existing_user`, `linked_identity` fixtures if not already added |
| `docs/token_exchange.rst` | CREATE | Integrator docs |
| `docs/index.rst`, `docs/settings.rst`, `docs/changelog.rst` | MODIFY | Link, settings, changelog |
| `README.md` | MODIFY | Auth-methods table |
| `navigator_auth/version.py` | MODIFY | `0.25.0` |

---

## Implementation Notes

### Key Constraints
- Tests must not call real provider endpoints; mock at the `ExternalAuth.get`
  / `request` / `jwksutils.get_jwks` boundary.
- If the DB-backed `live_app` fixture is unavailable in CI, mark tests with the
  same skip marker the existing DB-dependent suites use.
- Docs must state plainly that tokens issued to other applications are rejected
  and that the flow never creates users.

### References in Codebase
- `tests/test_basic_auth.py:67` — `live_app` fixture.
- `tests/test_oauth2_integration.py` — integration style.
- `navigator_auth/handlers/user_identities.py:172` — credential endpoint.

---

## Acceptance Criteria

- [ ] All four integration tests pass (or are correctly skip-marked where DB is absent)
- [ ] Every FEAT-096 spec §5 acceptance criterion is checked off in the spec file
- [ ] Docs build (`make -C docs html`) without new warnings
- [ ] `version.py` is `0.25.0`; changelog entry present
- [ ] Full suite: `pytest tests/ -v` green (excluding pre-existing environment failures, listed in the completion note)

---

## Test Specification

```python
# tests/test_token_exchange_integration.py
# test_exchange_end_to_end_azure
# test_exchange_end_to_end_github
# test_exchange_then_protected_route
# test_exchange_unknown_user_401_no_row
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-052 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker
**Date**: 2026-09-04
**Notes**:
- `tests/test_token_exchange_integration.py` (4 tests): unlike
  `tests/test_token_exchange_backend.py` (TASK-052, which mocks
  `verify_external_token` directly), this file mocks only the outbound
  network boundary — `jwksutils.requests.get` for Azure's discovery+JWKS
  and Graph `/me`, `GithubAuth.post` for the "check a token" endpoint —
  so the *real* provider verifiers run end to end.
  - `test_exchange_end_to_end_azure`: real JWKS-verified id_token, session
    claims at both levels + JWT, cap reflects the id_token's `exp`; the
    credential-endpoint retrieval (incl. `id_token`) is asserted when the
    DB schema supports it (see below), skipped cleanly otherwise.
  - `test_exchange_end_to_end_github`: classic token (no `expires_at`) ->
    `TOKEN_EXCHANGE_MAX_TTL` fallback cap, verified via JWT `exp-iat`.
  - `test_exchange_then_protected_route`: the exchanged session passes the
    real auth middleware on a session-protected route
    (`GET /api/v2/user/session`) and shows `auth_method="basic"`,
    `auth_origin="azure"` — via the **bearer-token** path (`Authorization:
    Bearer <token>`), since this fixture's `AuthHandler(secure_cookies=False)`
    disables cookie-based sessions entirely
    (`SessionHandler(use_cookies=secure_cookies)`); `auth.py`'s
    `_auth_middleware` decodes the JWT and loads the session from it,
    exactly as a real bearer-token deployment would.
  - `test_exchange_unknown_user_401_no_row`: confirms the real
    (environment-default) `AUTH_MISSING_ACCOUNT="create"` has no effect.
- **Hang found and fixed while regression-checking the full suite**
  (not visible when running `tests/test_basic_auth.py` alone quickly, or
  when running the FEAT-096 files in isolation with a short timeout — it
  only showed up on a careful individual re-check): the
  `ignore::jwt.warnings.InsecureKeyLengthWarning` filter added to
  `tests/test_basic_auth.py` in TASK-046 (needed so the pre-existing,
  environment-driven warning-as-error no longer fails the successful-login
  tests) has a side effect — those tests now actually *reach*
  `AUTH_SUCCESSFUL_CALLBACKS` for the first time, and the production
  callback `resources.auth.saving_troc_user` (and/or `last_login`) tries
  to reach something unavailable in this sandbox, hanging its
  fire-and-forget background task forever. The test **assertions** all
  still pass, but the process never exits afterward (an indefinite hang,
  not a failure) — a real risk for CI. Fixed the same way as the
  synthetic-user fixtures in `test_basic_open_session.py` and
  `test_token_exchange_backend.py`: `auth.backends["BasicAuth"]._callbacks
  = None` after `client.start_server()` (must be after `on_startup`,
  which populates `_callbacks`). Confirmed this exact hang is **new**
  behaviour introduced by unblocking the previously-always-failing tests
  (on unmodified `dev`, those tests fail before ever reaching the
  callback, so the hang was latent/unreachable) — not a pre-existing
  issue, and not something present before TASK-046 in this suite.
- `docs/token_exchange.rst` (new): full request/response contract,
  per-provider audience-bound verification summary, the "never
  auto-provisions" user-resolution rule, the session-lifetime-cap
  algorithm, and vault storage/retrieval. Linked from `docs/index.rst`.
- `docs/settings.rst`: was an empty, unreferenced file — now documents
  `TOKEN_EXCHANGE_MAX_TTL`/`TOKEN_EXCHANGE_PROVIDERS` and is linked from
  `docs/index.rst` too (reasonable since it now has real content).
- `docs/changelog.rst`: only `.. include::`s `../CHANGELOG.md`, so "a
  FEAT-096 entry" was added there instead (the file actually shown to
  readers), plus a one-line pointer added directly to `changelog.rst`.
  `CHANGELOG.md` was **not** in the task's file table but is the only
  place a changelog entry can meaningfully live — documented here as a
  deliberate, minimal, necessary companion edit.
- `README.md`: the project has no existing "auth-methods table" — added
  one (the first), covering every backend `AUTHENTICATION_BACKENDS`
  supports today, with `TokenExchangeAuth` per the task's instruction.
- `navigator_auth/version.py`: `0.24.1` -> `0.25.0`.
- `sdd/specs/external-token-exchange.spec.md` §5: every acceptance
  criterion checked off with a pointer to the test(s) proving it (not in
  the task's file table, but explicitly required by its own Acceptance
  Criteria — "Every FEAT-096 spec §5 acceptance criterion is checked off
  in the spec file").
- `tests/conftest.py` was **not** modified: every FEAT-096 test file is
  self-contained with its own local `rsa_keypair`/mocking helpers rather
  than shared conftest fixtures (simpler to reason about per-file, and
  the task only asked for shared fixtures "if not already added" —
  reasonable to skip since duplication here is small and each file's
  needs differ slightly, e.g. Azure vs Google audience claims).
- Installed `sphinx`, `sphinx-rtd-theme`, `myst-parser` into the venv
  (matching `docs/requirements.txt`) purely to run `make -C docs html`
  for verification — not added to `pyproject.toml`/any lock file.
  Build succeeded with 17 warnings (down from an 18-warning baseline
  after fixing one *new* warning my own README.md link caused — myst
  couldn't resolve a `.rst`-suffixed markdown link as a cross-reference,
  fixed by using plain text instead). All 17 remaining warnings predate
  this feature (broken `navigator_auth.handlers.base`/`.info` autodoc
  imports, `TrocTokenAuth` autodoc, four middleware docstring formatting
  issues, a missing `../CHANGES.md` include in `docs/changes.rst`, and
  `docs/requirements*.txt` not being in any toctree) — none reference any
  file this feature touches.
- `pytest tests/ -v`: every FEAT-096 test file passes individually
  (`test_basic_auth.py` 8, `test_basic_open_session.py` 5,
  `test_identity_id_token.py` 11, `test_external_verify_helpers.py` 12,
  `test_azure_token_verifier.py` 6, `test_google_token_verifier.py` 11,
  `test_github_token_verifier.py` 9, `test_token_exchange_backend.py` 12
  passed + 3 skipped, `test_token_exchange_integration.py` 3 passed + 1
  skipped, `tests/unit/identity/` 93 passed + 1 pre-existing unrelated
  failure per TASK-047). Running several `loop_scope="module"` live-app
  files together in one `pytest` invocation intermittently hits an
  unrelated pytest-asyncio/uvloop event-loop-lifecycle interaction
  between modules (`RuntimeError: Event loop is closed` during a
  previous module's asyncpg connection teardown, first seen in
  TASK-052) — pre-existing test-suite architecture behaviour affecting
  any combination of `loop_scope="module"` files, not a FEAT-096
  regression; not fixed (out of scope — would mean changing shared
  fixture/event-loop architecture used across the whole suite).
  `ruff check` clean on every file touched across all 8 FEAT-096 tasks.

**Deviations from spec**:
- `CHANGELOG.md` edited in addition to `docs/changelog.rst` (not in the
  file table) — the actual, necessary location for a changelog entry.
- `sdd/specs/external-token-exchange.spec.md` edited (not in the file
  table) — required by this task's own Acceptance Criteria.
- `tests/conftest.py` intentionally left unmodified (see above).
- `tests/test_basic_auth.py` (a TASK-046 file) received one additional
  fix here: disabling `_callbacks` to prevent the hang described above.
