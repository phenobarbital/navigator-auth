# TASK-195: 3LO example pins Oauth2Provider and warns on a short secret key

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1 S6 / G1, §3 Module 1, AC1–AC2. `examples/oauth2_3lo_server.py` builds
`AuthHandler(enable_authdb=False)` without `backends=` / `authz_backends=`. Because
`navigator_auth.conf` star-imports `settings.settings` last, the developer's local settings
decide the backend list (Azure, ADFS, TrocToken, NoAuth, APIKeyAuth all ran in the report)
and the `allow_hosts` authorization backend lets requests through without a session.
The JWT key came from `env/.env` (6 bytes); the example cannot override it, so it warns.

This task also creates `tests/test_oauth2_3lo_example.py` with the example loader that
TASK-206 (app-level 3LO test) extends.

---

## Scope

- Replace the `AUTHENTICATION_BACKENDS` `setdefault` block with a module-level `_BACKENDS`
  list plus the explanatory comment (pattern: `examples/identity_vault_server.py:108-119`).
- Construct `AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False)` in
  `make_app()`, with the `authz_backends=[]` comment (pattern: `identity_vault_server.py:715-722`).
- Add `_warn_on_short_secret()`: log ONE warning naming `AUTH_SECRET_KEY` when
  `navigator_auth.conf.SECRET_KEY` is shorter than 32 bytes; call it from `make_app()`.
- Create `tests/test_oauth2_3lo_example.py` with `_load_example()` and the M1 unit tests.

**NOT in scope**: `examples/README.md` (TASK-207); the app-level flow tests (TASK-206);
`examples/oauth2_server.py` (TASK-196); changing `env/.env`, `settings/settings.py` or
`navigator_auth/conf.py` precedence (spec Non-Goals).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `examples/oauth2_3lo_server.py` | MODIFY | `_BACKENDS`, pinned `AuthHandler`, `_warn_on_short_secret()` |
| `tests/test_oauth2_3lo_example.py` | CREATE | `_load_example()` + wiring / short-secret tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` (2026-11-11). FEAT-106 does not touch these files.

### Verified Imports
```python
from navigator_auth import AuthHandler                 # verified: examples/oauth2_3lo_server.py:61
import navigator_auth.conf as nav_conf                 # module exists; SECRET_KEY at navigator_auth/conf.py:328
import importlib.util                                  # stdlib
from types import ModuleType                           # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/auth.py
class AuthHandler:
    def __init__(self, app_name: str = "auth", secure_cookies: bool = True,
                 enable_authdb: bool = True, backends: Iterable[str] = None,
                 authz_backends: Iterable[str] = None, **kwargs) -> None:     # :95-103
    self.backends: dict = {}                                                 # :129, filled by get_backends() at :156
    self._backend_list: tuple = tuple(backends) if backends is not None else AUTHENTICATION_BACKENDS  # :132
    self._authz_backends: list = self.get_authorization_backends(
        AUTHORIZATION_BACKENDS if authz_backends is None else authz_backends)  # :158-160

# navigator_auth/conf.py
SECRET_KEY = config.get("AUTH_SECRET_KEY")                                   # :328 (bound at import; env/.env wins)

# examples/oauth2_3lo_server.py
os.environ.setdefault(                                                       # :46-49 (AUTHENTICATION_BACKENDS)
    "AUTHENTICATION_BACKENDS",
    "navigator_auth.backends.oauth2.Oauth2Provider",
)
os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me")  # :54
from navigator_auth.models import User  # noqa: E402                         # :66 (last import)
class DemoIdentityProvider(IdentityProvider):                                # :106 (user_from_id :136)
def make_app() -> web.Application:                                           # :214
    auth = AuthHandler(enable_authdb=False)                                  # :218
```

### Does NOT Exist
- ~~`_BACKENDS`~~ in `examples/oauth2_3lo_server.py` — new here (it exists only in `identity_vault_server.py`).
- ~~`_warn_on_short_secret`~~, or any secret-key length check anywhere in `navigator_auth/` or `examples/`.
- ~~`AuthHandler.authz_backends`~~ public attribute — the list is the private `_authz_backends`.
- No test imports or boots an example module today.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "examples/oauth2_3lo_server.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_3lo_example.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/auth.py#AuthHandler",
    "sym:examples/oauth2_3lo_server.py#make_app",
    "sym:examples/oauth2_3lo_server.py#DemoIdentityProvider"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Never log the key itself — only its length and the variable name `AUTH_SECRET_KEY`.
- Read `nav_conf.SECRET_KEY` at **call time** (module attribute), so tests can
  `monkeypatch.setattr(nav_conf, "SECRET_KEY", ...)`.
- `pyproject` sets `filterwarnings = ["error"]`: the warning is a `logging` warning, not a
  `warnings.warn` — a Python warning would turn every test that calls `make_app()` into an error.
- The example sets `os.environ` defaults at import; loading it in tests is expected (spec M8).

### References in Codebase
- `examples/identity_vault_server.py:108-119` — `_BACKENDS` + override comment.
- `examples/identity_vault_server.py:712-722` — `authz_backends=[]` comment + constructor.

---

## Implementation Blueprint

### Steps (in order)
1. Replace the 4-line `AUTHENTICATION_BACKENDS` `setdefault` (`:46-49`) with `_BACKENDS` + comment +
   `os.environ.setdefault("AUTHENTICATION_BACKENDS", ",".join(_BACKENDS))` — *why*: the env var is kept
   for tooling that reads it, but it is not what decides the list (G1).
2. Add `import navigator_auth.conf as nav_conf  # noqa: E402` and `_warn_on_short_secret()` after the
   last import (`:66`) — *why*: the check must read the value `conf` actually bound.
3. In `make_app()`, call `_warn_on_short_secret()` first, then build the pinned `AuthHandler` — *why*: AC1, AC2.
4. Create the test file and run it.

### `examples/oauth2_3lo_server.py` (MODIFY) — backend list
```python
# occurrences: 1 (verified: grep -c '"navigator_auth.backends.oauth2.Oauth2Provider",' examples/oauth2_3lo_server.py)
# REPLACE the block at :46-49 (verified):
#   os.environ.setdefault(
#       "AUTHENTICATION_BACKENDS",
#       "navigator_auth.backends.oauth2.Oauth2Provider",
#   )
# WITH:
#: Passed to AuthHandler(backends=...) — NOT only exported as AUTHENTICATION_BACKENDS,
#: because navigator_auth.conf ends with ``from settings.settings import *``: run from
#: the repository root, the local dev settings would otherwise decide the backend list
#: (they enable NoAuth, APIKeyAuth, Azure, ...). The env var is kept for tools that read it.
_BACKENDS: list[str] = ["navigator_auth.backends.oauth2.Oauth2Provider"]
os.environ.setdefault("AUTHENTICATION_BACKENDS", ",".join(_BACKENDS))
```
**Why**: keeps `_BACKENDS` above the `navigator_auth` imports, like the vault example.

### `examples/oauth2_3lo_server.py` (MODIFY) — warning helper
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.models import User  # noqa: E402' examples/oauth2_3lo_server.py)
# AFTER — insert below `from navigator_auth.models import User  # noqa: E402` (verified: examples/oauth2_3lo_server.py:66)
import navigator_auth.conf as nav_conf  # noqa: E402

#: RFC 7518 §3.2: an HS256 key must be at least 32 bytes.
_MIN_SECRET_BYTES = 32


def _warn_on_short_secret() -> None:
    """Log a warning when navigator_auth.conf.SECRET_KEY is shorter than 32 bytes.

    The key comes from navconfig (``env/.env`` wins over ``os.environ.setdefault``),
    so the example cannot override it; it tells the operator which variable to fix.
    The key itself is never logged.
    """
    key = nav_conf.SECRET_KEY
    # FILL IN: compute the byte length (str → len(key.encode("utf-8")); bytes → len(key);
    #          None/"" → 0) and, when < _MIN_SECRET_BYTES, emit exactly ONE
    #          logging.warning(...) naming AUTH_SECRET_KEY and the length — bounded by AC2
    #          (no output at all for >= 32 bytes; never the key value).
```

### `examples/oauth2_3lo_server.py` (MODIFY) — `make_app`
```python
# occurrences: 1 (verified: grep -c 'auth = AuthHandler(enable_authdb=False)' examples/oauth2_3lo_server.py)
# REPLACE `auth = AuthHandler(enable_authdb=False)` (verified: examples/oauth2_3lo_server.py:218) and the
# comment above it (:217) WITH:
    _warn_on_short_secret()

    # No PostgreSQL for this example: memory client storage + demo IdP.
    # ``backends`` pins exactly the backend this example demonstrates (see _BACKENDS),
    # and ``authz_backends=[]`` disables *authorization* backends: an inherited
    # ``allow_hosts`` (ALLOWED_HOSTS defaults to ``localhost*``) would let every browser
    # request through without a session.
    auth = AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False)
```
**Why**: AC1 — the pinned list is what `AuthHandler.__init__` uses (`auth.py:132`), whatever `settings.settings` says.

### `tests/test_oauth2_3lo_example.py` (CREATE)
```python
"""FEAT-108 — examples/oauth2_3lo_server.py wiring (M1) and, from TASK-206, the app-level flow (M8)."""
import importlib.util
import logging
from pathlib import Path
from types import ModuleType

import pytest

import navigator_auth.conf as nav_conf

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "oauth2_3lo_server.py"
SETTINGS = Path(__file__).resolve().parent.parent / "settings" / "settings.py"


def _load_example() -> ModuleType:
    """Import examples/oauth2_3lo_server.py by path (it is not a package).

    Its ``os.environ.setdefault`` side effects are expected.
    """
    spec = importlib.util.spec_from_file_location("oauth2_3lo_server_example", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_pins_oauth2_backend_only():
    """AC1: only Oauth2Provider, no authorization backends, even with a richer settings.py."""
    if not SETTINGS.exists():
        pytest.skip("settings/settings.py absent: nothing to override")
    example = _load_example()
    app = example.make_app()
    auth = app["auth"]
    # FILL IN: assert set(auth.backends) == {"Oauth2Provider"} and auth._authz_backends == [] —
    #          bounded by AC1. If make_app() needs Redis to construct, mark the test with the
    #          repository's existing Redis skip pattern instead of mocking AuthHandler.


@pytest.mark.parametrize("key", ["short", b"tiny", None])
def test_example_warns_on_short_secret(monkeypatch, caplog, key):
    """AC2: one warning naming AUTH_SECRET_KEY, never the key."""
    example = _load_example()
    monkeypatch.setattr(nav_conf, "SECRET_KEY", key)
    with caplog.at_level(logging.WARNING):
        example._warn_on_short_secret()
    # FILL IN: exactly one WARNING record whose message contains "AUTH_SECRET_KEY" and does
    #          not contain the key text — bounded by AC2.


def test_example_quiet_on_long_secret(monkeypatch, caplog):
    """AC2: nothing logged for a >= 32-byte key."""
    example = _load_example()
    monkeypatch.setattr(nav_conf, "SECRET_KEY", "k" * 48)
    with caplog.at_level(logging.WARNING):
        example._warn_on_short_secret()
    assert not [r for r in caplog.records if "AUTH_SECRET_KEY" in r.getMessage()]
```
**Why this shape**: TASK-206 reuses `_load_example()` from this file; keep the name and module name.

### FILL IN checklist
- [ ] `_warn_on_short_secret` — byte length + single warning; bounded by AC2.
- [ ] `test_example_pins_oauth2_backend_only` — the two asserts; bounded by AC1.
- [ ] `test_example_warns_on_short_secret` — one record, names the variable, hides the key; bounded by AC2.

---

## Acceptance Criteria

- [ ] AC1: `make_app()` builds `AuthHandler(backends=["navigator_auth.backends.oauth2.Oauth2Provider"], authz_backends=[], enable_authdb=False)`; `app["auth"].backends` holds only `Oauth2Provider` while `settings/settings.py` lists others.
- [ ] AC2: `_warn_on_short_secret()` logs exactly one warning naming `AUTH_SECRET_KEY` for a < 32-byte key, none otherwise.
- [ ] `ruff check examples/oauth2_3lo_server.py tests/test_oauth2_3lo_example.py` is clean.

---

## Validation Commands

- `pytest tests/test_oauth2_3lo_example.py -q`

---

## Test Specification

See the CREATE block above: `test_example_pins_oauth2_backend_only`,
`test_example_warns_on_short_secret` (parametrized), `test_example_quiet_on_long_secret` (spec §4, M1).

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` in the blueprint before editing; a changed
   count means the anchor moved (re-locate it), a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-195 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
