# TASK-86: Passkey settings and the `passkey` optional extra

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 1, §6 External library, AC1, AC2)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

This is the first task of serial stage S0. It adds the five `PASSKEY_*` settings that every later
module reads, and the optional `navigator-auth[passkey]` extra that pulls in py_webauthn.

It also confirms the py_webauthn 2.x API. The spec lists that API as **unverified**, because
`webauthn` was not installed when the spec was written. Tasks 93 to 95 depend on the names
confirmed here.

---

## Scope

- Add `PASSKEY_RELYING_PARTIES`, `PASSKEY_CHALLENGE_TTL`, `PASSKEY_USER_VERIFICATION`,
  `PASSKEY_TENANT_ATTRIBUTE` and `PASSKEY_DECOY_CREDENTIALS` to `navigator_auth/conf.py`.
- Add `passkey = ["webauthn>=2.0,<3"]` to `[project.optional-dependencies]` in `pyproject.toml`.
- Install it into the dev venv (`uv pip install "webauthn>=2.0,<3"`). Then verify every
  py_webauthn name listed in spec §6 "External library" against the installed package. Record
  the confirmed signatures, or any differences, in this task's Completion Note **and** in a new
  `### External library — verified` block in spec §6, so later tasks read verified names.
- Write `tests/test_passkey_conf.py` (`test_conf_passkey_defaults`).

**NOT in scope**:
- `RelyingParty` validation of the map entries (TASK-87 and TASK-89).
- Any import of `webauthn` from `navigator_auth`. It must stay lazy (R9), and TASK-93 owns it.
- Docs (TASK-98).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | `PASSKEY_*` settings block |
| `pyproject.toml` | MODIFY | `passkey` extra |
| `tests/test_passkey_conf.py` | CREATE | Defaults and invalid-JSON tests |
| `sdd/specs/passkey-support-backend.spec.md` | MODIFY | §6: append the verified py_webauthn API block |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
# already imported at the top of navigator_auth/conf.py (lines 5-12):
import orjson                                   # conf.py:7
from navconfig import config, BASE_DIR          # conf.py:10
from navconfig.logging import logging           # conf.py:11
```

### Existing Signatures to Use
```python
# navigator_auth/conf.py
AUTH_DB_SCHEMA = config.get("AUTH_DB_SCHEMA", fallback="auth")          # :32
REDIS_AUTH_URL = config.get("REDIS_AUTH_URL", fallback=REDIS_URL)       # :333
SECRET_KEY = config.get("AUTH_SECRET_KEY")  # bytes fallback when unset  # :341-344
# Pattern for a JSON setting (copy it), conf.py:311-319:
USER_MAPPING = DEFAULT_MAPPING
mapping = config.get("AUTH_USER_MAPPING")
if mapping is not None:
    try:
        USER_MAPPING = orjson.loads(mapping)
    except orjson.JSONDecodeError:
        logging.exception("Auth: Invalid User Mapping on *AUTH_USER_MAPPING*")
# Last block before the insertion point, conf.py:661-677:
TOKEN_EXCHANGE_MAX_TTL = config.getint("TOKEN_EXCHANGE_MAX_TTL", fallback=SESSION_TIMEOUT)
TOKEN_EXCHANGE_PROVIDERS = [...]                                        # :671
## Backend-Based Password Recovery (FEAT-098) — 3-step signed flow.     # :679  ← insert BEFORE this line
```
```toml
# pyproject.toml
[project.optional-dependencies]     # :60
uvloop = ["uvloop>=0.20.0"]         # :61
geoip = ["geoip2>=4.7.0"]           # :62
```

### Does NOT Exist
- No `PASSKEY_*` setting anywhere, no `passkey` extra, and no `webauthn` package in the venv.
- `config.getlist` is not used for JSON maps in this file; JSON settings are parsed with `orjson.loads`.
- `navigator_auth/passkey/` does not exist yet (TASK-87 creates it). Do not import from it here.

---

## Implementation Blueprint

### Steps (in order)
1. Insert the settings block in `conf.py` right before the FEAT-098 recovery header. It must sit
   after `REDIS_AUTH_URL` and `SECRET_KEY`, because those are defined earlier and the passkey
   backend reads them together.
2. Add the `passkey` extra to `pyproject.toml` below `geoip`.
3. `source .venv/bin/activate && uv pip install "webauthn>=2.0,<3"`. **Do not run `uv sync`**,
   and do not `uv add` from inside a worktree: it repoints the shared venv
   (`.claude/rules/worktree-management.md` §4).
4. Verify the py_webauthn API, e.g.
   `python -c "import webauthn, inspect; print(webauthn.__version__); print(inspect.signature(webauthn.verify_authentication_response))"`.
   Do this for every name in spec §6. Write the result into the spec as described in Scope,
   because tasks 93 to 95 copy their webauthn calls from that block.
5. Write the tests and run them.

### `navigator_auth/conf.py` — MODIFY
```python
# BEFORE — insert above `## Backend-Based Password Recovery (FEAT-098) — 3-step signed flow.`
#   (verified: conf.py:679; occurrences: 1 (verified: grep -cF))

## Passkey (WebAuthn) authentication (FEAT-101) — PasskeyAuth backend.
# Exact-origin allow-list of relying parties (one per tenant site), JSON list:
#   [{"origin": "https://app.a.com", "rp_id": "a.com", "rp_name": "A",
#     "org_id": 5, "client_id": 1}]
# Empty when unset or invalid; PasskeyAuth refuses to start with an empty map.
PASSKEY_RELYING_PARTIES: list = []
_passkey_rps = config.get("PASSKEY_RELYING_PARTIES")
if _passkey_rps:
    try:
        PASSKEY_RELYING_PARTIES = orjson.loads(_passkey_rps)
    except orjson.JSONDecodeError:
        logging.exception(
            "Auth: Invalid JSON on *PASSKEY_RELYING_PARTIES*"
        )
    # FILL IN: if the parsed value is not a list, log an error and reset it to [] — bounded by
    #          test_conf_passkey_defaults ("invalid JSON is logged and yields []").
# Seconds a registration/login challenge stays valid in Redis (single use).
PASSKEY_CHALLENGE_TTL = config.getint("PASSKEY_CHALLENGE_TTL", fallback=300)
# "required" (default) or "preferred". With "required", assertions without UV are rejected.
PASSKEY_USER_VERIFICATION = config.get("PASSKEY_USER_VERIFICATION", fallback="required")
# Optional user attribute compared to the RP's org_id (e.g. "org_id"); unset disables the check.
PASSKEY_TENANT_ATTRIBUTE = config.get("PASSKEY_TENANT_ATTRIBUTE", fallback=None)
# Number of decoy credential ids returned for unknown users (username-first, E5).
PASSKEY_DECOY_CREDENTIALS = config.getint("PASSKEY_DECOY_CREDENTIALS", fallback=1)
```
**Why**: Parsing at import time with a logged fallback matches `USER_MAPPING`. The empty-map
refusal belongs to `PasskeyAuth` startup (AC1), not to `conf.py`, because deployments that do not
enable the backend must still import `conf` cleanly.

### `pyproject.toml` — MODIFY
```toml
# AFTER — insert below `geoip = ["geoip2>=4.7.0"]` (verified: pyproject.toml:62; occurrences: 1)
passkey = ["webauthn>=2.0,<3"]
```
**Why**: An optional extra keeps `webauthn` out of default installs (Q7, R9).

### `tests/test_passkey_conf.py` — CREATE
```python
"""FEAT-101 TASK-86 — PASSKEY_* settings defaults and parsing."""
import importlib

import pytest


def _reload_conf(monkeypatch, **env):
    """Reload navigator_auth.conf with the given environment values."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import navigator_auth.conf as conf
    # FILL IN: confirm navconfig's `config.get` sees monkeypatched env vars on reload; if it
    #          caches values, patch `conf.config.get`/`getint` instead — bounded by: tests must
    #          not leak settings into other test modules (restore with a final reload).
    return importlib.reload(conf)


def test_conf_passkey_defaults(monkeypatch):
    """TTL 300, UV required, empty RP map, tenant check off, one decoy."""
    # FILL IN: assert the five defaults from the spec Module 1 skeleton.


def test_conf_passkey_invalid_json_yields_empty(monkeypatch, caplog):
    """Invalid PASSKEY_RELYING_PARTIES JSON is logged and yields []."""
    # FILL IN: set the env var to "not-json", reload, and assert [] plus a logged error.
```

### FILL IN checklist
- [ ] Non-list JSON resets to `[]` with a logged error.
- [ ] The reload strategy works with navconfig and does not leak state.
- [ ] Both test bodies are written.
- [ ] The py_webauthn verification block is added to spec §6 (exact signatures and the result attribute names).

---

## Acceptance Criteria

- [ ] The five settings exist with the defaults from the spec (AC1, settings part).
- [ ] `pyproject.toml` declares the `passkey` extra (AC2).
- [ ] `python -c "import navigator_auth.backends"` still works (AC2).
- [ ] `pytest tests/test_passkey_conf.py -v` passes.
- [ ] `ruff check navigator_auth/conf.py tests/test_passkey_conf.py` shows no new findings.
- [ ] Spec §6 carries the verified py_webauthn API.

---

## Test Specification

See the `tests/test_passkey_conf.py` blueprint above (spec §4: `test_conf_passkey_defaults`).

---

## Agent Instructions

1. Read the spec (Module 1, §6, §7 R9).
2. This task has no dependencies.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside the feature worktree `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**py_webauthn version / API differences**:
**Deviations from spec**: none
