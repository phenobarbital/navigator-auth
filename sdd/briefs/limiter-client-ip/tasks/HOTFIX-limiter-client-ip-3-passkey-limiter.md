# HOTFIX-limiter-client-ip-3: passkey `login/options` limiter keys on the real client IP

**Feature**: BRIEF-limiter-client-ip — IP rate limiters must key on the real client IP
**Spec**: `sdd/briefs/limiter-client-ip.brief.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: HOTFIX-limiter-client-ip-1
**Assigned-to**: unassigned

---

## Context

`PasskeyAuth._rate_limit` keys its Redis counter on `request.remote`
(`navigator_auth/backends/passkey.py:191`); its docstring says the limit must be
enforced at the proxy when one exists. Behind a proxy every passkey
`login/options` caller therefore shares one counter. The owner chose in Q&A to
change that design: the limiter now honours `ALLOWED_IP_TRUSTED_PROXIES`
through `limiter_client_ip`, which HOTFIX-limiter-client-ip-1 adds.

---

## Scope

- Key the passkey limiter on `limiter_client_ip(request, _TRUSTED_PROXIES)`,
  with a module-level `_TRUSTED_PROXIES = parse_proxies(auth_conf.ALLOWED_IP_TRUSTED_PROXIES)`
  in `navigator_auth/backends/passkey.py`.
- Rewrite the `_rate_limit` docstring to describe the new rule.
- Add a test proving the key follows the forwarded client from a trusted proxy
  and ignores the header from an untrusted peer.

**NOT in scope**: the rate value, the TTL, the Redis error handling, other
passkey endpoints, and the MFA / recovery / device-code limiters.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/passkey.py` | MODIFY | Limiter key via `limiter_client_ip`; docstring |
| `tests/test_passkey_backend_unit.py` | MODIFY | Key-resolution test |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
from .. import conf as auth_conf  # verified: navigator_auth/backends/passkey.py:19 (already imported)
from ..authorizations._client_ip import limiter_client_ip, parse_proxies  # limiter_client_ip added by HOTFIX-limiter-client-ip-1; parse_proxies verified: navigator_auth/authorizations/_client_ip.py:41
```

### Existing Signatures to Use
```python
# navigator_auth/backends/passkey.py:70
class PasskeyAuth(BasicAuth):
    async def _rate_limit(self, request: web.Request) -> None:  # line 183
        # limit = auth_conf.PASSKEY_LOGIN_OPTIONS_RATE ; returns when 0
        key = f"passkey_rl_{request.remote}"  # line 191
        # aioredis.Redis(connection_pool=self._pool): incr(key), expire(key, 60) on first hit
        # raises AuthException(status=429) when count > limit

# navigator_auth/authorizations/_client_ip.py (after HOTFIX-limiter-client-ip-1)
def limiter_client_ip(request: web.Request, proxies: set[IPAddress] | None = None) -> str: ...
```

```python
# tests/test_passkey_backend_unit.py:18-22
@pytest.fixture
def backend(passkey_rp_config):
    return PasskeyAuth(user_model=MagicMock(), identity=MagicMock())
# tests/test_passkey_backend_unit.py:180 test_rate_limit_disabled_and_enforced —
# pattern: monkeypatch conf.PASSKEY_LOGIN_OPTIONS_RATE and
# "navigator_auth.backends.passkey.aioredis.Redis" with a fake exposing incr/expire.
```

### Does NOT Exist
- ~~`PasskeyAuth._trusted_proxies`~~ — use the module-level `_TRUSTED_PROXIES` this task adds
- ~~`navigator_auth.conf.PASSKEY_TRUSTED_PROXIES`~~ — the setting is `ALLOWED_IP_TRUSTED_PROXIES`

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/passkey.py", "action": "MODIFY"},
    {"path": "tests/test_passkey_backend_unit.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth._rate_limit",
    "sym:navigator_auth/authorizations/_client_ip.py#parse_proxies"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Start only after HOTFIX-limiter-client-ip-1 is merged into this worktree's
  branch: `limiter_client_ip` must exist.
- With `ALLOWED_IP_TRUSTED_PROXIES` empty the key is `passkey_rl_<request.remote>`
  as today; a missing peer now yields `passkey_rl_unknown` instead of
  `passkey_rl_None`.
- Never run `tests/test_oauth2_passkey_session.py` here: it hangs at baseline.

---

## Implementation Blueprint

### Steps (in order)
1. Import the helpers and add `_TRUSTED_PROXIES` — *why*: same pattern as the MFA and recovery modules.
2. Change the key and the docstring — *why*: the owner widened scope to this limiter.
3. Add the test — *why*: prove proxy honoured and spoofing ignored.

### `navigator_auth/backends/passkey.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'key = f"passkey_rl_{request.remote}"' navigator_auth/backends/passkey.py)
# Imports: add next to `from .. import conf as auth_conf` (line 19):
from ..authorizations._client_ip import limiter_client_ip, parse_proxies
# Module level, after the imports:
_TRUSTED_PROXIES = parse_proxies(auth_conf.ALLOWED_IP_TRUSTED_PROXIES)

# _rate_limit docstring (lines 184-187) becomes:
        """Per-client cap on ``login/options`` (``PASSKEY_LOGIN_OPTIONS_RATE`` per minute).

        Disabled when the setting is 0. The client is resolved by
        ``limiter_client_ip``: ``X-Forwarded-For`` / ``CF-Connecting-IP`` count
        only when the direct peer is listed in ``ALLOWED_IP_TRUSTED_PROXIES``.
        """
# Line 191 becomes:
        key = f"passkey_rl_{limiter_client_ip(request, _TRUSTED_PROXIES)}"
```

### FILL IN checklist
- [ ] Key-resolution test — AC-1, AC-2.

---

## Acceptance Criteria

- [ ] AC-1: With `_TRUSTED_PROXIES` patched to `{ip_address("10.0.0.1")}`, a request from peer `10.0.0.1` with `X-Forwarded-For: 203.0.113.7` increments `passkey_rl_203.0.113.7`.
- [ ] AC-2: With the default empty set, the same request increments `passkey_rl_10.0.0.1`.
- [ ] `test_rate_limit_disabled_and_enforced` and the rest of `tests/test_passkey_backend_unit.py` pass.
- [ ] No lint errors on the touched files.

---

## Validation Commands

- `pytest tests/test_passkey_backend_unit.py -q`

---

## Test Specification

```python
# tests/test_passkey_backend_unit.py — append
@pytest.mark.asyncio
async def test_rate_limit_keys_on_trusted_forwarded_client(backend, monkeypatch):
    # FILL IN: fake Redis recording incr keys (copy the _Redis pattern of
    # test_rate_limit_disabled_and_enforced); monkeypatch
    # conf.PASSKEY_LOGIN_OPTIONS_RATE to 5 and
    # "navigator_auth.backends.passkey._TRUSTED_PROXIES" to {ip_address("10.0.0.1")};
    # request double with remote="10.0.0.1" and
    # headers={"X-Forwarded-For": "203.0.113.7"}; backend._pool = object();
    # await backend._rate_limit(req); assert recorded key == "passkey_rl_203.0.113.7";
    # then patch _TRUSTED_PROXIES to set() and assert "passkey_rl_10.0.0.1".
    ...
```

---

## Agent Instructions

1. Work in the brief worktree `.claude/worktrees/hotfix-limiter-client-ip-limiter-client-ip` — never on `main`.
2. Confirm HOTFIX-limiter-client-ip-1 is `done` in `sdd/briefs/limiter-client-ip.index.json`.
3. Verify the Codebase Contract before writing code.
4. Mark this task `in-progress` in the index and commit only that file.
5. Implement from the blueprint; complete every `FILL IN`.
6. Run the Validation Commands.
7. Commit only the files listed above.
8. Close the task with `parrot sdd task close HOTFIX-limiter-client-ip-3 limiter-client-ip verified`, then fill in the Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
