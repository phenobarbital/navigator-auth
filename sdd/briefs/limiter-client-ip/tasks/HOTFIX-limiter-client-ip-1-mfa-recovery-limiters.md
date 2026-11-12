# HOTFIX-limiter-client-ip-1: MFA and recovery limiters key on `get_client_ip`

**Feature**: BRIEF-limiter-client-ip — IP rate limiters must key on the real client IP
**Spec**: `sdd/briefs/limiter-client-ip.brief.md`
**Status**: done
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Behind a proxy, `request.remote` is the proxy's address, so the MFA and
password-recovery IP limiters put every user in one bucket (shared-budget DoS,
no per-source limit). The brief's Root cause table lists the anchors. This
task adds one limiter-identity helper on top of `get_client_ip` and routes the
MFA (both `_remote` helpers, which feed the same `services.ip_limiter`) and
recovery step-1 keys through it.

---

## Scope

- Add `limiter_client_ip(request, proxies)` to
  `navigator_auth/authorizations/_client_ip.py`.
- Make `_remote()` in `navigator_auth/mfa/login.py` and in
  `navigator_auth/handlers/mfa.py` return `limiter_client_ip(request, _TRUSTED_PROXIES)`,
  with a module-level `_TRUSTED_PROXIES = parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)`
  in each module. Call sites stay untouched.
- Replace `client_ip = self.request.remote or "unknown"` in
  `PasswordRecoveryHandler._step1_request` with the helper, using a
  module-level `_TRUSTED_PROXIES` in `navigator_auth/handlers/recovery/handler.py`.
- Write `tests/test_limiter_client_ip.py`.

**NOT in scope**: the OAuth2 device-code lockout (HOTFIX-limiter-client-ip-2),
the passkey limiter (HOTFIX-limiter-client-ip-3), refactoring
`Oauth2Provider._client_source_ip`, `abac/context.py`, and any change to the
limiter classes or their rates.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/authorizations/_client_ip.py` | MODIFY | Add `limiter_client_ip()` |
| `navigator_auth/mfa/login.py` | MODIFY | `_remote()` delegates to the helper; module `_TRUSTED_PROXIES` |
| `navigator_auth/handlers/mfa.py` | MODIFY | `_remote()` delegates to the helper; module `_TRUSTED_PROXIES` |
| `navigator_auth/handlers/recovery/handler.py` | MODIFY | Step-1 IP key uses the helper; module `_TRUSTED_PROXIES` |
| `tests/test_limiter_client_ip.py` | CREATE | Helper, MFA and recovery key tests |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
from navigator_auth.authorizations._client_ip import get_client_ip, parse_proxies  # verified: navigator_auth/authorizations/_client_ip.py:80, :41
from navigator_auth.conf import ALLOWED_IP_TRUSTED_PROXIES  # verified: navigator_auth/conf.py:212 (list[str])
from navigator_auth import conf as auth_conf  # verified: navigator_auth/mfa/login.py:18 (already imported there)
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY, AUTH_OTP_CHALLENGE_TTL  # verified: navigator_auth/handlers/mfa.py:18 (extend this line)
from navigator_auth.conf import (...)  # verified: navigator_auth/handlers/recovery/handler.py:28-40 (extend this tuple)
```

### Existing Signatures to Use
```python
# navigator_auth/authorizations/_client_ip.py:11
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# navigator_auth/authorizations/_client_ip.py:41
def parse_proxies(entries: list[str]) -> set[IPAddress]: ...

# navigator_auth/authorizations/_client_ip.py:80
def get_client_ip(request: web.Request, proxies: set[IPAddress] | None = None) -> str | None:
    # returns None when request.remote is falsy or not an IP address;
    # reads request.headers ONLY when ip_address(request.remote) is in proxies.

# navigator_auth/mfa/login.py:80  (sole call site: :187, services.ip_limiter.check(_remote(request)))
def _remote(request: web.Request) -> str:
    return getattr(request, "remote", None) or "unknown"

# navigator_auth/handlers/mfa.py:60  (call sites: :229, :251, :299, :347, :410 — all services.ip_limiter.check)
def _remote(request: web.Request) -> str:
    return request.remote or "unknown"

# navigator_auth/handlers/recovery/handler.py:132
class PasswordRecoveryHandler(BaseView):
    _ip_limiter  # RateLimiter, set at :167
    _email_limiter  # RateLimiter
    async def _step1_request(self):  # line 195; the key is built at line 205:
        client_ip = self.request.remote or "unknown"
```

Prior art for the exact fallback rule: `Oauth2Provider._client_source_ip`
(`navigator_auth/backends/oauth2/backend.py:1426`) returns
`get_client_ip(request, self._trusted_proxies) or request.remote or "unknown"`.

### Does NOT Exist
- ~~`navigator_auth.authorizations._client_ip.limiter_client_ip`~~ — created by this task
- ~~`navigator_auth.conf.TRUSTED_PROXIES`~~ — the setting is `ALLOWED_IP_TRUSTED_PROXIES`
- ~~`_TRUSTED_PROXIES`~~ in `mfa/login.py`, `handlers/mfa.py`, `handlers/recovery/handler.py` — created by this task

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/authorizations/_client_ip.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/login.py", "action": "MODIFY"},
    {"path": "navigator_auth/handlers/mfa.py", "action": "MODIFY"},
    {"path": "navigator_auth/handlers/recovery/handler.py", "action": "MODIFY"},
    {"path": "tests/test_limiter_client_ip.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/authorizations/_client_ip.py#get_client_ip",
    "sym:navigator_auth/authorizations/_client_ip.py#parse_proxies",
    "sym:navigator_auth/mfa/login.py#_remote",
    "sym:navigator_auth/handlers/mfa.py#_remote",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler._step1_request"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- With `ALLOWED_IP_TRUSTED_PROXIES` empty (the default) every key must be
  byte-identical to today's (`request.remote`, else `"unknown"`).
- Keep `getattr(request, "remote", None)` tolerance: MFA test doubles are
  `SimpleNamespace(remote=...)` objects, some without `headers`
  (`tests/test_mfa_verify.py:153`, `tests/test_mfa_review_followups.py:99`,
  `tests/test_mfa_admin_disenroll.py:82`).
- Do not rename `_remote` or touch its call sites.
- Never log the resolved IP or forwarding headers at INFO or above.
- After the change, confirm there is no import cycle in a fresh interpreter:
  `python -c "import navigator_auth.mfa.login, navigator_auth.handlers.mfa, navigator_auth.handlers.recovery.handler"`.

---

## Implementation Blueprint

### Steps (in order)
1. Add `limiter_client_ip` to `_client_ip.py` — *why*: one fallback rule for every limiter.
2. Point both MFA `_remote` helpers at it — *why*: both feed the same `services.ip_limiter`, so they must agree on the identity.
3. Point recovery step 1 at it — *why*: the requirement names `recovery/handler.py:205`.
4. Write the tests — *why*: proxy honoured, spoofing ignored, default unchanged.

### `navigator_auth/authorizations/_client_ip.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^def get_client_ip(' navigator_auth/authorizations/_client_ip.py)
# AFTER — append at the end of the module, below get_client_ip (verified: navigator_auth/authorizations/_client_ip.py:80)
def limiter_client_ip(
    request: web.Request,
    proxies: set[IPAddress] | None = None,
) -> str:
    """Return the identity an IP rate limiter keys on.

    Resolves the real client through ``get_client_ip`` (forwarding headers
    are honoured only when the direct peer is a trusted proxy), then falls
    back to the raw peer and finally to ``"unknown"`` so a limiter always
    has a key. With no trusted proxies this is exactly ``request.remote``.

    Args:
        request: The incoming request, or a test double exposing ``remote``.
        proxies: Trusted proxy addresses, normally
            ``parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)``.

    Returns:
        The client IP, the raw peer address, or ``"unknown"``.
    """
    remote = getattr(request, "remote", None)
    if not remote:
        return "unknown"
    return get_client_ip(request, proxies) or remote
```

### `navigator_auth/mfa/login.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^def _remote(' navigator_auth/mfa/login.py)
# Add to the imports (below `from navigator_auth import conf as auth_conf`, line 18):
from navigator_auth.authorizations._client_ip import limiter_client_ip, parse_proxies

# Module level, right above `def _remote` (line 80):
_TRUSTED_PROXIES = parse_proxies(auth_conf.ALLOWED_IP_TRUSTED_PROXIES)


def _remote(request: web.Request) -> str:
    """Return the client IP the MFA limiter keys on, honouring trusted proxies."""
    return limiter_client_ip(request, _TRUSTED_PROXIES)
```

### `navigator_auth/handlers/mfa.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^def _remote(' navigator_auth/handlers/mfa.py)
# Line 18 becomes:
from navigator_auth.conf import ALLOWED_IP_TRUSTED_PROXIES, AUTH_EXCLUDE_LIST_KEY, AUTH_OTP_CHALLENGE_TTL
# New import next to the other navigator_auth imports:
from navigator_auth.authorizations._client_ip import limiter_client_ip, parse_proxies

# Module level, right above `def _remote` (line 60):
_TRUSTED_PROXIES = parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)


def _remote(request: web.Request) -> str:
    """Return the client IP the MFA limiter keys on, honouring trusted proxies."""
    return limiter_client_ip(request, _TRUSTED_PROXIES)
```

### `navigator_auth/handlers/recovery/handler.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'client_ip = self.request.remote or "unknown"' navigator_auth/handlers/recovery/handler.py)
# Add ALLOWED_IP_TRUSTED_PROXIES to the `from navigator_auth.conf import (...)` tuple (lines 28-40), and:
from navigator_auth.authorizations._client_ip import limiter_client_ip, parse_proxies
# Module level, after the imports and the module logger:
_TRUSTED_PROXIES = parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)
# Line 205 becomes:
            client_ip = limiter_client_ip(self.request, _TRUSTED_PROXIES)
```

### FILL IN checklist
- [ ] `tests/test_limiter_client_ip.py` — recovery case: drive `_step1_request` with a recording fake `_ip_limiter` (and `_email_limiter` returning True, `_process_recovery_request` and `_pad_latency` stubbed) and assert the key; bounded by AC-4.

---

## Acceptance Criteria

- [ ] AC-1: `limiter_client_ip` returns the right-most non-proxy `X-Forwarded-For` hop when the peer is a trusted proxy.
- [ ] AC-2: `limiter_client_ip` ignores `X-Forwarded-For` / `CF-Connecting-IP` from an untrusted peer and returns the peer.
- [ ] AC-3: `limiter_client_ip` returns `"unknown"` for a missing/empty `remote` (including an object with no `remote` attribute) and the raw `remote` when it is not an IP.
- [ ] AC-4: With a patched `_TRUSTED_PROXIES`, `mfa.login._remote`, `handlers.mfa._remote` and recovery step 1 all key on the forwarded client IP; with the default empty set they key on `request.remote`.
- [ ] Existing MFA and recovery test files below pass (environmental failures from a short local `AUTH_SECRET_KEY` are pre-existing and must be reported, not fixed).
- [ ] No lint errors on the touched files.

---

## Validation Commands

- `pytest tests/test_limiter_client_ip.py -q`
- `pytest tests/test_mfa_verify.py -q`
- `pytest tests/test_mfa_review_fixes_management.py -q`
- `pytest tests/test_mfa_enrollment_security.py -q`
- `pytest tests/test_mfa_admin_disenroll.py -q`
- `pytest tests/test_mfa_review_followups.py -q`
- `pytest tests/test_password_recovery.py -q`

---

## Test Specification

```python
# tests/test_limiter_client_ip.py
from ipaddress import ip_address
from types import SimpleNamespace

import pytest

from navigator_auth.authorizations._client_ip import limiter_client_ip

PROXY = "10.0.0.1"
CLIENT = "203.0.113.7"


def _req(remote, headers=None):
    return SimpleNamespace(remote=remote, headers=headers or {})


def test_trusted_proxy_resolves_forwarded_client():
    req = _req(PROXY, {"X-Forwarded-For": f"198.51.100.9, {CLIENT}"})
    assert limiter_client_ip(req, {ip_address(PROXY)}) == CLIENT


def test_untrusted_peer_cannot_spoof():
    req = _req(CLIENT, {"X-Forwarded-For": "192.0.2.50"})
    assert limiter_client_ip(req, {ip_address(PROXY)}) == CLIENT


def test_no_proxies_is_raw_remote():
    assert limiter_client_ip(_req(PROXY, {"X-Forwarded-For": CLIENT})) == PROXY


@pytest.mark.parametrize("request_", [SimpleNamespace(), _req(None), _req("")])
def test_missing_remote_is_unknown(request_):
    assert limiter_client_ip(request_) == "unknown"


def test_non_ip_remote_is_kept():
    assert limiter_client_ip(_req("unix-socket")) == "unix-socket"


@pytest.mark.parametrize("module_path", ["navigator_auth.mfa.login", "navigator_auth.handlers.mfa"])
def test_mfa_remote_honours_trusted_proxies(module_path, monkeypatch):
    import importlib

    module = importlib.import_module(module_path)
    monkeypatch.setattr(module, "_TRUSTED_PROXIES", {ip_address(PROXY)})
    assert module._remote(_req(PROXY, {"X-Forwarded-For": CLIENT})) == CLIENT
    monkeypatch.setattr(module, "_TRUSTED_PROXIES", set())
    assert module._remote(_req(PROXY, {"X-Forwarded-For": CLIENT})) == PROXY


async def test_recovery_step1_keys_ip_limiter_on_client(monkeypatch):
    # FILL IN: build PasswordRecoveryHandler without a live app/Redis, patch
    # handler module `_TRUSTED_PROXIES`, stub json_data/_email_limiter/
    # _process_recovery_request/_pad_latency/json_response, record the key
    # passed to _ip_limiter.check, and assert it equals CLIENT.
    ...
```

---

## Agent Instructions

1. Work in the brief worktree `.claude/worktrees/hotfix-limiter-client-ip-limiter-client-ip` — never on `main`.
2. Read the brief at `sdd/briefs/limiter-client-ip.brief.md`.
3. Verify the Codebase Contract before writing code.
4. Mark this task `in-progress` in `sdd/briefs/limiter-client-ip.index.json` and commit only that file.
5. Implement from the blueprint; complete every `FILL IN`.
6. Run the Validation Commands.
7. Commit only the files listed above (never `git add .` / `-A`).
8. Close the task with `parrot sdd task close HOTFIX-limiter-client-ip-1 limiter-client-ip verified`, then fill in the Completion Note.

---

## Completion Note



**Completed by**: sdd-worker (sequential fallback; coder engine could not route HOTFIX-* ids: complexity_audit_failed)
**Date**: 2026-11-12
**Notes**: Implemented per blueprint; validation commands run. Env-only failures: tests/test_password_recovery.py needs Redis/DB (ConnectionError); several MFA tests skipped; test_passkey_backend_unit.py::test_on_startup_without_webauthn_raises fails on a google FutureWarning (pre-existing, unrelated).

**Deviations from spec**: none
