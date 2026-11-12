# HOTFIX-limiter-client-ip-2: OAuth2 device-code lockout stops trusting raw X-Forwarded-For

**Feature**: BRIEF-limiter-client-ip — IP rate limiters must key on the real client IP
**Spec**: `sdd/briefs/limiter-client-ip.brief.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

`Oauth2Provider.device_verification` builds its brute-force lockout key from
the left-most `X-Forwarded-For` value, read from **any** peer
(`navigator_auth/backends/oauth2/backend.py:3268`). An attacker rotates the
header on every `user_code` guess and never reaches
`OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS`. The same class already has the
proxy-aware identity `_client_source_ip` (`backend.py:1426`), used by the DCR
limiter. Added to the brief's scope by the owner in Q&A.

---

## Scope

- Replace the four lines that derive `client_ip` from `X-Forwarded-For` in
  `device_verification` with `client_ip = self._client_source_ip(request)`, and
  drop the now-wrong "Use X-Forwarded-For if available" comment (keep the
  shared-NAT caveat).
- Set `provider._trusted_proxies = set()` in the `_make_provider` builder of
  `tests/test_device_verification.py` (it builds the provider via `__new__`).
- Add regression tests for the spoofing case and the trusted-proxy case.

**NOT in scope**: `_record_device_attempt`, the lockout TTL/threshold
settings, the DCR limiter, any other `X-Forwarded-For` reader, and the MFA /
recovery / passkey limiters (HOTFIX-limiter-client-ip-1 and -3).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Device-code lockout key via `_client_source_ip` |
| `tests/test_device_verification.py` | MODIFY | Builder sets `_trusted_proxies`; two regression tests |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
from navigator_auth.backends.oauth2.backend import Oauth2Provider  # verified: tests/test_device_verification.py:108
from ipaddress import ip_address  # stdlib, for the tests
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py:287
class Oauth2Provider(BaseAuthBackend):
    _trusted_proxies: set  # set in __init__ at line 345: parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)

    def _client_source_ip(self, request: web.Request) -> str:  # line 1426
        # get_client_ip(request, self._trusted_proxies) or request.remote or "unknown"

    async def device_verification(self, request: web.Request):  # line 3228
        # lines 3265-3273 today:
        # # --- Anti-brute-force: Redis-backed rate-limit + lockout (D3) ---
        # # Use X-Forwarded-For if available (reverse proxy), else fall back to remote.
        # # NOTE: IP-only lockout is bypassable behind a shared NAT; see issue M-3.
        # client_ip = request.headers.get("X-Forwarded-For", request.remote)
        # if client_ip:
        #     client_ip = client_ip.split(",")[0].strip()  # take first (client) IP
        # client_ip = client_ip or "unknown"
        # lockout_key = f"oauth2:device:lockout:{client_ip}"
        # attempt_key = f"oauth2:device:attempts:{client_ip}"

    async def _record_device_attempt(self, attempt_key: str, lockout_key: str) -> None:  # line 3377
        # no-op unless self.device_code_storage has a `redis` attribute;
        # calls redis.incr(attempt_key), redis.expire(...), redis.set(lockout_key, ...)
```

```python
# tests/test_device_verification.py:105-152
def _make_provider(client, device_store=None, session_user=None, grant_store=None, code_store=None):
    provider = Oauth2Provider.__new__(Oauth2Provider)   # line 110 — __init__ is NOT run
    ...
# tests/test_device_verification.py:155
def _make_post_request(form_data: dict, remote: str = "127.0.0.1") -> MagicMock:
    # request.headers = {} ; request.remote = remote
```

### Does NOT Exist
- ~~`provider._trusted_proxies`~~ on providers built by `_make_provider` — the builder must set it (this task)
- ~~`navigator_auth.backends.oauth2.backend.get_device_client_ip`~~ — no such helper; reuse `_client_source_ip`

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "tests/test_device_verification.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._client_source_ip",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.device_verification",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._record_device_attempt"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- With `ALLOWED_IP_TRUSTED_PROXIES` empty, a request **without**
  `X-Forwarded-For` keeps the same key as today. A request **with** the header
  from an untrusted peer now keys on the peer — that is the fix.
- Do not change the Redis key prefixes (`oauth2:device:lockout:` /
  `oauth2:device:attempts:`).

---

## Implementation Blueprint

### Steps (in order)
1. Replace the key derivation in `device_verification` — *why*: close the header-rotation bypass.
2. Set `_trusted_proxies` in the test builder — *why*: `__new__` skips `__init__`, so `_client_source_ip` would raise `AttributeError`.
3. Add the regression tests — *why*: prove spoofed headers no longer move the key.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'client_ip = request.headers.get("X-Forwarded-For", request.remote)' navigator_auth/backends/oauth2/backend.py)
# Replace lines 3266-3271 (the comment "Use X-Forwarded-For if available ..." through
# `client_ip = client_ip or "unknown"`; keep line 3265 and the key lines 3272-3273) with:
        # Proxy-aware identity: forwarding headers count only from a trusted proxy.
        # NOTE: IP-only lockout is bypassable behind a shared NAT; see issue M-3.
        client_ip = self._client_source_ip(request)
```
**Why**: `_client_source_ip` already implements the trusted-proxy rule and the
`"unknown"` fallback, so the lockout and DCR limiters share one identity.

### `tests/test_device_verification.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'provider = Oauth2Provider.__new__(Oauth2Provider)' tests/test_device_verification.py -> first one is inside _make_provider, line 110)
# AFTER `provider.device_uri = "/oauth2/device"` (line 112) add:
    provider._trusted_proxies = set()
```

### FILL IN checklist
- [ ] Spoofing test — AC-1.
- [ ] Trusted-proxy test — AC-2.

---

## Acceptance Criteria

- [ ] AC-1: An invalid `user_code` POST from untrusted peer `127.0.0.1` carrying `X-Forwarded-For: 198.51.100.23` records the attempt under `oauth2:device:attempts:127.0.0.1` (fake `device_code_storage.redis` recording `incr` keys).
- [ ] AC-2: With `provider._trusted_proxies = {ip_address("10.0.0.1")}`, the same POST from peer `10.0.0.1` carrying `X-Forwarded-For: 203.0.113.7` records under `oauth2:device:attempts:203.0.113.7`.
- [ ] Existing tests in `tests/test_device_verification.py` and `tests/test_oauth2_dcr.py` pass.
- [ ] No lint errors on the touched files.

---

## Validation Commands

- `pytest tests/test_device_verification.py -q`
- `pytest tests/test_oauth2_dcr.py -q`

---

## Test Specification

```python
# tests/test_device_verification.py — append
from ipaddress import ip_address


class _RecordingRedis:
    def __init__(self):
        self.incr_keys = []

    async def exists(self, key):
        return 0

    async def incr(self, key):
        self.incr_keys.append(key)
        return 1

    async def expire(self, key, ttl):
        return True

    async def set(self, key, value, ex=None):
        return True

    async def delete(self, key):
        return 1


@pytest.mark.asyncio
async def test_device_lockout_ignores_spoofed_forwarded_for():
    # FILL IN: provider with MemoryDeviceCodeStorage + store.redis = _RecordingRedis();
    # request = _make_post_request({"action": "approve", "user_code": "XXXXXXXX"});
    # request.headers = {"X-Forwarded-For": "198.51.100.23"};
    # await provider.device_verification(request);
    # assert store.redis.incr_keys == ["oauth2:device:attempts:127.0.0.1"]
    ...


@pytest.mark.asyncio
async def test_device_lockout_honours_trusted_proxy():
    # FILL IN: as above, provider._trusted_proxies = {ip_address("10.0.0.1")},
    # remote="10.0.0.1", X-Forwarded-For "203.0.113.7";
    # assert incr_keys == ["oauth2:device:attempts:203.0.113.7"]
    ...
```

---

## Agent Instructions

1. Work in the brief worktree `.claude/worktrees/hotfix-limiter-client-ip-limiter-client-ip` — never on `main`.
2. Read the brief at `sdd/briefs/limiter-client-ip.brief.md`.
3. Verify the Codebase Contract before writing code (line numbers shift if task 1 landed first; re-anchor by the quoted text).
4. Mark this task `in-progress` in `sdd/briefs/limiter-client-ip.index.json` and commit only that file.
5. Implement from the blueprint; complete every `FILL IN`.
6. Run the Validation Commands.
7. Commit only the files listed above.
8. Close the task with `parrot sdd task close HOTFIX-limiter-client-ip-2 limiter-client-ip verified`, then fill in the Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
