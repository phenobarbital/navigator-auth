# TASK-129: MFA package foundation — types, settings, provider ABC, MfaSignal exceptions

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

First task of FEAT-106. It lays down everything the other nineteen tasks import,
and contains **no I/O at all**:

- **Spec §3 Module 1** — the frozen Pydantic v2 models and enums of spec §2
  "Data Models", plus the `AUTH_BASIC_2FA_ENABLED` / `AUTH_OTP_*` settings block.
- **Spec §3 Module 3, ABC half only** — `AbstractOTPProvider`. Moved here so the
  TOTP (TASK-136), e-mail (TASK-137) and backup-code (TASK-134) providers can be
  written in parallel (**decomposition decision D3**).
- **Spec §3 Module 9, exception half only** — `MFARequired`, plus the base
  `MfaSignal` and the fail-closed `MFARefused` (**D1, D2**). The hook that raises
  them stays in TASK-138; the three `auth.py` catch sites are TASK-139.

### Decomposition decisions this task implements (from the FEAT-106 task contract)

- **D1 — `MfaSignal` base exception.** Spec §7 R2 explains why `MFARequired`
  must be caught *before* api_login's `except (AuthException, …): continue`:
  otherwise the loop tries the next backend, which may accept the same
  credentials and mint a session with no second factor. **The same is true of
  every other terminal outcome of the hook** — a fail-closed refusal (Redis down,
  tables missing, enforced superuser without a strong factor) raised as a plain
  `AuthException` would be swallowed identically and become a bypass. So all of
  them share one base, `MfaSignal(AuthException)`, which TASK-139 catches:
  - `MFARequired(MfaSignal)` — 401, the challenge envelope. Keeps **exactly**
    the spec signature and payload.
  - `MFARefused(MfaSignal)` — fail-closed refusal with an error code:
    `strong_factor_required` (403), `no_factor_available` (403),
    `mfa_unavailable` (503).
- **D2** — the exception classes live here (not in TASK-138) because
  `navigator_auth/mfa/__init__.py` re-exports them and later modules
  (`state.py`, the stores) raise `MFARefused` / `MfaStorageError`.
- **D3** — `AbstractOTPProvider` lives here.
- **D4 — ABC compatible extensions.** `verify(..., challenge: Optional[MfaChallenge] = None)`
  (the e-mail provider cannot verify without the challenge's `email_code_hash`),
  `confirm_enrollment(..., *, conn: Any = None)` and `disenroll(..., *, conn: Any = None)`
  (the handler runs them inside the per-user lock transaction, D17). The
  positional signatures of spec M3 are unchanged.
- **D5 — refined AC5 grep.** Spec AC5 greps `remember\|create_token\|open_session`
  under `navigator_auth/mfa/`, but the spec-mandated field
  `TenantMfaPolicy.remember_days` (defined in THIS task) makes that literal grep
  fail forever. The refined, binding check is:
  `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` → **no output**.
  Consequence for this task and every later one: **no file under
  `navigator_auth/mfa/` may contain the text `open_session`, `create_token` or
  `remember(` — not in code, not in a docstring, not in a comment.** The spec's
  own M3 docstring ("it holds no reference to remember() or create_token()")
  must be reworded ("it holds no reference to the session-minting methods").
  This task adds a regression test that enforces it for the whole package.
- **D6 — notification channel.** Downgrades must "notify the user" (spec M10)
  but the spec names no channel, and `AUTH_OTP_EMAIL_CALLBACK` carries a live
  code. Add the optional setting `AUTH_MFA_NOTIFY_CALLBACK` and the frozen model
  `MfaSecurityNotice`. (The invoking code is TASK-137's `mfa/notify.py`.)
- **D13 — `AUTH_OTP_SECRET` has no fallback.** Spec M1 says "required when
  enabled". Unlike `AUTH_RECOVERY_SECRET` (`conf.py:623-627`), it does **not**
  fall back to `SECRET_KEY`; an unset/empty value becomes `None`, and TASK-138
  then marks MFA unavailable and refuses BasicAuth logins (never hard-fails startup).

### One hardening beyond the spec's literal model (record it in the Completion Note)

`MfaChallenge.email_code_hash` is declared `Field(default=None, repr=False)`.
The spec writes `Optional[str] = None`. The value is `sha256` of a **6-digit**
code — 10⁶ candidates — so a hash that reaches a log line *is* the code. AC14
("codes … are never logged") therefore requires it out of `repr()`. Type,
default and serialization are unchanged.

---

## Scope

- Create the package `navigator_auth/mfa/` with `__init__.py`, `types.py`,
  `exceptions.py`, `abstract.py`.
- Append `MfaSignal`, `MFARequired`, `MFARefused` to `navigator_auth/exceptions.py`.
- Insert the FEAT-106 settings block into `navigator_auth/conf.py`, immediately
  before `## Audit Backend`.
- Write `tests/test_mfa_types.py`, including the package-wide D5 regression test.

**NOT in scope**: any Redis/Postgres/vault access (TASK-130..137); provider
implementations (TASK-134/136/137); the `BasicAuth` hook (TASK-138); catching
`MfaSignal` in `auth.py` (TASK-139); SQL; docs (TASK-148). Do **not** touch
`pyproject.toml` (AC4: no new dependency).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/exceptions.py` | MODIFY | Append `MfaSignal`, `MFARequired`, `MFARefused` |
| `navigator_auth/conf.py` | MODIFY | FEAT-106 settings block before `## Audit Backend` |
| `navigator_auth/mfa/__init__.py` | CREATE | Public exports (exactly seven names) |
| `navigator_auth/mfa/types.py` | CREATE | Frozen Pydantic v2 models, enums, constants, cookie helper |
| `navigator_auth/mfa/exceptions.py` | CREATE | Re-exports + internal `MfaStorageError` |
| `navigator_auth/mfa/abstract.py` | CREATE | `AbstractOTPProvider` |
| `tests/test_mfa_types.py` | CREATE | Models, exceptions, ABC, settings, D5 regression |

---

## Codebase Contract

> Verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field     # pydantic 2.13.4 installed; pyproject.toml:56 "pydantic>=2.12.5"
from aiohttp import web                                # used throughout, e.g. navigator_auth/backends/basic.py:10
from navigator_auth.exceptions import AuthException    # navigator_auth/exceptions.py:3
# conf.py already has: from navconfig import config, BASE_DIR   (navigator_auth/conf.py:11)
```

### Existing signatures

```python
# navigator_auth/exceptions.py:3-23
class AuthException(Exception):
    status: int = 400
    def __init__(self, message: str, status: int = 400, **kwargs):
        super().__init__(message)          # args == (message,)
        self.stacktrace = None
        ...
        self.message = message
        self.status = status
    def __repr__(self): return f"{self.message}"
    def __str__(self):  return f"{self.message}"
    def get(self): return self.message
# House style for subclasses (exceptions.py:32-60): `def __init__(self, message: str = None, status=NNN)`.
# Last class in the file — the append anchor:
class AuthExpired(AuthException):          # exceptions.py:57  (grep -cF → 1)
    def __init__(self, message: str = None, status=410): ...
```

```python
# navigator_auth/conf.py — recovery block and the insertion anchor
AUTH_RECOVERY_SECRET = config.get("AUTH_RECOVERY_SECRET")          # :623 — pattern for str→bytes coercion (:626-627)
...
    AUTH_RECOVERY_CALLBACK = FORGOT_PASSWORD_CALLBACK                # :655 — end of the recovery block
## Audit Backend                                                     # :657 (grep -cF → 1)  ← insert BEFORE this line
```

### Facts that constrain this task

- **Import-cycle safety.** `navigator_auth/__init__.py` imports `.auth`
  (`AuthHandler`), so *any* `import navigator_auth.mfa…` first runs the whole
  package init (auth.py → handlers → backends). TASK-138 will make
  `backends/basic.py` import `navigator_auth.mfa.services`. Therefore the four
  modules created here may import **only**: stdlib, `pydantic`, `aiohttp`,
  `navigator_auth.exceptions`, `navigator_auth.conf`. Never `navigator_auth.auth`,
  `navigator_auth.backends`, `navigator_auth.handlers`.
- Pydantic: `Field(repr=False)` excludes a field from `repr()`/`str()` but **not**
  from `model_dump()`; the spec forbids logging `model_dump()` of secret-bearing models.
- Pydantic v2 accepts a defaulted field before a required one (unlike dataclasses),
  so the spec's `MfaChallenge` field order (`email_code_hash` default, then
  required `signature`) is legal as written.
- `aiohttp` `Response.set_cookie(name, value, *, max_age, path, secure, httponly, samesite, …)`
  — `trusted_cookie_kwargs()` returns kwargs for exactly that call (consumed by TASK-139).

### Does NOT Exist (Anti-Hallucination)

- ~~`navigator_auth/mfa/`~~ — created by this task (verified absent).
- ~~`MfaSignal`, `MFARequired`, `MFARefused`, `MfaStorageError`~~ — none exist (verified grep).
- ~~`AUTH_BASIC_2FA_ENABLED`, `AUTH_OTP_*`, `AUTH_TOTP_ISSUER`, `AUTH_MFA_*`~~ — not in `conf.py`.
- ~~`User.email_verified`~~ — no such column; do not model it.
- ~~`pyotp`, `qrcode`, `fakeredis`~~ — not installed, must not be added.
- ~~A `StrEnum` convention in this codebase~~ — use `class X(str, Enum)` exactly as spec §2.

---

## Implementation Blueprint

### `navigator_auth/exceptions.py` — MODIFY (append at end of file)

```python
# AFTER — append below the last class, `class AuthExpired(AuthException):`
# (verified: navigator_auth/exceptions.py:57)
# occurrences: 1 (verified: grep -cF 'class AuthExpired(AuthException):' navigator_auth/exceptions.py)


#### Second factor (FEAT-106)
class MfaSignal(AuthException):
    """Terminal outcome of the BasicAuth second-factor hook (FEAT-106, D1).

    Raised from ``BasicAuth.authenticate()`` after the password was accepted.
    Every caller MUST catch it BEFORE any generic ``AuthException`` handler and
    MUST NOT try another backend: ``api_login``'s
    ``except (AuthException, ...): continue`` would otherwise let the next
    backend authenticate the same credentials with no second factor (spec R2).
    """

    def payload(self) -> dict:
        """JSON body of the HTTP response. Never carries a token or session id."""
        raise NotImplementedError


class MFARequired(MfaSignal):
    """Credentials valid; a second factor is owed. Carries NO session material."""

    def __init__(
        self,
        challenge: str,
        providers: list[str],
        preferred: str,
        expires_in: int,
        status: int = 401,
    ):
        # The message is fixed so str()/repr()/tracebacks never show the token.
        super().__init__("Second factor required", status=status)
        self._challenge = challenge
        self.providers = list(providers)
        self.preferred = preferred
        self.expires_in = int(expires_in)

    def payload(self) -> dict:
        """``{'mfa_required': True, 'challenge', 'providers', 'preferred', 'expires_in'}``."""
        return {
            "mfa_required": True,
            "challenge": self._challenge,
            "providers": list(self.providers),
            "preferred": self.preferred,
            "expires_in": self.expires_in,
        }


class MFARefused(MfaSignal):
    """The MFA layer refused the login (fail closed). Carries NO session material."""

    STRONG_FACTOR_REQUIRED = "strong_factor_required"   # 403 — enforced superuser without TOTP/passkey
    NO_FACTOR_AVAILABLE = "no_factor_available"         # 403 — factor owed, none usable
    MFA_UNAVAILABLE = "mfa_unavailable"                 # 503 — an MFA dependency failed

    def __init__(self, code: str, message: str = None, status: int = 403):
        super().__init__(message or code, status=status)
        self.code = code

    def payload(self) -> dict:
        """``{'error': code, 'message': message}``."""
        return {"error": self.code, "message": self.message}
```

**Why** a base class instead of the spec's single `MFARequired`: see D1 — R2 is
not specific to the challenge; it is a property of *any* exception that leaves
`BasicAuth.authenticate()` after the password check. One base gives TASK-139 one
`except MfaSignal` clause that cannot forget a subclass. **Why** the fixed message
and the private `_challenge`: `Exception.args` is what tracebacks print; keeping
the raw challenge token out of `args` keeps it out of every `logger.exception`.
**Why** `message: str = None`: house style of every other class in this file.

### `navigator_auth/mfa/exceptions.py` — CREATE

```python
"""MFA exceptions (FEAT-106).

``MfaSignal`` / ``MFARequired`` / ``MFARefused`` are defined in
``navigator_auth.exceptions`` (next to ``AuthException``, which every caller
already imports) and re-exported here for ``navigator_auth.mfa`` users.
"""
from navigator_auth.exceptions import MFARefused, MFARequired, MfaSignal

__all__ = ("MfaSignal", "MFARequired", "MFARefused", "MfaStorageError")


class MfaStorageError(Exception):
    """Internal: an MFA dependency (Redis, Postgres, vault) failed.

    Never shown to a client. The BasicAuth hook and the MFA handlers translate
    it to ``MFARefused('mfa_unavailable', status=503)`` — "component
    unavailable" must mean "login refused", never "factor skipped" (spec R5).
    The message must never contain a code, token, seed or password verifier.
    """
```

**Why** `MfaStorageError` is not an `AuthException`: it must never be caught by
a generic auth handler and turned into a 4xx by accident; only MFA-aware code
translates it, explicitly, to `MFARefused`.

### `navigator_auth/mfa/types.py` — CREATE (block 1 of 2: enums, constants, base, policy, challenge)

```python
"""FEAT-106 MFA data structures — frozen Pydantic v2 models, no I/O.

Import rule: stdlib + pydantic only (see the package import-cycle note).
"""
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

# --- constants (FEAT-106 task contract §2) ---------------------------------
MFA_VAULT_PREFIX = "mfa:"                 # reserved auth.user_vault_secrets namespace (TASK-143)
PROVIDER_TOTP, PROVIDER_EMAIL, PROVIDER_BACKUP = "totp", "email", "backup"
AMR_PASSWORD, AMR_TRUSTED_DEVICE = "pwd", "trusted_device"
AMR_BY_PROVIDER = {"email": "otp", "totp": "totp", "backup": "backup"}   # D11
NO_TENANT_ORG_ID = 0                      # D8: "no tenant policy applies", never a global policy
TRUSTED_COOKIE = "nav_mfa_device"         # spec M6
MFA_DEVICE_TOKEN_KEY = "_mfa_trusted_device"   # D14: transient login-dict key, popped by finalize_login()


class MfaModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class MfaState(str, Enum):
    """Per-user second-factor state. The floor in an enforced tenant is EMAIL."""
    NONE = "none"
    EMAIL = "email"
    TOTP = "totp"


class MfaMode(str, Enum):
    """Per-tenant policy mode. OFF is also the absence of a policy row."""
    OFF = "off"
    OPTIONAL = "optional"
    ENFORCED = "enforced"


MODE_STRICTNESS = {MfaMode.OFF: 0, MfaMode.OPTIONAL: 1, MfaMode.ENFORCED: 2}   # D9


class TenantMfaPolicy(MfaModel):
    org_id: int
    mode: MfaMode
    remember_days: int            # 0 disables remember-me for the tenant
    enforced_at: Optional[datetime]
    enforced_by: Optional[str]


class MfaChallenge(MfaModel):
    """Redis-persisted challenge record. Keyed by sha256(token), never the token."""
    user_id: int
    username: str
    providers: tuple[str, ...]    # what THIS user may use
    preferred: str
    issued_at: float
    security_version: int         # auth.user_mfa_security.version at issuance
    context_digest: str           # keyed digest of current security inputs
    # repr=False: sha256 of a 6-digit code is the code (AC14). See task Context.
    email_code_hash: Optional[str] = Field(default=None, repr=False)
    signature: str                # HMAC-SHA256 over canonical immutable fields above
    # Attempts are separate atomic Redis state, not part of the signed payload.
```

### `navigator_auth/mfa/types.py` — CREATE (block 2 of 2: payloads, enrolment, audit, notice, evaluation, helper)

```python
class OtpNotificationPayload(MfaModel):
    """Hand-off to AUTH_OTP_EMAIL_CALLBACK. The only place a live code appears."""
    email: str
    display_name: str
    username: str
    code: str = Field(repr=False)  # never in an HTTP response, never in a log
    expires_at: datetime
    found: bool                   # False => no such account; callback decides
    # repr excludes code; logging model_dump()/JSON is prohibited.


class EnrollmentAuthorization(MfaModel):
    """Internal proof constructed by the handler after fresh authentication.
    Never deserialize this from a client-supplied object."""
    user_id: int
    session_id: str = Field(repr=False)
    security_version: int
    context_digest: str
    expires_at: datetime


class TrustedDevice(MfaModel):
    user_id: int
    token_hash: str               # sha256 of the cookie value
    label: str
    family_id: str                # rotation chain; replay revokes the family
    expires_at: datetime
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]


class PendingEnrollment(MfaModel):
    """Redis-persisted pending TOTP enrolment; attempts are separate Redis state."""
    user_id: int
    session_hash: str
    security_version: int
    sealed_seed: str = Field(repr=False)   # base64 of the pending-context ciphertext
    issued_at: float
    signature: str


class MfaAuditEntry(MfaModel):
    """One durable auth.user_mfa_audit row (spec M8; not abac AuditLog)."""
    actor_user_id: Optional[int]
    target_user_id: Optional[int]   # NULL for tenant-policy rows (D18)
    org_id: Optional[int]
    action: str
    old_state: Optional[str] = None
    new_state: Optional[str] = None
    method: Optional[str] = None
    request_id: Optional[str] = None
    outcome: str
    detail: dict = Field(default_factory=dict)


class MfaSecurityNotice(MfaModel):
    """Hand-off to AUTH_MFA_NOTIFY_CALLBACK (D6). Carries no secret."""
    email: Optional[str]
    display_name: str
    username: str
    event: str
    occurred_at: datetime
    actor: Optional[str] = None


class MfaEvaluation(MfaModel):
    """One consistent snapshot used to issue AND to re-validate a challenge."""
    user_id: int
    policy: TenantMfaPolicy
    memberships: tuple[int, ...]
    state: MfaState
    has_strong_factor: bool
    totp_confirmed: bool
    providers: tuple[str, ...]
    preferred: Optional[str]
    security_version: int
    context_digest: str


def trusted_cookie_kwargs(max_age: int) -> dict:
    """``set_cookie`` kwargs for TRUSTED_COOKIE: HttpOnly, Secure, SameSite=Lax (spec M6)."""
    # FILL IN: return {"max_age": int(max_age), "httponly": True, "secure": True,
    #          "samesite": "Lax", "path": "/"} — bounded by spec M6 cookie
    #          attributes; reject max_age <= 0 with ValueError (a zero/negative
    #          window means "do not issue", which is the caller's decision).
```

**Why** two blocks: the 80-line cap; it is one file. **Why** the models are
copied verbatim from spec §2 (except `email_code_hash`'s `repr=False`): their
field names are the wire/Redis format of TASK-131 and the audit columns of
TASK-130. **Why** `MfaEvaluation` exists: TASK-138 computes it once to *issue* a
challenge and again under the lock to *re-validate* it (spec "Challenge validity
and invalidation"); one model guarantees both sides compare the same fields.

### `navigator_auth/mfa/abstract.py` — CREATE

```python
"""AbstractOTPProvider — the second-factor contract (FEAT-106, spec M3).

Import rule: stdlib + aiohttp + .types only.
"""
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, Optional

from aiohttp import web

from .types import EnrollmentAuthorization, MfaChallenge


class AbstractOTPProvider(ABC):
    """A second factor. Deliberately NOT a ``BaseAuthBackend``.

    ``BaseAuthBackend.authenticate()``'s contract is to produce a session
    (navigator_auth/backends/abstract.py:64), so a provider registered as a
    backend would make the second factor sufficient on its own. A provider only
    ever answers a question with a bool or a dict; it holds no reference to the
    session-minting methods of any backend.
    """

    _provider_name: str            # "totp" | "email" | "backup"
    _is_strong: bool               # closes the e-mail path when enrolled

    @property
    def name(self) -> str:
        """Provider name, one of ``PROVIDER_TOTP/EMAIL/BACKUP``."""
        return self._provider_name

    @property
    def is_strong(self) -> bool:
        """True when an enrolment of this provider closes the e-mail path."""
        return self._is_strong

    @abstractmethod
    async def is_enrolled(self, user: Mapping) -> bool:
        """True when ``user`` can answer this provider right now."""

    @abstractmethod
    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """Provider-specific enrolment payload (TOTP: the otpauth:// URI)."""

    @abstractmethod
    async def confirm_enrollment(
        self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None
    ) -> bool:
        """Enrolment completes only on a working code. ``conn``: the caller's
        lock transaction (D4, D17) — providers never lock, bump or audit."""

    @abstractmethod
    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        """Deliver/prepare. TOTP: a no-op. E-mail: hands off to the callback."""

    @abstractmethod
    async def verify(
        self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None
    ) -> bool:
        """True when ``code`` is valid. ``challenge`` is the verified record (D4)."""

    @abstractmethod
    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        """Remove this provider's enrolment inside the caller's transaction."""
```

**Why** the docstring is reworded from the spec: D5 — the literal spec wording
contains `remember()` / `create_token()` and would trip the refined AC5 grep.
**Why** keyword-only `conn`: D4 — positional spec signatures stay intact for any
caller written against the spec.

### `navigator_auth/mfa/__init__.py` — CREATE

```python
"""Second-factor (OTP) support for BasicAuth (FEAT-106).

Providers are owned by BasicAuth and never mint a session themselves.
"""
from .abstract import AbstractOTPProvider
from .exceptions import MFARefused, MFARequired, MfaSignal
from .types import MfaMode, MfaState, TenantMfaPolicy

__all__ = (
    "AbstractOTPProvider",
    "MfaState",
    "MfaMode",
    "TenantMfaPolicy",
    "MFARequired",
    "MFARefused",
    "MfaSignal",
)
```

**Why** exactly these seven: contract §3 — no later task edits this file, so the
public surface is fixed now and parallel tasks never collide on it.

### `navigator_auth/conf.py` — MODIFY (insert a block)

```python
# BEFORE — insert immediately above `## Audit Backend` (verified: navigator_auth/conf.py:657),
# i.e. after the FORGOT_PASSWORD_CALLBACK shim that ends at :655.
# occurrences: 1 (verified: grep -cF '## Audit Backend' navigator_auth/conf.py)

## Two-factor authentication for BasicAuth (FEAT-106).
# Global kill switch. The per-tenant policy is DATA (auth.tenant_mfa_policy),
# not configuration. False => the login path is byte-identical (AC20).
AUTH_BASIC_2FA_ENABLED = config.getboolean("AUTH_BASIC_2FA_ENABLED", fallback=False)
# HMAC key for challenge records, context digests and backup-code hashes.
# REQUIRED when enabled; deliberately NO fallback to SECRET_KEY (spec M1, D13).
AUTH_OTP_SECRET = config.get("AUTH_OTP_SECRET")
if isinstance(AUTH_OTP_SECRET, str):
    AUTH_OTP_SECRET = AUTH_OTP_SECRET.encode("utf-8")
if not AUTH_OTP_SECRET:
    AUTH_OTP_SECRET = None
# Challenge lifetime (seconds) and failed-attempt budget per challenge.
AUTH_OTP_CHALLENGE_TTL = config.getint("AUTH_OTP_CHALLENGE_TTL", fallback=300)
AUTH_OTP_MAX_ATTEMPTS = config.getint("AUTH_OTP_MAX_ATTEMPTS", fallback=5)
# Digits in an e-mail OTP code.
AUTH_OTP_CODE_LENGTH = config.getint("AUTH_OTP_CODE_LENGTH", fallback=6)
# Verify/resend limits, "<count>/<window>" (backends/oauth2/dcr.py:parse_rate_limit).
AUTH_OTP_RATE_USER = config.get("AUTH_OTP_RATE_USER", fallback="10/hour")
AUTH_OTP_RATE_IP = config.get("AUTH_OTP_RATE_IP", fallback="30/hour")
# Dotted path to the e-mail OTP delivery callable (navigator-auth never sends e-mail).
AUTH_OTP_EMAIL_CALLBACK = config.get("AUTH_OTP_EMAIL_CALLBACK")
# Issuer label shown by authenticator apps.
AUTH_TOTP_ISSUER = config.get("AUTH_TOTP_ISSUER", fallback="Navigator")
# Backup codes: how many, and how long each one is.
AUTH_MFA_BACKUP_CODE_COUNT = config.getint("AUTH_MFA_BACKUP_CODE_COUNT", fallback=10)
AUTH_MFA_BACKUP_CODE_LENGTH = config.getint("AUTH_MFA_BACKUP_CODE_LENGTH", fallback=8)
# Optional dotted path receiving an MfaSecurityNotice on factor downgrades (D6).
AUTH_MFA_NOTIFY_CALLBACK = config.get("AUTH_MFA_NOTIFY_CALLBACK")

```

**Why** names and defaults are verbatim from spec M1 (plus D6's one setting):
they are referenced by name in TASK-131..148. **Why** the empty-string guard:
`config.get` can return `""` for a declared-but-empty variable; `b""` is not a
usable HMAC key and must read as "unset" (D13).

### `tests/test_mfa_types.py` — CREATE

```python
"""FEAT-106 TASK-129 — MFA models, exceptions, provider ABC, settings."""
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from navigator_auth import conf
from navigator_auth.exceptions import AuthException, MFARefused, MFARequired, MfaSignal
from navigator_auth.mfa import AbstractOTPProvider, MfaMode, MfaState, TenantMfaPolicy
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import (
    MfaChallenge, OtpNotificationPayload, trusted_cookie_kwargs,
)

MFA_PKG = Path(__file__).resolve().parents[1] / "navigator_auth" / "mfa"
FORBIDDEN = re.compile(r"remember\(|create_token|open_session")


def test_mfa_models_frozen_and_redacted():
    """Spec §4 M1 (AC34): mutation and extra fields rejected; secrets not in repr."""
    # FILL IN: build a TenantMfaPolicy; assert assignment raises ValidationError;
    #  assert TenantMfaPolicy(..., extra_field=1) raises ValidationError;
    #  assert the code of an OtpNotificationPayload and the email_code_hash of an
    #  MfaChallenge are absent from repr() and str() — bounded by AC14, AC34.


def test_notification_payload_repr_redacted():
    """Spec §4 M4 row (model lives here): repr() shows no code."""
    # FILL IN: code "493817" must not appear in repr(payload) — AC14.


def test_mfa_required_payload_has_no_token():
    """Spec §4 M9 row: payload carries no token / refresh_token / session id."""
    # FILL IN: err = MFARequired("chal-tok", ["email"], "email", 300);
    #  assert set(payload) == {"mfa_required","challenge","providers","preferred","expires_in"};
    #  assert "chal-tok" not in str(err) and not in repr(err) and not in err.args;
    #  assert err.status == 401 — AC6.


def test_mfa_signal_hierarchy():
    # FILL IN: MFARequired/MFARefused are MfaSignal and AuthException;
    #  MfaStorageError is NOT an AuthException (D1).


def test_mfa_refused_payload_and_status():
    # FILL IN: MFARefused("mfa_unavailable", status=503).payload() ==
    #  {"error": "mfa_unavailable", "message": "mfa_unavailable"}; status 503.


def test_abstract_provider_contract():
    # FILL IN: AbstractOTPProvider() raises TypeError; a minimal subclass
    #  implementing all six methods instantiates and exposes .name/.is_strong.


def test_trusted_cookie_kwargs():
    # FILL IN: attributes exactly per spec M6; max_age <= 0 -> ValueError.


def test_settings_defaults_and_types():
    # FILL IN: AUTH_BASIC_2FA_ENABLED is a bool; AUTH_OTP_SECRET is None or bytes
    #  (never str, never b""); numeric settings are ints — D13, spec M1.


def test_no_session_minting_text_in_mfa_package():
    """D5 — the refined AC5 grep, enforced for the whole package forever."""
    offenders = [
        f"{path.relative_to(MFA_PKG.parent.parent)}:{n}"
        for path in sorted(MFA_PKG.rglob("*"))
        if path.is_file() and path.suffix in {".py", ".sql"}
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if FORBIDDEN.search(line)
    ]
    assert offenders == [], offenders
```

**Why** the D5 test lives here and scans `rglob`: every later task that adds a
file to `navigator_auth/mfa/` is automatically covered by this test, so the
"providers can never reach a session" property (spec G2) stays checked without
anyone remembering to grep.

### Steps (in order)

1. `ls navigator_auth/mfa` must fail (package absent). Confirm the two anchors:
   `grep -cF 'class AuthExpired(AuthException):' navigator_auth/exceptions.py` → 1,
   `grep -cF '## Audit Backend' navigator_auth/conf.py` → 1.
2. Append the three exception classes to `navigator_auth/exceptions.py` — do
   this first, because `mfa/exceptions.py` re-exports them.
3. Insert the settings block in `conf.py` — the ABC and models do not need it,
   but TASK-130/131 import it immediately after.
4. Create `mfa/types.py` (both blocks, one file), then `mfa/exceptions.py`,
   `mfa/abstract.py`, `mfa/__init__.py` — in that order, because each imports the previous.
5. Fill `trusted_cookie_kwargs`.
6. Write `tests/test_mfa_types.py`; fill every `FILL IN` body.
7. Run the Test Specification commands. Then the import smoke test:
   `python -c "import navigator_auth; from navigator_auth.mfa import MFARequired"` —
   proves no import cycle with the package init.
8. `git diff --stat` must list only the seven files above (AC4: `pyproject.toml` untouched).

### FILL IN checklist

- [ ] `trusted_cookie_kwargs` body + `ValueError` on `max_age <= 0` — spec M6
- [ ] `test_mfa_models_frozen_and_redacted` — AC14, AC34
- [ ] `test_notification_payload_repr_redacted` — AC14
- [ ] `test_mfa_required_payload_has_no_token` — AC6
- [ ] `test_mfa_signal_hierarchy` — D1
- [ ] `test_mfa_refused_payload_and_status` — D1
- [ ] `test_abstract_provider_contract` — D3, D4
- [ ] `test_trusted_cookie_kwargs` — spec M6
- [ ] `test_settings_defaults_and_types` — D13, spec M1

---

## Acceptance Criteria

- [ ] **AC-1** `navigator_auth/mfa/` exists with exactly `__init__.py`, `types.py`, `exceptions.py`, `abstract.py`; `from navigator_auth.mfa import AbstractOTPProvider, MfaState, MfaMode, TenantMfaPolicy, MFARequired, MFARefused, MfaSignal` works after `import navigator_auth` (no import cycle).
- [ ] **AC-2** Every model is a frozen Pydantic v2 model with `extra="forbid"`; `OtpNotificationPayload.code`, `MfaChallenge.email_code_hash`, `EnrollmentAuthorization.session_id`, `PendingEnrollment.sealed_seed` never appear in `repr()`/`str()` (closes spec **AC34**, part of **AC14**).
- [ ] **AC-3** `MFARequired(...).payload()` has exactly the five spec keys and no token/refresh_token/session id; the challenge token is absent from `str()`, `repr()` and `.args` (part of spec **AC6**).
- [ ] **AC-4** `MFARequired` and `MFARefused` subclass `MfaSignal`, which subclasses `AuthException`; `MfaStorageError` does not subclass `AuthException` (D1).
- [ ] **AC-5** `conf.py` defines the twelve settings with spec defaults; `AUTH_BASIC_2FA_ENABLED` defaults to `False`; `AUTH_OTP_SECRET` is `None` or non-empty `bytes`, with no `SECRET_KEY` fallback (D13).
- [ ] **AC-6** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` prints nothing, and `test_no_session_minting_text_in_mfa_package` passes (D5, refined spec **AC5**).
- [ ] **AC-7** `pyproject.toml` unchanged (spec **AC4**).
- [ ] **AC-8** `pytest tests/test_mfa_types.py -v` passes; `ruff check navigator_auth/mfa navigator_auth/exceptions.py tests/test_mfa_types.py` is clean; `pytest tests/test_basic_auth.py -q` still passes.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_types.py -v
pytest tests/test_basic_auth.py -q                      # regression: exceptions.py/conf.py edits
ruff check navigator_auth/mfa navigator_auth/exceptions.py tests/test_mfa_types.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1
python -c "import navigator_auth; from navigator_auth.mfa import MFARequired, MfaSignal"
```

Spec §4 rows owned (fully or partly) by this task: `test_mfa_models_frozen_and_redacted` (M1),
`test_notification_payload_repr_redacted` (M4, model half), `test_mfa_required_payload_has_no_token` (M9, payload half).

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §2 Data Models and New Public
   Interfaces, §3 M1, M3 (ABC), M9 (exception), §7 R2, AC5/AC6/AC14/AC34.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Keep the D5 rule in mind for every docstring you write under `navigator_auth/mfa/`.
5. **Verify** every acceptance criterion, AC-1 import smoke test included.
6. **Move this file** to `sdd/tasks/completed/TASK-129-mfa-foundation.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below (record the `email_code_hash` `repr=False` hardening).

---

## Completion Note

**Completed by**: gpt-5.6-terra (codex), 1 attempt, branch merge 2011216
**Date**: 2026-11-11
**Notes**: Delivered navigator_auth/mfa/{__init__,types,exceptions,abstract}.py, MfaSignal/MFARequired/MFARefused in exceptions.py, 12 settings in conf.py, tests/test_mfa_types.py. Merge-tier validation green (14 passed incl. TASK-145 tests). AC-6 grep empty; pyproject.toml unchanged. tests/test_basic_auth.py could not run in the sandbox (Postgres connection refused) — environmental, re-check in CI. ruff not installed in the shared venv, so AC-8 lint check was not run; engine black autofix applied (0c46189).

**Deviations from spec**: `MfaSignal`/`MFARefused` (D1), ABC kwargs (D4), `AUTH_MFA_NOTIFY_CALLBACK` + `MfaSecurityNotice` (D6), `email_code_hash` `repr=False` — all pre-recorded decisions; list anything else here.
