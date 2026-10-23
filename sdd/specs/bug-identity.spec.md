---
type: feature
base_branch: dev
---

# Feature Specification: Identity-Link Failure — Non-Nullable Token Columns and Unsafe Error Headers

**Feature ID**: FEAT-104
**Date**: 2026-10-23
**Author**: Jesus Lara
**Status**: approved
**Target version**: next patch on `dev`

---

## 1. Motivation & Business Requirements

### Problem Statement

Running `python examples/identity_vault_server.py` and clicking **Link Github**
fails. The OAuth2 round-trip succeeds (GitHub returns `200` from
`https://api.github.com/user`), but persisting the linked identity raises:

```
datamodel.exceptions.ValidationError: UserIdentity: There are errors in Model.
(Fields with errors: refresh_token, id_token)
```

and the error handler that should have redirected the browser instead crashes
the connection:

```
ValueError: Forbidden control character detected in headers.
Potential header injection attack.
```

Two independent defects stack into one unrecoverable 500.

**Defect A — `UserIdentity` cannot hold a null token.**
`navigator_auth/models.py:100-102` declares the three ciphered credential
columns as bare `bytes`, not `Optional[bytes]`, on a `strict = True` model:

```python
access_token: bytes  = Column(required=False, repr=False)   # models.py:100
refresh_token: bytes = Column(required=False, repr=False)   # models.py:101
id_token: bytes      = Column(required=False, repr=False)   # models.py:102
```

`required=False` only makes the field optional *to supply*; `datamodel` still
runs the `bytes` converter over the resulting `None` and fails with
`Cannot convert None to bytes`. Verified by direct repro on `dev` @ `99ad936`:

| Construction | Result |
|---|---|
| `UserIdentity(user_id=1, auth_provider='g')` | **ValidationError** on all three columns |
| `UserIdentity(..., refresh_token=None, id_token=None, access_token=b'x')` | **ValidationError** on `refresh_token`, `id_token` |
| `UserIdentity(..., access_token=b'a', refresh_token=b'b', id_token=b'c')` | OK |

The blast radius is wider than the GitHub button:

- **Insert path.** `IdentityStore.save_linked_identity` passes `None`
  explicitly for a provider that returns no refresh/id token
  (`store.py:155-160`, then `store.py:194`). GitHub OAuth Apps return neither.
  The `existing` branch at `store.py:179-193` pops those keys, so *re-linking*
  an already-stored account works — only the **first** link of a
  refresh-token-less provider fails. That asymmetry is why the defect looks
  intermittent.
- **Hydration path.** The model is unconstructable without all three columns,
  so `UserIdentity.get()` / `UserIdentity.filter()` raise the same error for
  any pre-FEAT-096 row whose nullable `BYTEA` columns are `NULL`. That breaks
  `IdentityStore.list_for_user`, `get_one` and `get_by_provider` for legacy
  identities, independently of any link attempt.
- The DB schema already permits this — `001_identity_credentials.sql:9-10`
  and `002_identity_id_token.sql:5` declare plain nullable `BYTEA`. The model
  is stricter than the table it maps.

**Defect B — error text is written verbatim into response headers.**
`ExternalAuth.failed_redirect` (`navigator_auth/backends/external.py:347-352`)
builds:

```python
headers = {"x-message": message, "x-error": str(error)}   # external.py:349
```

`message` is unvalidated. When it carries a multi-line `datamodel`
`ValidationError`, aiohttp's `_write_str_raise_on_nlcr` rejects the embedded
`\n` and the whole response dies with `ValueError`, turning a handled,
redirectable failure into an unhandled 500 with no response body. Worse, at
`external.py:799-801` the message is built from `?error` / `?error_description`
— **attacker-controlled query string** — giving a live CRLF header-injection
vector reachable by sending a victim to
`/auth/<provider>/callback/?error=x&error_description=<CRLF payload>`.
`failed_redirect` is the single chokepoint for 22 call sites across
`external.py`, `azure.py`, `adfs.py` and `saml/sp.py`, so every one of them
carries the same exposure.

**Defect C — internal detail leaks to the browser.**
Six call sites interpolate exception or provider text straight into the
user-visible `?message=` query parameter and the `x-message` header
(`external.py:801`, `external.py:819`, `azure.py:282`, `azure.py:322`,
`azure.py:333`, `azure.py:337`). The GitHub trace shows a `datamodel`
stack-adjacent message — ORM internals, model name and field list — being
handed to the browser.

### Goals

- A first-time identity link against a provider that returns no
  `refresh_token` and no `id_token` (GitHub OAuth App) persists and succeeds.
- `UserIdentity` round-trips rows whose `access_token` / `refresh_token` /
  `id_token` columns are `NULL`, matching the nullable `BYTEA` schema.
- No value written into a response header can contain CR, LF, NUL or other
  control characters, regardless of its origin.
- A failure inside the identity-link flow produces the intended redirect to
  the failed-redirect URL, never an unhandled 500.
- Error output reaching the browser is a stable, enumerable code plus a fixed
  human string; the diagnostic detail goes to the log only.

### Non-Goals (explicitly out of scope)

- Changing the on-the-wire shape of the failed redirect (the `?error=` /
  `?message=` parameter names and the `x-error` / `x-message` headers stay).
- Re-wording the 16 `failed_redirect` call sites that already pass a static,
  non-reflective literal (e.g. `message="Missing Auth Nonce"`). The Module 2
  sanitizer already makes them injection-safe; only the six interpolating
  sites in Defect C are rewritten.
- Adding a `NOT NULL` constraint or any DDL change to
  `auth.user_identities`. The table is already correct; the model is wrong.
- Auditing the other `Model` classes in `navigator_auth/models.py` for the
  same non-`Optional` pattern. `UserIdentity` is the only one with `bytes`
  columns (verified: `grep -n ": bytes" navigator_auth/models.py` → lines
  100, 101, 102 only).

---

## 2. Architectural Design

### Overview

Three narrowly-scoped, independent fixes. No new subsystems, no new
dependencies, no schema migration.

1. **Model (`models.py`)** — widen the three credential columns to
   `Optional[bytes]`, so the model agrees with its nullable `BYTEA` columns.
   This alone unblocks the GitHub link.
2. **Transport (`libs/sanitize.py` + `external.py`)** — add a `header_safe()`
   helper and route every value `failed_redirect` puts into a header through
   it. One chokepoint protects all call sites in all backends.
3. **Messaging (`external.py`, `azure.py`)** — the six sites that interpolate
   an exception or a provider-supplied string stop doing so: the detail is
   logged, the browser gets the stable `error` code and a fixed message.

Modules 1 and 2 are independent and may be implemented in parallel. Module 3
depends on Module 2 only for its test fixture (it asserts on the sanitized
output), not for correctness.

### Component Diagram

```
  GitHub callback
        │
        ▼
  ExternalAuth.finish_identity_link            external.py:793
        │                                      ── Module 3: stable message
        ├── exchange_code_for_tokens ──► TokenResponse(refresh_token=None,
        │                                             id_token=None)
        ├── IdentityStore.save_linked_identity  store.py:134
        │        └── UserIdentity(...)          store.py:194
        │                 └──────────────► models.py:100-102
        │                                  ── Module 1: Optional[bytes]
        └── (on failure)
             ExternalAuth.failed_redirect       external.py:347
                     └── header_safe(...) ────► libs/sanitize.py
                                                ── Module 2: strip CR/LF/ctl
```

### Integration Points

| Existing component | Integration type | Notes |
|---|---|---|
| `navigator_auth.models.UserIdentity` | modifies | 3 column type annotations widened to `Optional[bytes]` |
| `navigator_auth.identity.store.IdentityStore` | unchanged | Already passes `None` correctly; becomes functional once the model accepts it |
| `navigator_auth.libs.sanitize` | extends | New `header_safe()` alongside the existing `sanitize_request()` |
| `ExternalAuth.failed_redirect` | modifies | Routes header values through `header_safe()` |
| `ExternalAuth.finish_identity_link` | modifies | Stops reflecting `{err}` / `{error}: {desc}` |
| `AzureAuth` | modifies | 4 call sites stop reflecting `{err}` / `{result}` |
| `ADFSAuth`, `SAMLSP` | unchanged | Inherit the hardened `failed_redirect`; no call-site edits |
| `auth.user_identities` (DDL) | unchanged | Columns are already nullable `BYTEA` |

### Data Models

No new models. The change to the existing one:

```python
# navigator_auth/models.py — UserIdentity, lines 100-102
# BEFORE                                          # AFTER
access_token:  bytes                              access_token:  Optional[bytes]
refresh_token: bytes                              refresh_token: Optional[bytes]
id_token:      bytes                              id_token:      Optional[bytes]
```

`Optional` is already imported at `navigator_auth/models.py` (used by
`scopes`, `auth_data`, `attributes` on the same class). Verified behaviour of
the widened form under `strict = True`:

```python
class T(Model):
    a: Optional[bytes] = Column(required=False, repr=False)
    class Meta:
        strict = True

T(a=None).a   # -> None     (was: ValidationError)
T(a=b'xx').a  # -> b'xx'    (unchanged)
```

### New Public Interfaces

```python
# navigator_auth/libs/sanitize.py  (NEW function in an existing module)

#: Characters forbidden in an HTTP header value (RFC 9110 §5.5):
#: CR, LF, NUL and the remaining C0/C1 controls.
HEADER_FORBIDDEN: ...

def header_safe(value: Any, max_length: int = 256) -> str:
    """Make an arbitrary value safe to use as an HTTP header value.

    Collapses CR/LF/NUL and every other C0/C1 control character to a single
    space, collapses runs of whitespace, strips the result, and truncates it
    to ``max_length`` characters. Always returns a ``str``; ``None`` and
    non-string values are coerced via ``str()`` first (``None`` -> ``""``).

    This is the last line of defence against header injection — it must be
    applied to every header value derived from a request, a provider
    response, or an exception message.

    Args:
        value: The untrusted value destined for a header.
        max_length: Maximum length of the returned string.

    Returns:
        A single-line, control-character-free string.
    """
```

---

## 3. Module Breakdown

### Module 1: Nullable credential columns on `UserIdentity`
- **Path**: `navigator_auth/models.py` (lines 100-102)
- **Responsibility**: Make the three ciphered credential columns accept
  `None`, so a provider that issues no refresh/id token can be linked and so
  legacy rows with `NULL` columns can be hydrated. **All three** columns are
  widened — including `access_token` — because `auth.user_identities`
  predates the vault and profile-only rows carry `NULL` there (§8 Q3).
- **Depends on**: nothing.
- **Delegation-eligible**: **Yes.** Mechanical, fully specified, three lines.

**Interface Skeleton**
```python
# navigator_auth/models.py
class UserIdentity(Model):                                   # verified: navigator_auth/models.py:77
    ...
    provider_user_id: str = Column(required=False, repr=False)      # verified: navigator_auth/models.py:96
    scopes: Optional[list] = Column(
        required=False, default_factory=list, repr=False
    )                                                        # verified: navigator_auth/models.py:97-99
    access_token: Optional[bytes] = Column(required=False, repr=False)   # verified: navigator_auth/models.py:100
    refresh_token: Optional[bytes] = Column(required=False, repr=False)  # verified: navigator_auth/models.py:101
    id_token: Optional[bytes] = Column(required=False, repr=False)       # verified: navigator_auth/models.py:102
    token_type: str = Column(required=False, repr=False)     # verified: navigator_auth/models.py:103
```

Only the three annotations change. `Column(...)` arguments, ordering,
`Meta` and every other field stay byte-identical.

### Module 2: Header-safe `failed_redirect`
- **Path**: `navigator_auth/libs/sanitize.py` (new `header_safe`),
  `navigator_auth/backends/external.py` (lines 347-352)
- **Responsibility**: Guarantee that no header value emitted by
  `failed_redirect` can contain a control character, closing both the
  aiohttp `ValueError` crash and the CRLF-injection vector — for every
  backend that inherits it.
- **Depends on**: nothing.
- **Delegation-eligible**: **Yes.** Contract and call site are both fixed below.

**Interface Skeleton**
```python
# navigator_auth/libs/sanitize.py
HEADER_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f-\x9f]")

def header_safe(value: Any, max_length: int = 256) -> str:
    """Make an arbitrary value safe to use as an HTTP header value."""
    ...

# navigator_auth/backends/external.py
from ..libs.sanitize import header_safe

class ExternalAuth(BaseAuthBackend):                         # verified: navigator_auth/backends/external.py:85
    def failed_redirect(                                     # verified: navigator_auth/backends/external.py:347
        self,
        request: web.Request,
        error: str = "ERROR_UNKNOWN",
        message: str = "ERROR_UNKNOWN",
    ):
        """Redirect the browser to the failed-redirect URL.

        Both ``error`` and ``message`` may originate from a provider
        response, a query parameter or an exception string, so both are
        passed through :func:`header_safe` before reaching a header.
        """
        url = self.get_failed_redirect_url(request)          # verified: navigator_auth/backends/external.py:348
        safe_error = header_safe(error)
        safe_message = header_safe(message)
        headers = {"x-message": safe_message, "x-error": safe_error}  # verified: navigator_auth/backends/external.py:349
        params = {"error": safe_error, "message": safe_message}       # verified: navigator_auth/backends/external.py:350
        url = self.prepare_url(url, params)                  # verified: navigator_auth/backends/external.py:351
        return web.HTTPFound(url, headers=headers)           # verified: navigator_auth/backends/external.py:352
```

Note: `prepare_url` already URL-encodes query parameters
(`PreparedRequest.prepare_url`, `external.py:281-300`), so the query string
was never the injection vector — but the sanitized values are used for both
so that header and URL agree.

### Module 3: Stop reflecting exception and provider text
- **Path**: `navigator_auth/backends/external.py` (lines 799-820),
  `navigator_auth/backends/azure.py` (lines 282, 322, 333, 337)
- **Responsibility**: Replace the six reflective `message=f"...{err}"` /
  `f"{error}: {desc}"` call sites with a stable, fixed string. The diagnostic
  detail is already written to the log by the surrounding
  `self.logger.exception(...)` / `self.logger.warning(...)`; where it is not,
  add the log line.
- **Depends on**: Module 2 (for the test fixture that asserts on output).
- **Delegation-eligible**: **Partially.** The six sites and the rule are
  fixed; the exact replacement wording per site is listed below and must not
  be improvised.

**Interface Skeleton**
```python
# navigator_auth/backends/external.py
    async def finish_identity_link(self, request: web.Request, flow: dict):   # verified: navigator_auth/backends/external.py:793
        if error := request.rel_url.query.get("error"):                       # verified: navigator_auth/backends/external.py:798
            desc = request.rel_url.query.get("error_description", "")         # verified: navigator_auth/backends/external.py:799
            self.logger.warning(
                "%s: identity link denied by provider: error=%r description=%r",
                self._service_name, error, desc,
            )
            return self.failed_redirect(                                      # verified: navigator_auth/backends/external.py:800
                request,
                error="IDENTITY_LINK_DENIED",
                message="Identity link was denied by the provider.",
            )
        try:
            ...                                                               # verified: navigator_auth/backends/external.py:803-812
        except Exception as err:  # pylint: disable=W0703                     # verified: navigator_auth/backends/external.py:813
            self.logger.exception(
                f"{self._service_name}: identity link failed: {err}"
            )                                                                 # verified: navigator_auth/backends/external.py:814-816
            return self.failed_redirect(                                      # verified: navigator_auth/backends/external.py:817
                request,
                error="IDENTITY_LINK_FAILED",
                message="Identity link failed.",
            )
```

Exact per-site replacements (the `error=` code at each site is unchanged):

| File:line | Current `message=` | Replacement `message=` |
|---|---|---|
| `external.py:801` | `f"{error}: {desc}"` | `"Identity link was denied by the provider."` |
| `external.py:819` | `f"Identity link failed: {err}"` | `"Identity link failed."` |
| `azure.py:282` | `f"Info: {result}"` | `"Authentication failed."` |
| `azure.py:322` | `f"Error getting User information: {err}"` | `"Error getting user information."` |
| `azure.py:333` | `f"Error getting User information: {err}"` | `"Invalid user information."` |
| `azure.py:337` | `f"Error: {err}"` | `"Authentication failed."` |

Every site that loses an interpolated value must log that value first at
`warning` (or `exception` inside an `except` block) so no diagnostic
information is lost — only relocated.

### Delegation-eligible modules

| Module | Eligible | Why / what is fixed |
|---|---|---|
| 1 — Nullable credential columns | Yes | Three annotations, exact text given; no design choice remains |
| 2 — Header-safe `failed_redirect` | Yes | Helper signature, regex, call site and semantics all specified |
| 3 — Stop reflecting detail | Partially | The six sites and their exact replacement strings are fixed; the accompanying log lines follow the module's existing `self.logger` idiom |

---

## 4. Test Specification

The existing identity tests are **why this bug shipped**: every one of them
builds a `FakeUserIdentity` stub rather than the real model
(`tests/unit/identity/test_identity_vault_v2.py:114,132,143,155,169`,
`tests/test_identity_id_token.py:184,209,237,250`). The store logic was
covered; the model contract never was.

**Therefore: at least one test in Module 1 MUST instantiate the real
`navigator_auth.models.UserIdentity`, not a stub.** A fix validated only
against `FakeUserIdentity` is not validated at all.

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_user_identity_accepts_null_tokens` | 1 | Real `UserIdentity(user_id=1, auth_provider="github", access_token=b"x", refresh_token=None, id_token=None)` constructs; all three attributes read back as expected |
| `test_user_identity_bare_construction` | 1 | Real `UserIdentity(user_id=1, auth_provider="github")` constructs — the legacy-row hydration path — and all three token columns are `None` |
| `test_user_identity_still_accepts_bytes` | 1 | Supplying real `bytes` to all three columns still round-trips unchanged (no regression on the sealed path) |
| `test_header_safe_strips_crlf` | 2 | `header_safe("a\r\nX-Evil: 1")` contains no `\r`, no `\n`, and does not round-trip the injected header name as a separate line |
| `test_header_safe_strips_controls` | 2 | NUL, `\x1b`, `\x7f` and C1 controls are all removed |
| `test_header_safe_truncates` | 2 | A 10 000-char input returns at most `max_length` characters |
| `test_header_safe_coerces_non_str` | 2 | `None` → `""`; an `Exception` instance → its `str()`, sanitized |
| `test_failed_redirect_sanitizes_multiline_message` | 2 | `failed_redirect(request, error="E", message="line1\nline2")` returns an `HTTPFound` whose `x-message` header contains no newline |
| `test_failed_redirect_blocks_header_injection` | 2 | A `message` carrying `\r\nSet-Cookie: evil=1` does not produce a `Set-Cookie` header on the response |
| `test_identity_link_denied_message_is_stable` | 3 | With `?error=access_denied&error_description=<junk>`, the redirect's `message` is the fixed string and contains none of the query-supplied text |
| `test_identity_link_failed_message_is_stable` | 3 | A `save_linked_identity` that raises yields `error=IDENTITY_LINK_FAILED` and the fixed message, with the exception text absent from both header and URL |

### Integration Tests

| Test | Description |
|---|---|
| `test_save_linked_identity_insert_without_refresh_token` | End-to-end `IdentityStore.save_linked_identity` against a `TokenResponse(access_token="at", refresh_token=None, id_token=None)` on the **insert** branch (no existing row) — the GitHub shape. Asserts the real `UserIdentity` is built and `insert()` is reached with `refresh_token is None` |
| `test_save_linked_identity_update_keeps_tokens` | Regression guard on the `existing` branch (`store.py:179-193`): a re-save with `refresh_token=None` still keeps the previously vaulted ciphertext and does not clobber it |
| `test_finish_identity_link_failure_returns_redirect` | A failure inside `finish_identity_link` yields an `HTTPFound`, never an unhandled `ValueError` from the header writer |

### Test Data / Fixtures

```python
@pytest.fixture
def github_token_response():
    """The GitHub OAuth App shape: no refresh_token, no id_token, no expiry."""
    from navigator_auth.identity.types import TokenResponse
    return TokenResponse(
        access_token="gho_testtoken",
        token_type="bearer",
        refresh_token=None,
        id_token=None,
        expires_in=None,
        scopes=["read:user", "user:email"],
        provider_user_id="12345",
    )

@pytest.fixture
def crlf_payload():
    """A header-injection probe."""
    return "boom\r\nSet-Cookie: evil=1\r\nX-Injected: yes"
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `UserIdentity(user_id=1, auth_provider="github")` constructs without
      raising, using the **real** model, and all three token columns are `None`.
- [ ] `UserIdentity(..., access_token=b"x", refresh_token=None, id_token=None)`
      constructs without raising, using the **real** model.
- [ ] Supplying `bytes` to all three columns still round-trips unchanged.
- [ ] `IdentityStore.save_linked_identity` completes the **insert** branch for
      a `TokenResponse` with `refresh_token=None` and `id_token=None`.
- [ ] The `existing`-row branch of `save_linked_identity` still preserves a
      previously vaulted `refresh_token` / `id_token` on a re-save
      (no regression on `store.py:179-193`).
- [ ] `header_safe()` exists in `navigator_auth/libs/sanitize.py` and removes
      CR, LF, NUL and all C0/C1 control characters, and truncates to
      `max_length`.
- [ ] `failed_redirect` passes both `error` and `message` through
      `header_safe()` before they reach a header.
- [ ] A `failed_redirect` with a multi-line `message` returns an `HTTPFound`
      instead of raising `ValueError: Forbidden control character detected in
      headers`.
- [ ] A `message` containing `\r\nSet-Cookie: evil=1` produces no `Set-Cookie`
      header on the response.
- [ ] None of the six call sites listed in Module 3 interpolates an exception
      or a query-string value into `message=`; each logs the dropped detail
      instead. Verified by:
      `! grep -nE 'failed_redirect\(|message=f"' -A2 navigator_auth/backends/external.py navigator_auth/backends/azure.py | grep -E 'message=f".*\{(err|desc|result|error)\}'`
- [ ] Manual verification: `python examples/identity_vault_server.py`, click
      **Link Github**, complete the GitHub consent screen — the browser lands
      on the success redirect and the identity appears in the identities list.
      No `ValidationError` and no `Forbidden control character` in the log.
- [ ] `pytest tests/unit/identity/ tests/test_identity_id_token.py -v` passes.
- [ ] Full suite shows no new failures: `pytest tests/ -q` compared against
      the `dev` @ `99ad936` baseline.
- [ ] No DDL change and no migration file added under
      `navigator_auth/identity/sql/`.

---

## 6. Codebase Contract

> Every entry below was read on branch `dev` @ commit `99ad936`
> (2026-10-23). Line numbers are from that commit.

### `navigator_auth/models.py`

```python
# line 77
class UserIdentity(Model):
    identity_id: UUID = Column(required=False, primary_key=True, db_default="auto", repr=False)  # 78-80
    display_name: str = Column(required=False)        # 81
    title: str = Column(required=False)               # 82
    nickname: str = Column(required=False)            # 83
    email: str = Column(required=False)               # 84
    phone: str = Column(required=False)               # 85
    short_bio: Text = Column(required=False)          # 86
    avatar: Text = Column(required=False)             # 87
    user_id: User = Column(required=True, fk="user_id|username", api="users", label="User")  # 88-90
    auth_provider: str = Column(required=False)       # 91
    auth_data: Optional[dict] = Column(required=False, repr=False)    # 92
    attributes: Optional[dict] = Column(required=False, repr=False)   # 93
    provider_user_id: str = Column(required=False, repr=False)        # 96
    scopes: Optional[list] = Column(required=False, default_factory=list, repr=False)  # 97-99
    access_token: bytes = Column(required=False, repr=False)          # 100  <-- CHANGE
    refresh_token: bytes = Column(required=False, repr=False)         # 101  <-- CHANGE
    id_token: bytes = Column(required=False, repr=False)              # 102  <-- CHANGE
    token_type: str = Column(required=False, repr=False)              # 103
    expires_at: datetime = Column(required=False, repr=False)         # 104
    refreshed_at: datetime = Column(required=False, repr=False)       # 105
    enabled: bool = Column(required=False, default=True)              # 106
    key_version: int = Column(required=False, repr=False)             # 107
    created_at: datetime = Column(required=False, default=datetime.now, repr=False)  # 108-110

    class Meta:                      # 112
        name = "user_identities"     # 113
        schema = AUTH_DB_SCHEMA      # 114
        strict = True                # 115  <-- why None is rejected
        connection = None            # 116
        frozen = False               # 117
```

`Optional` is already imported in this module and already used at lines 92,
93 and 97 — **no new import is required**.

`: bytes` appears at exactly three places in this file (lines 100, 101, 102);
no other model in `navigator_auth/models.py` has the same defect.

`VwUserIdentity` (line 119) is a separate read-only view model and has **no**
token columns — it must not be touched.

### `navigator_auth/identity/store.py`

```python
class IdentityStore:                                        # 71
    def __init__(self, db_pool: Any, cipher: Optional[IdentityCipher] = None)  # 74
    def _seal(self, value, user_id, provider, provider_user_id, field) -> bytes  # 82-96
    def _open(self, identity, field) -> Any                 # 98-115
    def _reseal_kept(self, existing, user_id, provider, new_provider_user_id, fields) -> dict[str, bytes]  # 117-132
    async def save_linked_identity(                         # 134
        self, user_id: Any, provider: str,
        token: TokenResponse, userinfo: Optional[dict] = None,
    ) -> UserIdentity
    def _identity_profile(self, userinfo: dict) -> dict     # 201
    async def list_for_user(self, user_id: Any) -> list[dict]           # 221
    async def get_one(self, user_id, identity_id) -> Optional[UserIdentity]   # 231
    async def get_by_provider(self, user_id, provider) -> ...           # 244
    def masked(self, identity: UserIdentity) -> dict        # 375
```

The exact lines that pass `None` into the model:

```python
"refresh_token": (                                          # 155
    self._seal(token.refresh_token, user_id, provider, puid, "refresh_token")
    if token.refresh_token
    else None                                               # 158
),
"id_token": (self._seal(...) if token.id_token else None),  # 160
...
identity = UserIdentity(                                    # 194  <-- raises today
    user_id=user_id, auth_provider=provider, **values,
)
return await identity.insert()                              # 199
```

The `existing`-row branch that masks the bug on a re-link:

```python
if existing:                                                # 179
    kept: list[str] = []
    if token.refresh_token is None:
        values.pop("refresh_token", None)                   # 184
        kept.append("refresh_token")
    if token.id_token is None:
        values.pop("id_token", None)                        # 187
        kept.append("id_token")
```

**No change is required in this file.** It is already correct; it is the
model that rejects what it passes.

### `navigator_auth/identity/types.py`

```python
@dataclass
class TokenResponse:
    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None      # already Optional
    id_token: Optional[str] = None           # already Optional
    expires_in: Optional[int] = None
    expires_at: Optional[datetime] = None
    scopes: list = field(default_factory=list)
    provider_user_id: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def is_expiring(self, leeway: int = 0) -> bool
    def credential(self) -> dict
    @classmethod
    def from_credential(cls, data: dict) -> "TokenResponse"
    @classmethod
    def from_oauth_response(cls, payload: dict, scopes: Optional[list] = None) -> "TokenResponse"
```

`from_oauth_response` uses `payload.get("refresh_token")` and
`payload.get("id_token")` — both correctly yield `None` for GitHub. No change.

### `navigator_auth/backends/external.py`

```python
def get_domain(self, request: web.Request) -> str                  # 238
def get_redirect_uri(self, request: web.Request) -> str            # 244
def get_finish_redirect_url(self, request: web.Request) -> str     # 253
def prepare_url(self, url: str, params: dict = None)               # 281
def get_failed_redirect_url(self, request: web.Request) -> str     # 338
def failed_redirect(self, request, error="ERROR_UNKNOWN", message="ERROR_UNKNOWN")  # 347  <-- CHANGE
def get_identity_userid(self, userinfo: dict) -> Optional[str]     # 568
async def exchange_code_for_tokens(self, ...)                      # 605
async def get_identity_userinfo(self, token: "TokenResponse") -> dict  # 778
async def finish_identity_link(self, request: web.Request, flow: dict) # 793  <-- CHANGE
```

`failed_redirect` body as it stands:

```python
def failed_redirect(self, request, error="ERROR_UNKNOWN", message="ERROR_UNKNOWN"):  # 347
    url = self.get_failed_redirect_url(request)              # 348
    headers = {"x-message": message, "x-error": str(error)}  # 349  <-- unsanitized
    params = {"error": error, "message": message}            # 350
    url = self.prepare_url(url, params)                      # 351
    return web.HTTPFound(url, headers=headers)               # 352
```

Imports already present at the top of this module (lines 6-39) include
`from aiohttp import web, hdrs` and `from ..libs.redirect import
safe_redirect_url`. The new import is
`from ..libs.sanitize import header_safe`.

### `navigator_auth/libs/sanitize.py`

Existing contents (whole file, 928 B):

```python
"""Sanitize auth-related query parameters from request URLs."""
from aiohttp import web

AUTH_QUERY_PARAMS = frozenset({"apikey", "api_key", "auth", "access_token"})

def sanitize_request(request: web.Request, params: frozenset[str] = AUTH_QUERY_PARAMS) -> web.Request
```

`header_safe` is appended here. `re` is **not** currently imported in this
module — the implementation must add it.

### `navigator_auth/identity/sql/` — schema (no change)

Five migrations exist, all additive and idempotent, applied in order at
startup. None is modified by this feature:

| File | Purpose |
|---|---|
| `001_identity_credentials.sql` | credential columns (`access_token`, `refresh_token`, …) onto the **pre-existing** table |
| `002_identity_id_token.sql` | `id_token BYTEA` |
| `003_identity_key_version_integer.sql` | widen `key_version` |
| `004_identity_base_columns.sql` | FEAT-103: the model's **base** columns (`identity_id`, `display_name`, …) that legacy databases lack |
| `005_identity_legacy_uid_default.sql` | FEAT-103: make the legacy `uid NOT NULL` column self-filling |

That 001/002 use `ALTER TABLE … ADD COLUMN` — and that 004 had to exist at
all — is the evidence that pre-vault rows with `NULL` token columns are real.

```sql
-- 001_identity_credentials.sql:7-15
ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS provider_user_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS scopes           JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS access_token     BYTEA,   -- nullable
    ADD COLUMN IF NOT EXISTS refresh_token    BYTEA,   -- nullable
    ADD COLUMN IF NOT EXISTS token_type       VARCHAR(50),
    ADD COLUMN IF NOT EXISTS expires_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS refreshed_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS enabled          BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS key_version      SMALLINT;

-- 002_identity_id_token.sql:5
ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS id_token BYTEA;   -- nullable
```

### Verified reproduction (run on `dev` @ `99ad936`)

```
$ python -c "from navigator_auth.models import UserIdentity; UserIdentity(user_id=1, auth_provider='g')"
ValidationError: UserIdentity: There are errors in Model.
payload: {
 'access_token':  'Error parsing *access_token*  = *None*...  Cannot convert None to bytes',
 'refresh_token': 'Error parsing *refresh_token* = *None*...  Cannot convert None to bytes',
 'id_token':      'Error parsing *id_token*      = *None*...  Cannot convert None to bytes'}
```

### Does NOT Exist (do not reference)

- There is **no** `navigator_auth/identity/models.py`. `UserIdentity` lives in
  `navigator_auth/models.py` only.
- There is **no** existing header-sanitizing helper anywhere in
  `navigator_auth/` — `libs/sanitize.py` sanitizes *query parameters*, not
  headers. Do not import a `header_safe` / `sanitize_header` that already
  exists; it must be written.
- There is **no** `sdd/templates/design_research.prompt.md` or
  `design_research.schema.json` in this repository (see §9).
- `IdentityStore` has **no** `save_identity`, `upsert_identity` or
  `create_identity` method — the only write entry point is
  `save_linked_identity` (`store.py:134`).
- `UserIdentity` has **no** `has_refresh_token` attribute. That key exists
  only in the dict returned by `IdentityStore.masked()` (`store.py:375`).
- `TokenResponse` has **no** `refresh()` or `is_expired()` method. It has
  `is_expiring(leeway=0)` (`types.py`).
- `VwUserIdentity` (`models.py:119`) has **no** token columns — it is not
  part of this fix.
- No `.github/workflows/sync-down.yml` exists in this repository, despite
  `CLAUDE.md` describing one. Merging to `dev` is the end of this feature.

---

## 7. Implementation Notes & Constraints

### Patterns to Follow

- `Optional[X]` is the established idiom in this model for a nullable column
  (`models.py:92, 93, 97`). Match it exactly rather than introducing
  `X | None`.
- Keep `Column(required=False, repr=False)` byte-identical on the three
  changed lines — `repr=False` is what keeps ciphertext out of logs.
- Logging uses `self.logger` on backends and the module-level
  `logger = logging.getLogger("navigator.identity")` in `store.py`. Use lazy
  `%s` formatting for the new log lines in Module 3; do not f-string secrets.
- Never log, and never place in a header or query parameter, the *value* of
  `access_token`, `refresh_token` or `id_token`.
- `async`/`await` throughout; no blocking I/O added.

### Known Risks / Gotchas

- **`FakeUserIdentity` blind spot.** The existing identity tests stub the
  model, which is precisely why this shipped. A new test that uses the stub
  proves nothing about this fix — §4 makes the real model mandatory.
- **Do not "fix" `store.py`.** The tempting shortcut is to make
  `save_linked_identity` pop `refresh_token` / `id_token` on the insert branch
  too. That would hide the defect while leaving hydration of legacy `NULL`
  rows broken, and would mean a re-link could never clear a stale token. Fix
  the model.
- **Do not add `NOT NULL` or a default to the DDL.** The columns are
  legitimately nullable; GitHub OAuth Apps issue no refresh token at all.
- **Truncation vs. injection.** `header_safe` must sanitize *before*
  truncating, so a payload cannot be split such that the surviving prefix ends
  mid-escape. Strip controls first, then slice.
- **C1 range matters.** Stripping only `\r\n\0` is insufficient; aiohttp's
  `_write_str_raise_on_nlcr` is the current tripwire but latin-1 encoding of
  C1 bytes is its own hazard. Strip `\x00-\x1f` and `\x7f-\x9f`.
- **Losing diagnostics.** Module 3 removes text the operator currently reads
  off the browser URL. Each removal must be paired with a log line, or the
  next incident becomes harder to debug than this one was.
- **Error-code stability.** The `error=` codes (`IDENTITY_LINK_DENIED`,
  `IDENTITY_LINK_FAILED`, `ERROR_UNKNOWN`, …) are the contract a frontend can
  rely on and must not be renamed in this feature. Only the free-text
  `message=` changes.
- **Cython extensions in a worktree.** `navigator_auth/libs/` contains
  compiled `.pyx` modules; the shared `.venv` is editable-installed against
  the main checkout. If test results look stale inside the worktree, rebuild
  with `python setup.py build_ext --inplace` before trusting them, and never
  run `uv sync` inside a worktree.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| — | — | None. `re`, `typing.Optional` and the existing `datamodel` / `aiohttp` pins cover the whole change. |

---

## 8. Open Questions

- [x] Should this be a `hotfix` on `main` or a `feature` on `dev`? The defect
      is present on `origin/main` as well (`models.py:101`) —
      *Resolved by user (2026-10-23)*: **feature on `dev`**. FEAT-103
      (`external-provider-token-capture`) has just merged to `dev` and a
      main-based branch would conflict; the Identity Vault link flow is not
      yet relied on in production.
- [x] Scope — the model fix alone, or the header defects too? —
      *Resolved by user (2026-10-23)*: **all three** — the model fix, the
      header sanitization, and removing the leaked internal detail from the
      user-visible error output. The user explicitly accepted the wider blast
      radius of the third item.
- [x] Should `access_token` really be widened to `Optional[bytes]` as well? —
      *Resolved by user (2026-10-23)*: **yes, widen all three; no write-path
      guard.** `auth.user_identities` predates the Identity Vault entirely —
      migrations `001`/`002` `ADD COLUMN` the credential columns onto an
      existing table, and `004_identity_base_columns.sql` exists precisely
      because legacy databases had the table without even the model's base
      columns. Profile-only rows written before FEAT-096 therefore have
      `NULL access_token`, and hydrating them through `UserIdentity.get()` /
      `.filter()` raises the same `Cannot convert None to bytes` today —
      breaking `list_for_user`, `get_one` and `get_by_provider` independently
      of any link attempt. The model must match the nullable `BYTEA` schema
      on all three columns. The accepted trade-off: nothing at the type level
      prevents a credential row being written without an access token; a
      `save_linked_identity` guard for that was considered and **declined**
      as out of scope for this fix.
- [ ] Does any frontend currently parse the free-text `?message=` value rather
      than the `?error=` code? If one does, Module 3 changes what it displays.
      No consumer was found in this repository
      (`examples/identity_vault_server.py` reads neither), but downstream
      Navigator apps were not surveyed. *Owner: Jesus Lara*

---

## 9. Design Research Cross-Check

**Model**: —
**Status**: skipped (no accepted exploration document — `/sdd-spec` was invoked
directly with a bug report, so §3b's precondition of an `accepted` brainstorm
or proposal is unmet; additionally `sdd/templates/design_research.prompt.md`
and `sdd/templates/design_research.schema.json` do not exist in this
repository. `codex` itself is available — `codex-cli 0.163.0` — so this seat
can be used on a future spec once an exploration document exists.)

| Suggestion | Disposition | Reason | Landed in |
|---|---|---|---|
| — | — | — | — |

---

## Worktree Strategy

- **Default isolation unit**: `per-spec`. All tasks run sequentially in one
  worktree.
- **Worktree**: `.worktrees/feat-FEAT-104-bug-identity`, created from
  `origin/dev` via
  `python -m scripts.sdd.ensure_worktree --slug bug-identity --feature-id FEAT-104`.
- **Parallelism**: Modules 1 and 2 touch disjoint files and are logically
  independent, but the change is three files and well under a day's work —
  the coordination cost of a second worktree exceeds the benefit. Module 3
  depends on Module 2's helper for its assertions, so a parallel split would
  serialize at the end anyway.
- **Cross-feature dependencies**: none outstanding. FEAT-103
  (`external-provider-token-capture`) is already merged to `dev` at `99ad936`
  and this spec's anchors were verified against that commit.
- **Rebuild note**: `navigator_auth/libs/` ships Cython extensions compiled
  against the main checkout. Rebuild in the worktree before trusting test
  results.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-10-23 | Jesus Lara | Initial draft — GitHub identity-link failure: non-nullable `UserIdentity` token columns, unsanitized error headers, leaked internal detail |
| 0.2 | 2026-10-23 | Jesus Lara | Resolved §8 Q3 (widen all three columns, no write-path guard); corrected the migration inventory (`004`/`005` were missing); status → approved |
