# TASK-117: Stop reflecting exception and provider text into the failed redirect

**Feature**: FEAT-104 — Identity-Link Failure: Non-Nullable Token Columns and Unsafe Error Headers
**Spec**: `sdd/specs/bug-identity.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-116
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 3** — the third defect in the FEAT-104 report.

TASK-116 made the headers *safe*. This task stops them carrying information
they should never have carried. Six call sites interpolate an exception
string or a provider-supplied value into the user-visible `?message=` query
parameter and the `x-message` header. The original traceback shows a
`datamodel` error — ORM internals, model name and the failing field list —
being handed to the browser:

```
message=f"Identity link failed: {err}"
  -> "Identity link failed: UserIdentity: There are errors in Model.
      Hint: please check the 'payload' attribute ... (Fields with errors: ...)"
```

Two of the six are worse than noisy: `external.py:801` builds its message
from `?error` and `?error_description`, so it **reflects attacker-controlled
input straight back into the response**. Sanitized now, but still reflected.

This task is last because each replacement must be paired with a log line —
the detail is relocated, not discarded — and because its tests assert on the
sanitized output that TASK-116 produces.

**The error codes are the contract, not the message.** `IDENTITY_LINK_DENIED`,
`IDENTITY_LINK_FAILED`, `ERROR_UNKNOWN`, `ERROR_USER_NOT_FOUND`,
`ERROR_INVALID_REQUEST` and `AUTHENTICATION_ERROR` must not be renamed
(spec §1 Non-Goals). Only the free-text `message=` changes.

---

## Scope

- Replace the interpolated `message=` at the six call sites listed below with
  the exact fixed strings given.
- Ensure every value that stops being interpolated is logged first, at
  `warning` or inside an `except` block at `exception` level.
- Add tests asserting the identity-link failure paths emit stable messages
  that leak none of the underlying detail.

**NOT in scope**:
- The ~16 `failed_redirect` call sites that already pass a static literal
  (e.g. `message="Missing Auth Nonce"` in `adfs.py:187`, the SAML sites).
  TASK-116's sanitizer already makes them injection-safe (spec §1 Non-Goals).
- Renaming any `error=` code.
- `auth_error(reason={...})` JSON responses in `azure.py:541-588`,
  `github.py:112-135`, `google.py`, `okta.py`, `odoo.py`. Those are API
  bodies, not redirect headers, and are a separate concern.
- Any further change to `failed_redirect` itself — TASK-116 owns it.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/external.py` | MODIFY | 2 call sites in `finish_identity_link` + a new log line |
| `navigator_auth/backends/azure.py` | MODIFY | 4 call sites + log lines where detail would be lost |
| `tests/unit/identity/test_link_flow.py` | MODIFY | Assert stable, non-reflective messages |

---

## Codebase Contract

> Verified on `dev` @ `b222064` (2026-10-23).

### The six call sites — exact replacements (spec §3 Module 3)

| File:line | Current `message=` | Replacement `message=` | `error=` (unchanged) |
|---|---|---|---|
| `external.py:801` | `f"{error}: {desc}"` | `"Identity link was denied by the provider."` | `IDENTITY_LINK_DENIED` |
| `external.py:819` | `f"Identity link failed: {err}"` | `"Identity link failed."` | `IDENTITY_LINK_FAILED` |
| `azure.py:282` | `f"Info: {result}"` | `"Authentication failed."` | `AUTHENTICATION_ERROR` |
| `azure.py:322` | `f"Error getting User information: {err}"` | `"Error getting user information."` | `ERROR_USER_NOT_FOUND` |
| `azure.py:333` | `f"Error getting User information: {err}"` | `"Invalid user information."` | `ERROR_INVALID_REQUEST` |
| `azure.py:337` | `f"Error: {err}"` | `"Authentication failed."` | `ERROR_UNKNOWN` |

### Anchor occurrence counts (verified with `grep -cF`)

| Anchor | File | Count |
|---|---|---|
| `message=f"{error}: {desc}"` | `external.py` | 1 |
| `message=f"Identity link failed: {err}"` | `external.py` | 1 |
| `message=f"Info: {result}"` | `azure.py` | 1 |
| `message=f"Error: {err}"` | `azure.py` | 1 |
| `message=f"Error getting User information: {err}"` | `azure.py` | **2** |

> **The azure.py `Error getting User information` anchor is NOT unique.** It
> appears at both line 322 and line 333 and the two get **different**
> replacements. Disambiguate with surrounding context — see the blueprint.

### `navigator_auth/backends/external.py:793-820` — current source

```python
    async def finish_identity_link(self, request: web.Request, flow: dict):    # 793
        """Provider callback for an identity-link flow: exchange the code,
        cipher and store the credential, cache it in the Session Vault."""
        from ..identity.store import IdentityStore, cache_credential          # 796

        if error := request.rel_url.query.get("error"):                       # 798
            desc = request.rel_url.query.get("error_description", "")         # 799
            return self.failed_redirect(                                      # 800
                request, error="IDENTITY_LINK_DENIED", message=f"{error}: {desc}"   # 801
            )
        try:                                                                  # 803
            token = await self.exchange_code_for_tokens(request, flow)
            userinfo = await self.get_identity_userinfo(token)
            if not token.provider_user_id:
                token.provider_user_id = self.get_identity_userid(userinfo)
            store = IdentityStore(request.app["authdb"])
            await store.save_linked_identity(
                flow["user_id"], self._service_name, token, userinfo
            )
        except Exception as err:  # pylint: disable=W0703                     # 813
            self.logger.exception(                                            # 814
                f"{self._service_name}: identity link failed: {err}"
            )
            return self.failed_redirect(                                      # 817
                request,
                error="IDENTITY_LINK_FAILED",
                message=f"Identity link failed: {err}",                       # 819
            )
```

Line 814 **already logs** the detail — so `external.py:819` loses nothing.
Line 798-801 has **no log at all** — so that site needs one added.

### `navigator_auth/backends/azure.py` — logging idiom

Azure uses the **module-level** `logging`, not `self.logger`, on these paths:

```python
logging.exception(f"Azure: Error getting User information: {err}")   # 320 — before the :322 call site
logging.exception(err)                                               # 331 — before the :333 call site
logging.exception(err)                                               # 336 — before the :337 call site
```

- `azure.py:322` — already logged with context at line 320. Loses nothing.
- `azure.py:333` and `:337` — logged as bare `logging.exception(err)`, no
  context. Add context rather than leaving a message-less traceback.
- `azure.py:282` — `result` is **not** logged anywhere on that branch. A log
  line must be added or the MSAL failure detail is lost entirely.

`self.logger` also exists on this class (used at `azure.py:231, 504, 526`).
Match whatever the surrounding block already uses; do not convert one style
to the other as a drive-by.

### Existing tests that must keep passing (`tests/unit/identity/test_link_flow.py`)

```python
class TestFinishIdentityLink:                                        # 109
    async def test_provider_error_redirects_to_failure(self, flow_store):    # 152
        backend.failed_redirect = MagicMock(return_value="FAILED")           # 154
        request = make_mocked_request(
            "GET", "/auth/github/callback/?error=access_denied&state=s")
        ...
        assert backend.failed_redirect.call_args.kwargs["error"] == "IDENTITY_LINK_DENIED"   # 161

    async def test_exchange_failure_redirects_to_failure(self, flow_store):  # 166
        backend.exchange_code_for_tokens = AsyncMock(side_effect=AuthException("bad code"))
        backend.failed_redirect = MagicMock(return_value="FAILED")           # 171
```

These assert on `error=`, which this task does not change — they should keep
passing untouched. They mock `failed_redirect`, which is fine **here**: this
task asserts on the `message=` kwarg handed to it, not on header bytes.

### Does NOT Exist (do not reference)

- There is **no** error-code enum or constants module for these strings.
  `IDENTITY_LINK_DENIED` / `IDENTITY_LINK_FAILED` are bare literals at the
  call sites. `EXCHANGE_REASONS` (`external.py:47`) is an unrelated frozenset
  for token-exchange verification reasons — do not reuse or extend it.
- There is **no** i18n / message-catalog layer. The replacement strings are
  literals at the call site.
- `azure.py` has **no** `self._service_name`-style prefix convention on these
  log lines; existing ones hardcode `"Azure: ..."`.
- `adfs.py` and `saml/sp.py` have **no** interpolating `message=` call sites —
  verified; they are out of scope and must not be edited.

---

## Implementation Blueprint

### `navigator_auth/backends/external.py` — MODIFY (denied branch)

```python
# AFTER — replace lines 798-802 (verified: navigator_auth/backends/external.py:798-801)
# occurrences: 1 (verified: grep -cF 'message=f"{error}: {desc}"' navigator_auth/backends/external.py)
        if error := request.rel_url.query.get("error"):
            desc = request.rel_url.query.get("error_description", "")
            self.logger.warning(
                "%s: identity link denied by provider: error=%r description=%r",
                self._service_name,
                error,
                desc,
            )
            return self.failed_redirect(
                request,
                error="IDENTITY_LINK_DENIED",
                message="Identity link was denied by the provider.",
            )
```

**Why the log line is mandatory here — do not skip it.** This branch has no
logging today, so simply deleting the interpolation would make a
provider-side denial completely invisible to the operator. Use lazy `%r`
formatting (not an f-string): `%r` quotes and escapes the control characters
an attacker may have planted, so the log file itself cannot be forged with an
injected newline — the same class of bug being fixed one layer out.

### `navigator_auth/backends/external.py` — MODIFY (failure branch)

```python
# AFTER — replace line 819 only (verified: navigator_auth/backends/external.py:819)
# occurrences: 1 (verified: grep -cF 'message=f"Identity link failed: {err}"' navigator_auth/backends/external.py)
                message="Identity link failed.",
```

**Why no log line is added**: `self.logger.exception(...)` at line 814 already
records `{err}` with the service name. Adding a second is noise.

### `navigator_auth/backends/azure.py` — MODIFY (4 sites)

```python
# SITE 1 — AFTER (verified: navigator_auth/backends/azure.py:282)
# occurrences: 1 (verified: grep -cF 'message=f"Info: {result}"' navigator_auth/backends/azure.py)
# FILL IN: add a log of `result` immediately before this return — the value is
# logged nowhere on this branch today and would otherwise be lost entirely.
# Match the block's existing style (module-level `logging`) — bounded by AC-5.
                        return self.failed_redirect(
                            request,
                            error="AUTHENTICATION_ERROR",
                            message="Authentication failed.",
                        )

# SITE 2 — AFTER (verified: navigator_auth/backends/azure.py:320-323)
# occurrences of the bare anchor: 2 — DISAMBIGUATE on the preceding log line,
# which is unique (verified: grep -cF 'logging.exception(f"Azure: Error getting User information: {err}")' navigator_auth/backends/azure.py -> 1)
                except Exception as err:
                    logging.exception(f"Azure: Error getting User information: {err}")
                    return self.failed_redirect(
                        request,
                        error="ERROR_USER_NOT_FOUND",
                        message="Error getting user information.",
                    )

# SITE 3 — AFTER (verified: navigator_auth/backends/azure.py:331-334)
# DISAMBIGUATE on error="ERROR_INVALID_REQUEST", which is unique in this file
# (verified: grep -cF 'error="ERROR_INVALID_REQUEST"' navigator_auth/backends/azure.py -> 1)
            except Exception as err:
                # FILL IN: give the bare `logging.exception(err)` at line 331 the
                # context it lacks, e.g. an "Azure: invalid user information"
                # prefix — bounded by AC-5.
                return self.failed_redirect(
                    request,
                    error="ERROR_INVALID_REQUEST",
                    message="Invalid user information.",
                )

# SITE 4 — AFTER (verified: navigator_auth/backends/azure.py:335-337)
# occurrences: 1 (verified: grep -cF 'message=f"Error: {err}"' navigator_auth/backends/azure.py)
        except Exception as err:
            # FILL IN: give the bare `logging.exception(err)` at line 336 the
            # context it lacks — bounded by AC-5.
            return self.failed_redirect(
                request, error="ERROR_UNKNOWN", message="Authentication failed."
            )
```

**Why sites 3 and 4 get different messages despite sharing `{err}`.** They
sit on different branches with different `error=` codes, and the message is
what a user sees. `ERROR_INVALID_REQUEST` means the provider gave us
something unusable; `ERROR_UNKNOWN` is the outermost catch-all. Collapsing
both to one string would make the two indistinguishable in a support
conversation even though the codes differ.

**Why the azure anchor must be disambiguated.** `message=f"Error getting
User information: {err}"` is present **twice** (lines 322 and 333) and the
two replacements differ. A blind search-and-replace will write the wrong
string into one of them, and both tests would still pass because neither is
covered today. Anchor on the unique neighbouring line as shown.

### `tests/unit/identity/test_link_flow.py` — MODIFY

```python
# AFTER — append to class TestFinishIdentityLink (verified: tests/unit/identity/test_link_flow.py:109)
# occurrences: 1 (verified: grep -cF 'class TestFinishIdentityLink:' tests/unit/identity/test_link_flow.py)

    @pytest.mark.asyncio
    async def test_denied_message_leaks_no_query_input(self, flow_store):
        """?error_description is attacker-controlled and must not be echoed."""
        # FILL IN: request with ?error=access_denied&error_description=PWNED123
        # mock failed_redirect; assert kwargs["error"] == "IDENTITY_LINK_DENIED"
        # and "PWNED123" not in kwargs["message"] and "access_denied" not in
        # kwargs["message"] — bounded by AC-1.

    @pytest.mark.asyncio
    async def test_failed_message_leaks_no_exception_text(self, flow_store):
        """The FEAT-104 case: a ValidationError's text must not reach the user."""
        # FILL IN: make save_linked_identity raise with a distinctive multi-line
        # message; assert kwargs["error"] == "IDENTITY_LINK_FAILED" and the
        # distinctive text is absent from kwargs["message"] — bounded by AC-2.
```

**Why assert on absence of a distinctive marker rather than equality with the
fixed string.** Equality would break every time the wording is adjusted;
absence of the leaked token is the property that actually matters and
survives rewording. Assert the `error=` code by equality (it is the contract)
and the `message=` by absence (it is prose).

### Steps (in order)

1. Confirm TASK-116 is in `sdd/tasks/completed/`.
2. `external.py` denied branch: add the log line, then replace the message.
3. `external.py` failure branch: replace line 819 only — do not touch the
   `logger.exception` above it.
4. `azure.py`: do the four sites **one at a time**, re-running
   `grep -n 'message=' navigator_auth/backends/azure.py` after each, because
   the duplicate anchor makes a batch edit unsafe.
5. Verify no interpolating site survives — this is AC-4's command:
   ```bash
   grep -nE 'failed_redirect\(|message=f"' -A2 \
     navigator_auth/backends/external.py navigator_auth/backends/azure.py \
     | grep -E 'message=f".*\{(err|desc|result|error)\}'
   ```
   It must print nothing. (It matches 6 lines before this task.)
6. Add the two tests; run `pytest tests/unit/identity/test_link_flow.py -v`.
   The two pre-existing tests at lines 152 and 166 must still pass unchanged.
7. Run `pytest tests/ -q` and compare against the baseline — `azure.py` is
   widely exercised.
8. `ruff check navigator_auth/backends/external.py navigator_auth/backends/azure.py tests/unit/identity/test_link_flow.py`.

### FILL IN checklist

- [ ] `azure.py:282` — add the missing log of `result` — AC-5
- [ ] `azure.py:331` — add context to the bare `logging.exception(err)` — AC-5
- [ ] `azure.py:336` — add context to the bare `logging.exception(err)` — AC-5
- [ ] `test_denied_message_leaks_no_query_input` body — AC-1
- [ ] `test_failed_message_leaks_no_exception_text` body — AC-2

---

## Acceptance Criteria

- [ ] **AC-1** With `?error=access_denied&error_description=<marker>`, the identity-link redirect's `message` contains neither the marker nor `access_denied`; `error` is still `IDENTITY_LINK_DENIED`.
- [ ] **AC-2** When `save_linked_identity` raises, the redirect's `message` contains none of the exception text; `error` is still `IDENTITY_LINK_FAILED`.
- [ ] **AC-3** All six call sites use the exact replacement strings from the table above.
- [ ] **AC-4** The verification command in Step 5 prints nothing.
- [ ] **AC-5** Every value that stopped being interpolated is logged: a new log at `external.py` denied branch and at `azure.py:282`; added context on the bare `logging.exception(err)` at `azure.py:331` and `:336`.
- [ ] **AC-6** No `error=` code is renamed.
- [ ] **AC-7** `adfs.py` and `saml/sp.py` are not modified; the ~16 static-literal call sites are unchanged.
- [ ] **AC-8** `failed_redirect` itself is unchanged from TASK-116.
- [ ] **AC-9** The pre-existing `test_provider_error_redirects_to_failure` and `test_exchange_failure_redirects_to_failure` still pass **unmodified**.
- [ ] **AC-10** `pytest tests/ -q` shows no new failures versus the `dev` baseline.
- [ ] **AC-11** `ruff check` clean on all three files.

---

## Test Specification

```bash
pytest tests/unit/identity/test_link_flow.py -v
pytest tests/ -q
grep -nE 'failed_redirect\(|message=f"' -A2 \
  navigator_auth/backends/external.py navigator_auth/backends/azure.py \
  | grep -E 'message=f".*\{(err|desc|result|error)\}'   # must print nothing
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/bug-identity.spec.md` — §1 Defect C, §3 Module 3.
2. **Check dependencies** — TASK-116 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/bug-identity.json` → `"in-progress"`.
4. **Implement** per the blueprint, one azure site at a time (Step 4).
5. **Verify** every acceptance criterion, especially AC-3 (the duplicate
   azure anchor) and AC-5 (nothing silently lost).
6. **Move this file** to `sdd/tasks/completed/TASK-117-stop-reflecting-error-detail.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
