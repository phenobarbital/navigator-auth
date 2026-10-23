# TASK-122: `OwnerOrSuperuserGuard` mixin (`handlers/guards.py`)

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-118, TASK-119
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 3** — the centre of the feature. This mixin holds
the authorization decision, the query sanitation, the parameterized safe
filter and the audit trail for all three hardened surfaces, so that one
implementation serves **two different handler base classes** and can be unit
tested without HTTP plumbing.

The business rule it encodes (spec §1): *querying, editing and managing these
rows is the user's own prerogative over their own rows, or a `superuser`'s —
and a superuser never sees credentials.*

Four properties this task is responsible for, each from spec §2 Overview:

1. **Ownership binding (layer 1)** — owner ⇒ allowed, with no policy
   consulted at all. Not owner ⇒ the superuser path. Neither ⇒ refused.
   `owner_column = None` means *no owner exists* ⇒ superuser-only for every
   verb (the partner-keys configuration).
2. **Policy-gated admin path (layer 2)** — the superuser path additionally
   requires the handler's **named** policy to allow the action, through
   `policy_allows()` (TASK-119). Fails closed: no PDP, policy undeclared, or
   evaluation raised ⇒ deny.
3. **Safe filtering (layer 4)** — `?_filter=` becomes a parameterized query
   over `public_columns` only, with the ownership predicate ANDed in.
4. **Audit (G6)** — every cross-user and admin decision, allow *and* deny,
   produces one `AuditLog` record.

Layer 3 (redaction) is TASK-118's module; this mixin only carries the column
sets and hands them to it.

**Why it is a mixin and not a base class.** `UserIdentityHandler` and
`UserAccountHandler` must keep inheriting `navigator.views.ModelView` (via
`handlers/handler.py`), while `PartnerKeyHandler` must keep inheriting the
local `handlers/model.py` `ModelHandler`. A mixin placed **before** the base
in the MRO is the only shape that serves both without forking the logic
(spec §7: "The guard mixin goes **before** the handler base in the MRO so its
hooks win").

> **Environment drift (read this).** The spec's §6 "Exists — upstream
> `navigator`" table was recorded against `navigator-api` **3.2.2**; `.venv`
> actually has **4.0.1**, which already contains the §2 Prerequisite fix. The
> design is unchanged — it never depended on upstream — but every upstream
> anchor in this task was **re-verified against 4.0.1** and some of the
> spec's line numbers and claims are stale. Where this task and the spec
> disagree about an upstream fact, this task is right; the differences are
> called out inline.

---

## Scope

- Create `navigator_auth/handlers/guards.py` with `OwnerOrSuperuserGuard`:
  the five class attributes and the five coroutines from spec §3 Module 3.
- Create `tests/unit/handlers/test_owner_superuser_guard.py` covering the
  seven Module-3 rows of spec §4.

**NOT in scope**:
- Wiring the mixin into any handler. `userattrs.py` and `partners.py` must be
  untouched — TASK-123/124/125/126 do the wiring. This task's tests drive the
  mixin through a **synthetic** host class.
- The identity-specific `masked()`-shape projection — TASK-124.
- Changing `redaction.py` (TASK-118) or `policy_allows()` (TASK-119). If
  either looks wrong, raise it rather than patching it here.
- The `readonly_columns` write refusal. That is identity-specific
  (vault-managed columns) and belongs to TASK-123.
- Overriding `_pre_get` / `_filtering` / `_model_response` / `_get_meta_info`.
  Those are per-handler hooks; this mixin provides the *primitives* they
  call. (Deliberate: the two bases have different hooks, so hook overriding
  cannot live in the shared mixin — see the base-asymmetry table below.)

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/guards.py` | CREATE | The `OwnerOrSuperuserGuard` mixin |
| `tests/unit/handlers/test_owner_superuser_guard.py` | CREATE | Unit tests |

---

## Codebase Contract

> Every fact below was re-verified on `dev` @ `62fd419` against the installed
> `navigator-api` **4.0.1** (2026-10-23).

### Verified imports — the only ones this module needs

```python
from typing import Any, Optional                        # stdlib
from navigator_session import get_session               # verified: navigator_auth/handlers/model.py:16
from navigator_auth.conf import AUTH_SESSION_OBJECT     # verified: navigator_auth/conf.py:312 -> "session"
from navigator_auth.decorators import _check_superuser  # verified: navigator_auth/decorators.py:291
from navigator_auth.decorators import policy_allows     # TASK-119
from navigator_auth.abac.audit import AuditLog          # verified: navigator_auth/abac/audit.py:189
from navigator_auth.abac.policies import PolicyEffect   # verified: tests/test_check_access.py:11
from navigator_auth.abac.policies.abstract import PolicyResponse  # verified: abstract.py:19
from navigator_auth.handlers.redaction import redact_rows, safe_fields  # TASK-118
```

`AUTH_SESSION_OBJECT` is also exported by `navigator_session` and both equal
`"session"` (verified by executing both imports). Spec §3 Module 3 fixes the
`navigator_auth.conf` source — use that one.

### CRITICAL — `self.error()` RAISES, it does not return

Verified `.venv/lib/python3.11/site-packages/navigator/views/base.py:201-243`:

```python
    def error(
        self,
        response: dict = None,
        exception: Exception = None,
        status: int = 400,
        ...
    ) -> web.Response:
        ...
        if status == 400:    obj = web.HTTPBadRequest(**args)
        elif status == 401:  obj = web.HTTPUnauthorized(**args)
        elif status == 403:  obj = web.HTTPForbidden(**args)
        elif status == 404:  obj = web.HTTPNotFound(**args)
        elif status == 406:  obj = web.HTTPNotAcceptable(**args)
        elif status == 412:  obj = web.HTTPPreconditionFailed(**args)
        ...
        raise obj
```

This is **the fact the whole design rests on.** `error()` lives on
`BaseHandler` (`base.py:42`), and both handler bases inherit it:
`BaseView(CorsViewMixin, BaseHandler, web.View)` (`base.py:619`) →
`AbstractModel(BaseView)` (`abstract.py:138`) → `ModelView(AbstractModel)`
(`model.py:57`); and the local `ModelHandler(BaseView)`
(`navigator_auth/handlers/model.py:21`).

Consequence: a refusal raised from inside a `_pre_*` hook reaches the client
with **its own** status. That matters because returning `False` from
`_pre_get` yields a fixed **412** instead (verified: `model.py:553-559`):

```python
    async def get(self):
        """GET Model information."""
        if not await self._pre_get():
            return self.error(
                response={
                    "message": f"{self.__name__} Error on Pre-Validation"
                },
                status=412
            )
```

So `authorize_row()` must **raise** on deny (403/404), never return `False`.
Spec §3's `-> bool` signature is kept, but the only value it ever returns is
`True`. This is the single most important thing to get right in this task.

### `_check_superuser` — the superuser decision (verified: `decorators.py:291-313`)

```python
def _check_superuser(userinfo: dict, user: object = None) -> bool:
    """Return True if the user has superuser privileges."""
    if userinfo.get("superuser") is True or userinfo.get("is_superuser") is True:
        return True
    groups = userinfo.get("groups")
    # Membership only on a real collection: `in` on a str is SUBSTRING
    # matching, so an unguarded test would grant superuser to any value
    # merely containing the word (e.g. groups="ex_superuser_revoked"),
    # and raise TypeError on groups=None.
    if isinstance(groups, (list, tuple, set, frozenset)):
        if SUPERUSER_GROUP in groups:
            return True
    if user is not None and hasattr(user, "groups"):
        for g in user.groups:
            name = getattr(g, "group", None) or getattr(g, "group_name", None)
            if name == SUPERUSER_GROUP:
                return True
    return False
```

`SUPERUSER_GROUP = "superuser"` (`decorators.py:288`). This is the single
source of truth — reuse it, and do not re-implement any part of it. Spec §6
records that `client_access.py:57`'s `_require_superuser` checks only the
attribute (not group membership) and `decorators.is_superuser` (`:315`)
consults no policy, so **neither** may be substituted.

### How the session yields `user_id` — the two established patterns

`AbstractModel.get_userid` (verified: `.venv/.../navigator/views/abstract.py:310-328`):

```python
    async def get_userid(self, session, idx: str = 'user_id') -> int:
        if not session:
            self.error(response={"error": "Unauthorized"}, status=403)
        try:
            if AUTH_SESSION_OBJECT in session:
                return session[AUTH_SESSION_OBJECT][idx]
            else:
                return session[idx]
        except KeyError:
            self.error(response={...}, status=403)
```

`BaseIdentityView._user_id` (verified: `navigator_auth/handlers/user_identities.py:38-59`)
does the same two-step lookup and then `_json_error(401, ...)`.

`get_session` signature (verified by executing it):
`get_session(request, userdata: dict = None, new: bool = False, ignore_cookie: bool = True)`.

`_abac_eval_context` (`decorators.py:1044-1070`) reads `userinfo` as
`session[AUTH_SESSION_OBJECT]` and `user` as `session.decode("user")`, and
tolerates both being absent.

### The two handler bases are asymmetric — this is why the mixin holds primitives only

| | `UserIdentityHandler`, `UserAccountHandler` | `PartnerKeyHandler` |
|---|---|---|
| base | `handlers/handler.py:4` `ModelHandler(ModelView)` | `handlers/model.py:21` `ModelHandler(BaseView)` |
| `_pre_*` hooks | **yes** — `_pre_get/_pre_patch/_pre_put/_pre_post/_pre_delete` (verified: `.venv/.../navigator/views/abstract.py:553-571`, all `async (*args, **kwargs) -> True`) | **no** |
| `_filter_<column>` hook | **yes** (verified: `model.py:399-401`, `getattr(self, f'_filter_{name}', None)`) | **no** |
| `_model_response` | **yes** (verified: `model.py:237`) | **no** — redaction attaches to `_post_get` (`navigator_auth/handlers/model.py:88`) |
| `error()` | yes (`BaseHandler`) | yes (`BaseHandler`) |
| `self.request` | yes | yes |

Only `error()` and `self.request` are common — hence the mixin's documented
requirement: *"it needs only `self.request` and a session."*

### `policy_allows()` — the contract this mixin consumes (TASK-119, spec §2)

```python
async def policy_allows(
    policy: Union[str, list],
    request: web.Request,
    action: str = None,
    resource: str = None,
    resource_type: Any = None,
    require_all: bool = False,
) -> tuple[bool, str, Any]:
```

Returns `(allowed, reason, response)`; `allowed` is `False` when ABAC is
absent, the policy is not declared, or evaluation raised; `reason` is always
a non-empty string. **Raises `ValueError`** when the policy list is empty —
so a handler with `policy_name = None` must be refused *before* the call, not
by catching that error.

### `AuditLog` — the audit sink (verified: `navigator_auth/abac/audit.py`)

```python
class AuditLog:                                   # :189
    def __init__(self):                           # :208 — no arguments
    async def log(self, answer, status, user, *, tenant: str = None):   # :277
```

Backends read `answer.response` and `getattr(answer, "rule", None)`
(verified: `audit.py:181-182`, `:299-303`). So `answer` must be a
`PolicyResponse`.

`PolicyResponse` (verified: `navigator_auth/abac/policies/abstract.py:19-23`):

```python
class PolicyResponse(ClassDict):
    effect: PolicyEffect
    response: str
    rule: str
    actions: list[str]
```

How the PDP itself calls it (verified: `navigator_auth/abac/pdp.py:85` and
`:483-487`):

```python
        self._auditlog = AuditLog()
        ...
        try:
            await self._auditlog.log(answer, PolicyEffect(answer.effect).name, user)
        except Exception as exc:
            self.logger.warning('Error saving policy Log: %s', exc)
```

**Copy that `try/except`.** An audit backend is remote (influx / mongo / SQL
via `AUDIT_DSN`); letting it raise would turn a successful authorization into
a 500.

### Reuse the PDP's `AuditLog` when there is one

`_get_pdp(request)` (`decorators.py:994-1001`) returns `request.app["abac"]`
or `request.app["security"].pdp`, and that PDP already owns an `AuditLog` at
`pdp._auditlog` (`pdp.py:85`). Prefer it; construct a bare `AuditLog()` only
as a fallback. Rationale in the blueprint.

### Safe filter — the parameterized idiom and what upstream now does

Repo idiom (verified `navigator_auth/passkey/store.py:44-47`,
`navigator_auth/middlewares/strategies.py:87-91`):

```python
            row = await conn.fetch_one(
                f"SELECT * FROM {_CREDENTIALS} WHERE credential_id = $1",
                credential_id,
            )
```

`asyncdb` pg driver signatures (verified
`.venv/lib/python3.11/site-packages/asyncdb/drivers/pg.py`):

| Method | Line | Signature |
|---|---|---|
| `query` | `:892` | `async def query(self, sentence, *args, **kwargs)` — returns `(result, error)` |
| `fetch_all` | `:1013` | `async def fetch_all(self, sentence, *args, **kwargs)` |
| `fetch_one` | `:1036` | `async def fetch_one(self, sentence, *args, **kwargs)` |
| `fetchval` | `:1052` | `async def fetchval(self, sentence, *args, column: int = 0, **kwargs)` |

**Upstream `_filtering` in 4.0.1 — the spec is stale here.** Verified
`.venv/.../navigator/views/model.py:479-547`: it is **already** validated and
parameterized (`column not in self.get_model.get_columns()` ⇒ 400; value
bound as `$1`). The spec's §6 claim that it interpolates and is "unreachable,
answers 406" describes 3.2.2 and no longer holds.

The override is **still required**, for two reasons that 4.0.1 does not
address:

1. Its allowlist is "a real column and not in `_hidden`". `_hidden` is derived
   from `secret=True` columns only (`model.py:178`), and **no** credential
   column on these models declares `secret=True` (verified:
   `navigator_auth/models.py:104-106`, `handlers/partners.py:25`). So
   `?_filter=access_token=x` is a *valid* filter upstream and returns token
   bytes. `public_columns` is the allowlist that actually closes this.
2. It has **no ownership predicate** — `SELECT "<col>" FROM <table> WHERE
   "<col>"::text LIKE $1` reads the whole table regardless of session. Spec
   G7 requires the owner predicate ANDed in.

Mention both in the override's docstring so nobody deletes it as redundant.

### What a foreign `user_id` query parameter does today (spec §3 is slightly off)

Verified `.venv/.../navigator/views/model.py:446`:

```python
                elif len(qp) > 0:
                    print("FILTER")
                    query = await self.get_model.filter(**qp, **_filter)
```

A duplicate key between `qp` (the request's `?user_id=`) and `_filter` (the
`_filter_user_id` hook's forced value) raises `TypeError`, which `_get_data`
converts at `:468-471` (`except Exception as err: raise ModelError(...)`) and
`get()` answers as **400** (`:577-583`). Spec §3 Module 3 says this
"would surface as a 500" — verified today it is a 400 `ModelError`. Either
way the parameter must be **refused by `sanitize_query` before any DB
access**, which is what the spec requires; only the stated symptom differs.

### Does NOT Exist (do not reference)

- `navigator_auth/handlers/guards.py` — **this task creates it.** There is no
  guard, mixin, or ownership helper anywhere in `navigator_auth/handlers/`
  today.
- `navigator_auth/handlers/redaction.py` functions other than the four
  TASK-118 declares: `safe_fields`, `redact_row`, `redact_rows`,
  `redact_schema`. There is no `redact_response`, no `project`, no
  `mask_row`.
- Any row-ownership key on `EvalContext`. `EvalContext.__init__`
  (`navigator_auth/abac/context.py:89`) stores `user`, `userinfo`, `session`,
  `auth_method`, `mfa`, `org_id`, `client_id` — **no** `owner`,
  `object_owner`, `resource_owner` or `row_user_id`. And
  `ResourcePolicy.evaluate_conditions` (`abac/policies/resource_policy.py:119-150`)
  **passes** on a missing attribute (`if actual is None: continue`), so a
  condition naming an owner would silently allow. Ownership stays in code.
- `PDP.filter_obj` (`abac/pdp.py:616`) / `ObjectPolicy._filter`
  (`abac/policies/obj.py:208`) as a row filter — they filter opaque object
  *names*, not SQL rows.
- `ResourceType.IDENTITY` / `.MODEL` / `.PARTNER` — not in the enum
  (`abac/policies/resources.py:15-30`). Use `ResourceType.URI`, which
  `policy_allows` already defaults to when a `resource` is given with no
  type (`decorators.py:1136-1139`).
- `decorators.is_superuser` (`:315`) and `client_access._require_superuser`
  (`client_access.py:57`) — see the `_check_superuser` entry; neither is a
  valid substitute.
- A `superuser` flag on `UserIdentity`. The `superuser` at
  `navigator_auth/identities.py:235` belongs to the auth **user** object, not
  to this model.
- `self._session` as a reliable attribute on the mixin. It is set by
  `@service_auth` on the `ModelView` path and by `session()` on the local
  path (`navigator_auth/handlers/model.py:112-125`) — i.e. at different times
  by different bases. The mixin must call `get_session(self.request)` itself.

---

## Implementation Blueprint

### `navigator_auth/handlers/guards.py` — CREATE

Split into three blocks to stay inside the ~80-line-per-block cap. They form
one file in this order.

**Block 1 — module header, class attributes, `acting_user`:**

```python
"""Owner-or-superuser authorization for generic model handlers (FEAT-105).

Base-agnostic: works over ``navigator.views.ModelView`` (through
``handlers/handler.py``) and over the local ``handlers/model.py``
``ModelHandler``; it needs only ``self.request``, a session, and the
``error()`` helper both bases inherit from ``navigator.views.base.BaseHandler``.

Every refusal is **raised**, not returned: ``BaseHandler.error()`` raises the
matching ``web.HTTPException`` (verified: navigator/views/base.py:201-243), so
a deny reaches the client with its own status. Returning a falsy value from a
``_pre_*`` hook would instead produce a fixed 412 (navigator/views/model.py:553).
"""
import logging
from typing import Any, Optional

from navigator_session import get_session

from ..abac.audit import AuditLog
from ..abac.policies import PolicyEffect
from ..abac.policies.abstract import PolicyResponse
from ..conf import AUTH_SESSION_OBJECT
from ..decorators import _check_superuser, policy_allows

logger = logging.getLogger("navigator.auth.guards")


class OwnerOrSuperuserGuard:
    """Owner-or-superuser authorization for generic model handlers.

    Per-surface behaviour is configuration, not forked logic: subclasses set
    the five class attributes below and call the coroutines from their own
    verb hooks.

    Attributes:
        owner_column: Column holding the row's owner ``user_id``. ``None``
            means *no owner exists* for this model, which makes the superuser
            path the only path for every verb.
        credential_columns: Columns that must never be serialized or
            enumerated, for any role, through any parameter.
        public_columns: The serialization allowlist. A column absent from it
            is invisible, including to its own owner.
        policy_name: Name of the ABAC policy governing the admin path. A
            falsy value disables cross-user access entirely.
        superuser_actions: Actions the admin path may take. An action outside
            this set is refused even when the policy would allow it.
    """

    owner_column: Optional[str] = "user_id"
    credential_columns: frozenset[str] = frozenset()
    public_columns: frozenset[str] = frozenset()
    policy_name: str = None
    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})

    async def acting_user(self) -> tuple[int, bool]:
        """Resolve ``(user_id, is_superuser)`` for the current request.

        Returns:
            The session's ``user_id`` and whether it has superuser
            privileges, decided by
            :func:`navigator_auth.decorators._check_superuser`.

        Raises:
            web.HTTPUnauthorized: no session, or no ``user_id`` in it.
        """
        # FILL IN: session = await get_session(self.request) (treat a raised
        # RuntimeError/ValueError as "no session"); refuse with
        # self.error(status=401) when falsy. Read userinfo as
        # session[AUTH_SESSION_OBJECT] when that key is present, else the
        # session itself — the two-step lookup at
        # navigator/views/abstract.py:316-320. user_id = userinfo["user_id"],
        # 401 when absent. user = session.decode("user") guarded by
        # try/except (decorators.py:1055-1058 shows the exceptions).
        # Return (user_id, _check_superuser(userinfo, user)).
        # Bounded by AC-1, AC-2, AC-3.
```

**Why `acting_user` reads the session itself instead of using
`self._session`.** `self._session` is populated by `@service_auth` on the
`ModelView` path and by `session()` on the local path — different times,
different bases, and `None` in a unit test that never ran either. Calling
`get_session(self.request)` is the one thing both bases can guarantee, and it
is what the mixin's own docstring promises.

**Why 401 and not 403 for a missing session.** 401 says "authenticate"; 403
says "you are authenticated and still not allowed". The local base's
`get_userid` answers 403 (`navigator_auth/handlers/model.py:52-55,62`) and
`BaseIdentityView._user_id` answers 401
(`handlers/user_identities.py:58`). Spec §3 Module 3 fixes **401** for this
method — follow the spec, and do not "harmonize" the other two.

**Why `_check_superuser` is called with both `userinfo` and `user`.** Its
third check walks `user.groups[].group` / `.group_name`
(`decorators.py:306-312`), which is the only path that works when the session
carries a `User` object rather than a `groups` list. Passing `userinfo` alone
silently loses superuser status for those deployments.

**Block 2 — `authorize_row` and `sanitize_query`:**

```python
    async def authorize_row(
        self,
        action: str,
        owner_id: Optional[int],
        *,
        not_found_on_deny: bool = False,
    ) -> bool:
        """Authorize one row operation. Owner, else policy-gated superuser.

        Args:
            action: The action to authorize, e.g. ``"identity:read"``. For the
                superuser path it must be a member of ``superuser_actions``.
            owner_id: The row's owner ``user_id``, or ``None`` when the row
                has no owner (``owner_column is None``) or does not exist.
            not_found_on_deny: Answer 404 instead of 403, so a primary-key
                probe cannot be used to confirm that a foreign row exists.

        Returns:
            ``True``. This method **never returns False** — see the module
            docstring; a refusal is raised.

        Raises:
            web.HTTPForbidden: refused (``not_found_on_deny`` is False).
            web.HTTPNotFound: refused (``not_found_on_deny`` is True).
            web.HTTPUnauthorized: no session.
        """
        # FILL IN, in this order — the order IS the security property:
        #  1. user_id, is_superuser = await self.acting_user()
        #  2. owner path: self.owner_column is not None and owner_id is not
        #     None and the two ids compare equal -> return True immediately,
        #     with NO policy call and NO audit record (AC-4, AC-5).
        #     Compare defensively: owner_id may arrive as str/UUID-ish from a
        #     dict row while the session holds an int.
        #  3. not is_superuser -> audit the deny, then refuse (AC-6, AC-7).
        #  4. action not in self.superuser_actions -> audit, refuse (AC-8).
        #  5. not self.policy_name -> audit, refuse. Do NOT call
        #     policy_allows with a falsy policy: it raises ValueError on an
        #     empty name list (TASK-119 AC-2).
        #  6. allowed, reason, response = await policy_allows(
        #         self.policy_name, self.request, action=action,
        #         resource=self.request.path)
        #     audit the outcome either way, then return True or refuse (AC-9,
        #     AC-10, AC-11).
        # Refusal helper: self.error(response={...}, status=404 if
        # not_found_on_deny else 403). Keep the body generic — spec §7: a deny
        # message must not confirm a foreign row's existence (AC-12).

    async def sanitize_query(
        self,
        qp: dict,
        fields: Optional[list[str]],
    ) -> tuple[dict, Optional[list[str]]]:
        """Remove the parameter bypasses before any database access.

        Args:
            qp: Query parameters, as ``get_parameters()`` returns them with
                ``fields`` already popped out
                (verified: navigator/views/abstract.py:434-447).
            fields: The caller's ``?fields=`` projection, or ``None``.

        Returns:
            ``(qp, fields)`` — sanitized. ``fields`` is intersected with
            ``public_columns``; ``qp`` keeps only safe keys.

        Raises:
            web.HTTPForbidden: a non-superuser named a foreign
                ``owner_column`` value.
        """
        # FILL IN:
        #  - fields -> safe_fields(fields, self.public_columns) (AC-13).
        #  - when self.owner_column is in qp and the caller is NOT a
        #    superuser: refuse with 403 if the value differs from the acting
        #    user_id, otherwise DROP the key. Refuse/drop rather than merge,
        #    because the forced `_filter_<owner>` hook value and a surviving
        #    qp key collide in `filter(**qp, **_filter)`
        #    (navigator/views/model.py:446) — a duplicate keyword raises
        #    TypeError, which _get_data turns into a 400 ModelError
        #    (model.py:468-471, 577-583). Bounded by AC-14, AC-15.
        #  - drop any qp key naming a credential_columns member, for everyone
        #    (AC-16).
```

**Why the owner path takes no policy and writes no audit record.** Spec G1/G2
separate the two decisions: ownership is a code invariant, the policy governs
only the *admin capability*. If the owner path consulted the policy, a
deployment with no PDP (the common case — nothing loads
`default_policies/`) would lock every user out of their own rows. And
auditing ordinary self-service access would bury the cross-user events that
G6 exists to surface.

**Why an action outside `superuser_actions` is refused before the policy.**
Defence in depth against a mis-scoped policy file: the handler declares the
verbs its surface supports, and that envelope is code. A policy that grew an
extra action — by edit, by merge, by a `*` — cannot widen a handler.

**Why `policy_name` falsy is a refusal and not a `ValueError`.**
`policy_allows` raises `ValueError` on an empty name list (TASK-119 AC-2),
which would surface as a 500. A handler whose `policy_name` was never set
has simply not opted into cross-user access; the right answer is a clean
deny with an audit record naming the misconfiguration.

**Why `not_found_on_deny` exists rather than always answering 404.** On a
*list* request there is no specific row to hide, and a 404 would wrongly say
"this endpoint does not exist". 404 is only correct on the primary-key path,
where the status itself is the information being withheld (spec §2 layer 1).

**Why `sanitize_query` refuses a foreign owner value instead of silently
rewriting it.** Rewriting `?user_id=<victim>` into `?user_id=<me>` returns
200 with someone else's row-count-shaped data and teaches the caller nothing;
worse, it makes the endpoint look like it honoured the request. A 403 is the
honest answer, and spec §3 Module 3 specifies it.

**Block 3 — `safe_filter` and `audit_decision`:**

```python
    async def safe_filter(self, expr: str) -> Any:
        """Parameterized replacement for ``ModelView._filtering`` (G7).

        ``expr`` is ``<field>=<value>``. ``<field>`` must be in
        ``public_columns`` **and** a real model column, else 400. The value is
        bound as ``$1`` — never interpolated — and the ownership predicate is
        ANDed in for non-superusers.

        This override is still required on ``navigator-api`` 4.0.1, whose own
        ``_filtering`` is already parameterized (navigator/views/model.py:479):
        upstream's allowlist is "a real column not in ``_hidden``", and
        ``_hidden`` is derived from ``secret=True`` only (model.py:178) —
        which no credential column on these models declares. Upstream also
        applies no ownership predicate. Do not delete this as redundant.

        Args:
            expr: The raw ``_filter`` query-parameter value.

        Returns:
            The matching rows, already restricted to the acting user when the
            caller is not a superuser.

        Raises:
            web.HTTPBadRequest: malformed ``expr``, or a field outside
                ``public_columns`` / absent from the model.
        """
        # FILL IN:
        #  - column, sep, value = expr.partition('='); refuse 400 when not sep
        #    or not column.strip() (AC-17).
        #  - refuse 400 when column not in self.public_columns OR column not
        #    in <model>.get_columns(). Check public_columns FIRST so a
        #    credential column is refused identically whether or not it is a
        #    real column — no existence oracle (AC-18, AC-19).
        #  - build the statement with the column name taken from the MODEL
        #    (never from the request) and the value bound as $1; AND the
        #    ownership predicate as $2 for a non-superuser. Quote the
        #    identifiers and qualify with Meta.schema/Meta.name, as upstream
        #    does at model.py:529-540. Execute through the handler's
        #    connection with conn.fetch_all(sql, *args) — the repo idiom at
        #    passkey/store.py:44. Bounded by AC-20, AC-21.
        #  - a superuser filter issues the statement WITHOUT the owner
        #    predicate, and must be audited via audit_decision (AC-22).

    async def audit_decision(
        self,
        action: str,
        allowed: bool,
        owner_id: Optional[int],
        reason: str,
    ) -> None:
        """Record one admin / cross-user decision through ``AuditLog``.

        Never raises: an audit backend is remote (influx / mongo / SQL via
        ``AUDIT_DSN``), and a failure to write the record must not turn an
        authorized request into a 500 — the same guard the PDP itself applies
        at abac/pdp.py:483-487.

        Args:
            action: The action that was decided.
            allowed: The decision.
            owner_id: Owner of the target row, for the record.
            reason: Human-readable explanation, as returned by
                :func:`policy_allows`.
        """
        # FILL IN:
        #  - build answer = PolicyResponse(effect=PolicyEffect.ALLOW if
        #    allowed else PolicyEffect.DENY, response=<message naming actor,
        #    action, target owner>, rule=self.policy_name,
        #    actions=[action]) — the shape AuditLog reads (audit.py:181-182).
        #  - auditlog = getattr(_get_pdp-ish pdp, "_auditlog", None) or
        #    AuditLog(): prefer the PDP's instance (pdp.py:85) so the
        #    configured backend/connection is reused; fall back to a fresh
        #    AuditLog(). Reach the PDP via request.app.get("abac") or
        #    getattr(request.app.get("security"), "pdp", None) — the same
        #    lookup as decorators._get_pdp:994.
        #  - await auditlog.log(answer, "ALLOW" if allowed else "DENY", user)
        #    inside try/except Exception -> logger.warning. Bounded by
        #    AC-23, AC-24, AC-25.
```

**Why `public_columns` is checked before the model's column list.** If the
order were reversed, `?_filter=access_token=x` (a real column, not public)
and `?_filter=nonsense=x` (not a column at all) would return *different*
400s, and the difference tells an attacker which columns exist. Check the
allowlist first and emit one message for both.

**Why the column name must come from the model, not from the request —
even after validation.** The validated string and the model's key are equal
by then, so it reads like a pointless substitution. It is not: it means the
statement is built from values the process owns, so a future edit that
relaxes the validation cannot reach the SQL text. The value is bound; the
identifier is ours.

**Why the ownership predicate is `$2` and not string-built.** Same reason as
`$1`, and because the acting `user_id` comes from a session the caller
influences. Bind both.

**Why `audit_decision` prefers the PDP's `AuditLog`.** `AuditLog.__init__`
(`audit.py:208`) selects a backend from config and, for the SQL/influx/mongo
families, builds a driver. Constructing a new one per request would open a
connection per request. The PDP already has one; reuse it.

**Why `audit_decision` is called on the deny paths too.** G6 says "every
cross-user and every admin decision (allow and deny)". A refused cross-user
attempt is the single most interesting event this feature produces — an
audit trail with only the successes is a log of authorized activity, not a
security record.

### `tests/unit/handlers/test_owner_superuser_guard.py` — CREATE

```python
"""Unit tests for OwnerOrSuperuserGuard (FEAT-105, TASK-122).

The mixin is driven through a synthetic host so no handler is involved: this
task must not depend on, or change, userattrs.py / partners.py.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.handlers.guards import OwnerOrSuperuserGuard

pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)

PUBLIC = frozenset({"identity_id", "user_id", "email", "auth_provider"})
CREDENTIALS = frozenset({"access_token", "refresh_token", "id_token", "key_version"})


class Host(OwnerOrSuperuserGuard):
    """Minimal host exposing only what the mixin is documented to need."""

    owner_column = "user_id"
    credential_columns = CREDENTIALS
    public_columns = PUBLIC
    policy_name = "user_identities_admin_access"
    superuser_actions = frozenset({
        "identity:read", "identity:revoke", "identity:delete",
    })

    def __init__(self, request):
        self.request = request

    def error(self, response=None, status=400, **kwargs):
        """Mirror BaseHandler.error(): RAISE, never return."""
        # FILL IN: map 400/401/403/404 to the matching web.HTTPxxx and raise
        # it, exactly as navigator/views/base.py:226-243 does. Getting this
        # wrong makes every deny test pass for the wrong reason — AC-26.


class OwnerlessHost(Host):
    owner_column = None


class FakePDP:
    def __init__(self, policies, auditlog=None):
        self._evaluator = None
        self._policies = policies
        self._auditlog = auditlog

    @property
    def policies(self):
        return self._policies


def _request(pdp=None, path="/api/v1/user_identity/abc"):
    # FILL IN: web.Application(); app["abac"] = pdp when given;
    # make_mocked_request("GET", path, app=app); request["authenticated"]=True.


def _session(user_id=42, groups=("users",)):
    # FILL IN: a dict-like session with {"session": {"user_id": user_id,
    # "username": "u", "groups": list(groups)}} and a decode() returning None
    # — the shape abstract.py:316-320 and decorators.py:1061 read.


def _patch_session(session):
    return patch(
        "navigator_auth.handlers.guards.get_session",
        new=AsyncMock(return_value=session),
    )


class TestActingUser:
    @pytest.mark.asyncio
    async def test_requires_session(self):
        """No session => 401, not 403 and not a bare None."""
        # FILL IN: patch get_session to return None; pytest.raises(
        # web.HTTPUnauthorized) — bounded by AC-1, AC-2.

    @pytest.mark.asyncio
    async def test_superuser_via_group_only(self):
        """groups=["superuser"] is a superuser; "ex_superuser_revoked" is not."""
        # FILL IN: two cases. The second guards the _check_superuser
        # substring contract (cf. tests/test_check_superuser.py) — AC-3.

    @pytest.mark.asyncio
    async def test_superuser_via_attribute(self):
        """userinfo["superuser"] is True also counts."""
        # FILL IN: bounded by AC-3.


class TestAuthorizeRow:
    @pytest.mark.asyncio
    async def test_owner_needs_no_policy(self):
        """The owner is allowed with no PDP configured at all."""
        # FILL IN: request with pdp=None, owner_id == session user_id;
        # assert the call returns True — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_owner_writes_no_audit_record(self):
        """Self-service access produces no AuditLog entry."""
        # FILL IN: patch AuditLog in the guards module; assert .log was never
        # awaited — bounded by AC-5.

    @pytest.mark.asyncio
    async def test_owner_id_type_mismatch_still_matches(self):
        """A str owner_id from a dict row matches an int session user_id."""
        # FILL IN: owner_id="42", session user_id=42 — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_foreign_row_refused_403(self):
        """A non-superuser on a foreign row => HTTPForbidden."""
        # FILL IN: bounded by AC-6.

    @pytest.mark.asyncio
    async def test_foreign_row_refused_404_when_asked(self):
        """not_found_on_deny=True => HTTPNotFound, so the PK is no oracle."""
        # FILL IN: bounded by AC-7.

    @pytest.mark.asyncio
    async def test_deny_body_leaks_no_row_data(self):
        """The refusal body names no column value of the foreign row."""
        # FILL IN: inspect the raised exception's text; assert it contains
        # neither the owner_id nor any column name — bounded by AC-12.

    @pytest.mark.asyncio
    async def test_ownerless_requires_superuser(self):
        """owner_column=None => a non-superuser is refused for every action."""
        # FILL IN: OwnerlessHost, loop over the three actions — AC-8 is about
        # the action envelope; this one is bounded by AC-6 and spec G8.

    @pytest.mark.asyncio
    async def test_action_outside_superuser_actions_refused(self):
        """Refused even when the policy would allow it."""
        # FILL IN: superuser session, a PDP whose policy allows everything,
        # action="identity:refresh" => refused — bounded by AC-8.

    @pytest.mark.asyncio
    async def test_missing_policy_name_refuses_without_valueerror(self):
        """policy_name=None => clean deny, not a ValueError/500."""
        # FILL IN: a Host subclass with policy_name=None; superuser session;
        # assert HTTPForbidden and NOT ValueError — bounded by AC-9.

    @pytest.mark.asyncio
    async def test_fails_closed_without_pdp(self):
        """Superuser + no ABAC => denied; the owner path still works."""
        # FILL IN: assert the cross-user call raises and that an owner call on
        # the same request returns True — bounded by AC-10.

    @pytest.mark.asyncio
    async def test_cross_user_allow_is_audited(self):
        """One AuditLog.log call carrying .response and .rule."""
        # FILL IN: assert log awaited once; inspect the answer argument for a
        # non-empty .response and .rule == policy_name — bounded by AC-23.

    @pytest.mark.asyncio
    async def test_cross_user_deny_is_audited(self):
        """A refused cross-user attempt is recorded too."""
        # FILL IN: bounded by AC-24.

    @pytest.mark.asyncio
    async def test_audit_backend_failure_does_not_break_the_request(self):
        """AuditLog.log raising must not change the authorization outcome."""
        # FILL IN: log=AsyncMock(side_effect=RuntimeError); assert the allow
        # path still returns True — bounded by AC-25.


class TestSanitizeQuery:
    @pytest.mark.asyncio
    async def test_fields_intersected_with_allowlist(self):
        """?fields=access_token,email => ["email"]."""
        # FILL IN: bounded by AC-13.

    @pytest.mark.asyncio
    async def test_foreign_owner_param_refused(self):
        """?user_id=<other> as a non-superuser => 403, no TypeError."""
        # FILL IN: assert HTTPForbidden — bounded by AC-14.

    @pytest.mark.asyncio
    async def test_own_owner_param_is_dropped_not_merged(self):
        """?user_id=<self> is removed from qp so filter() cannot collide."""
        # FILL IN: assert the returned qp has no owner_column key — AC-15.

    @pytest.mark.asyncio
    async def test_superuser_may_name_a_foreign_owner(self):
        """?user_id=<other> survives for a superuser."""
        # FILL IN: bounded by AC-14.

    @pytest.mark.asyncio
    async def test_credential_qp_key_dropped_for_everyone(self):
        """?access_token=... never reaches the model, owner included."""
        # FILL IN: bounded by AC-16.


class TestSafeFilter:
    @pytest.mark.asyncio
    async def test_rejects_non_allowlisted_field(self):
        """_filter=access_token=x => 400 and NO query is issued."""
        # FILL IN: a recording connection; assert HTTPBadRequest and that the
        # recorder captured nothing — bounded by AC-18.

    @pytest.mark.asyncio
    async def test_rejects_unknown_field_identically(self):
        """An unknown column and a credential column give the same 400 text."""
        # FILL IN: compare the two messages — bounded by AC-19.

    @pytest.mark.asyncio
    async def test_rejects_malformed_expression(self):
        """"justafield" with no '=' => 400, no ValueError."""
        # FILL IN: bounded by AC-17.

    @pytest.mark.asyncio
    async def test_binds_value_as_parameter(self):
        """The SQL contains $1 and "' OR 1=1 --" is passed as an argument."""
        # FILL IN: assert "$1" in sql and the payload in args and NOT in sql
        # — bounded by AC-20.

    @pytest.mark.asyncio
    async def test_ands_owner_predicate_for_non_superuser(self):
        """A non-superuser's filter carries owner_column = <acting user>."""
        # FILL IN: assert the owner column appears in the WHERE clause and the
        # acting user_id is among the bound args — bounded by AC-21.

    @pytest.mark.asyncio
    async def test_superuser_filter_has_no_owner_predicate_and_is_audited(self):
        """A superuser filter spans users and is recorded."""
        # FILL IN: bounded by AC-22.
```

**Why `Host.error` must raise in the tests.** If the test double returned a
response instead, `authorize_row` would appear to "return" on the deny paths
and every deny assertion would pass against an implementation that leaks.
The double must reproduce `BaseHandler.error`'s raise-always contract — that
is why AC-26 exists and why this body is in the FILL IN checklist.

**Why `test_rejects_unknown_field_identically` compares message text.** The
two 400s are individually correct and jointly an oracle: different wording
for "not public" and "not a column" tells a caller which columns exist. The
assertion is about them being *indistinguishable*.

**Why `test_audit_backend_failure_does_not_break_the_request` matters.** The
audit call sits on the success path of every superuser read. Without this
test, a deployment with an unreachable `AUDIT_DSN` turns every admin request
into a 500 and the cause is three layers down.

**Why `test_owner_writes_no_audit_record` is an assertion and not a comment.**
It pins a deliberate decision (owner access is not audited) that otherwise
looks like an omission, so a later "let's audit everything" change has to be
a conscious one.

### Steps (in order)

1. Confirm dependencies are in place: `from navigator_auth.handlers.redaction
   import safe_fields` and `from navigator_auth.decorators import
   policy_allows` must both import. If either fails, TASK-118/TASK-119 are
   not merged yet — stop.
2. Create `guards.py` with Block 1 (header, attributes, `acting_user`) and
   fill `acting_user`. Run only `TestActingUser` before going on: every other
   method begins by calling it, so a wrong session read makes all the later
   failures uninformative.
3. Add Block 2 and fill `authorize_row`, then `sanitize_query`. Write the
   deny paths before the allow paths — the allow path is easy to get right by
   accident.
4. Add Block 3 and fill `safe_filter`, then `audit_decision`.
5. Create the test module. Fill `Host.error`, `_request` and `_session`
   first — three helpers that every test depends on.
6. Fill the test bodies class by class, running each class as you go.
7. Run `pytest tests/unit/handlers/test_owner_superuser_guard.py -v`, then
   the regression gate:
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`.
8. `ruff check navigator_auth/handlers/guards.py tests/unit/handlers/`.
9. Confirm the blast radius: `git diff --name-only` lists exactly
   `navigator_auth/handlers/guards.py` and the new test file. **No change to
   `userattrs.py`, `partners.py`, `model.py`, `handler.py`, `redaction.py` or
   `decorators.py`** (AC-27).

### FILL IN checklist

- [ ] `acting_user` body — session read, 401s, `_check_superuser(userinfo, user)` — AC-1, AC-2, AC-3
- [ ] `authorize_row` body — the six ordered steps — AC-4..AC-12
- [ ] `sanitize_query` body — fields intersection, owner-param refusal, credential drop — AC-13..AC-16
- [ ] `safe_filter` body — parse, allowlist-first validation, bound `$1`/`$2`, owner AND — AC-17..AC-22
- [ ] `audit_decision` body — `PolicyResponse`, PDP's `AuditLog`, try/except — AC-23..AC-25
- [ ] `Host.error` double — raise-always, status-mapped — AC-26
- [ ] `_request` / `_session` helpers
- [ ] `TestActingUser` — 3 bodies — AC-1..AC-3
- [ ] `TestAuthorizeRow` — 13 bodies — AC-4..AC-12, AC-23..AC-25
- [ ] `TestSanitizeQuery` — 5 bodies — AC-13..AC-16
- [ ] `TestSafeFilter` — 6 bodies — AC-17..AC-22

---

## Acceptance Criteria

- [ ] **AC-1** `acting_user()` raises `web.HTTPUnauthorized` when there is no session.
- [ ] **AC-2** It raises `web.HTTPUnauthorized` when the session carries no `user_id`.
- [ ] **AC-3** It reports superuser for `groups=["superuser"]` and for `userinfo["superuser"] is True`, and **not** for `groups="ex_superuser_revoked"`.
- [ ] **AC-4** `authorize_row()` returns `True` for the owner with **no PDP configured**, including when `owner_id` is a `str` and the session `user_id` an `int`.
- [ ] **AC-5** The owner path makes no `policy_allows` call and writes no `AuditLog` record.
- [ ] **AC-6** A non-superuser on a foreign row raises `web.HTTPForbidden`; with `owner_column = None` every action is refused for a non-superuser.
- [ ] **AC-7** `not_found_on_deny=True` raises `web.HTTPNotFound` instead.
- [ ] **AC-8** An action outside `superuser_actions` is refused even when the policy allows it.
- [ ] **AC-9** `policy_name` falsy yields a clean refusal — never a `ValueError` and never a 500.
- [ ] **AC-10** With no PDP, with the policy undeclared, and with a policy that raises, the superuser path is denied in all three cases while the owner path keeps working.
- [ ] **AC-11** A superuser whose policy allows the action gets `True`.
- [ ] **AC-12** No refusal body contains the target row's owner id or any column value.
- [ ] **AC-13** `sanitize_query` intersects `fields` with `public_columns` (`["access_token","email"] → ["email"]`).
- [ ] **AC-14** A non-superuser naming a foreign `owner_column` value is refused 403; a superuser's value survives.
- [ ] **AC-15** A non-superuser naming their **own** `owner_column` value has the key removed from `qp` (so `filter(**qp, **_filter)` cannot collide).
- [ ] **AC-16** A `credential_columns` member used as a query-parameter key is dropped for everyone.
- [ ] **AC-17** `safe_filter` answers 400 on a malformed expression, with no `ValueError`.
- [ ] **AC-18** `_filter=access_token=x` answers 400 and issues **no** query.
- [ ] **AC-19** A non-allowlisted real column and an unknown column produce the same 400 message.
- [ ] **AC-20** The executed statement contains `$1`; the hostile value `' OR 1=1 --` appears in the bound arguments and never in the SQL text.
- [ ] **AC-21** A non-superuser's filter ANDs `owner_column = <acting user>`, bound as a parameter.
- [ ] **AC-22** A superuser's filter omits the owner predicate and produces an audit record.
- [ ] **AC-23** A cross-user allow produces exactly one `AuditLog.log` call whose `answer` carries a non-empty `.response` and `.rule == policy_name`.
- [ ] **AC-24** A cross-user deny also produces one record.
- [ ] **AC-25** An `AuditLog.log` that raises does not change the authorization outcome and does not propagate.
- [ ] **AC-26** The test double's `error()` raises (mirrors `BaseHandler.error`), so the deny assertions are meaningful.
- [ ] **AC-27** `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes, `ruff check navigator_auth/handlers/guards.py tests/unit/handlers/` is clean, and no file other than the two in the table is modified.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_owner_superuser_guard.py -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q   # regression
ruff check navigator_auth/handlers/guards.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §2 Overview layers 1/2/4, §2 Component Diagram, §2 New Public Interfaces,
   §3 Module 3, §4 the seven Module-3 rows, §7 Patterns to Follow.
2. **Check dependencies** — TASK-118 (`handlers/redaction.py`) and TASK-119
   (`decorators.policy_allows`) must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. The ordered steps inside `authorize_row`
   are the security property — do not reorder them.
5. **Verify** every acceptance criterion, AC-26 and AC-27 included.
6. **Move this file** to `sdd/tasks/completed/TASK-122-owner-or-superuser-guard.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-24
**Notes**: 30 tests pass; regression gate green; ruff clean.

**Deviations from spec**: none
