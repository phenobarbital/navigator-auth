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
from typing import Any, Iterable, Optional

from navigator_session import get_session

from ..abac.audit import AuditLog
from ..abac.policies import PolicyEffect
from ..abac.policies.abstract import PolicyResponse
from ..conf import AUTH_PROTECTED_GROUPS, AUTH_SESSION_OBJECT
from ..decorators import SUPERUSER_GROUP, _check_superuser, policy_allows
from .redaction import safe_fields

logger = logging.getLogger("navigator.auth.guards")

_BAD_FILTER = "Invalid _filter"
_GRANT_ROLE_POLICY = "users_grant_role"
_GRANT_ROLE_ACTION = "users:grant_role"


def protected_groups() -> frozenset[str]:
    """Return the effective protected group set."""
    return frozenset(AUTH_PROTECTED_GROUPS) | {SUPERUSER_GROUP}


class OwnerOrSuperuserGuard:
    """Owner-or-superuser authorization for generic model handlers.

    Per-surface behaviour is configuration, not forked logic: subclasses set
    the nine class attributes below and call the coroutines from their own
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
        writable_by_owner: Columns the owner may update.
        writable_by_admin: Columns the authorized admin path may update.
        creatable_by_admin: Columns the authorized admin path may set when
            creating. ``None`` uses ``writable_by_admin``.
        privileged_columns: Columns no CRUD path may write.
    """

    owner_column: Optional[str] = "user_id"
    credential_columns: frozenset[str] = frozenset()
    public_columns: frozenset[str] = frozenset()
    policy_name: Optional[str] = None
    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})
    #: Write side (FEAT-107). Allowlists, never denylists (spec G3): a key
    #: absent from the applicable set is refused, so a column added to the
    #: model later is closed by default. All empty by default, and only
    #: consulted when ``authorize_row`` receives a ``payload`` — the FEAT-105
    #: handlers pass none and are unaffected (spec G7).
    writable_by_owner: frozenset[str] = frozenset()
    writable_by_admin: frozenset[str] = frozenset()
    #: ``None`` means "same as ``writable_by_admin``".
    creatable_by_admin: Optional[frozenset[str]] = None
    #: Writable by NO CRUD path, owner included, create included.
    privileged_columns: frozenset[str] = frozenset()

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    async def _session_info(self) -> tuple[Any, dict, Any]:
        """Return ``(session, userinfo, user)`` or raise 401."""
        try:
            session = await get_session(self.request)
        except (RuntimeError, ValueError):
            session = None
        if not session:
            self.error(response={"error": "Unauthorized"}, status=401)
        try:
            if AUTH_SESSION_OBJECT in session:
                userinfo = session[AUTH_SESSION_OBJECT]
            else:
                userinfo = session
        except (KeyError, TypeError):
            userinfo = None
        if not userinfo:
            self.error(response={"error": "Unauthorized"}, status=401)
        user = None
        try:
            user = session.decode("user")
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
            user = None
        return session, userinfo, user

    async def acting_user(self) -> tuple[int, bool]:
        """Resolve ``(user_id, is_superuser)`` for the current request.

        Returns:
            The session's ``user_id`` and whether it has superuser
            privileges, decided by
            :func:`navigator_auth.decorators._check_superuser`.

        Raises:
            web.HTTPUnauthorized: no session, or no ``user_id`` in it.
        """
        _, userinfo, user = await self._session_info()
        try:
            user_id = userinfo["user_id"]
        except (KeyError, TypeError):
            user_id = None
        if user_id is None:
            self.error(response={"error": "Unauthorized"}, status=401)
        return user_id, _check_superuser(userinfo, user)

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------
    def _refuse(self, not_found: bool = False):
        """Raise a generic refusal that confirms nothing about the row."""
        if not_found:
            self.error(response={"error": "Not Found"}, status=404)
        self.error(response={"error": "Forbidden"}, status=403)

    async def authorize_row(
        self,
        action: str,
        owner_id: Optional[int],
        *,
        not_found_on_deny: bool = False,
        payload: Optional[Iterable[str]] = None,
        creating: bool = False,
    ) -> bool:
        """Authorize one row operation. Owner, else policy-gated superuser.

        Args:
            action: The action to authorize, e.g. ``"identity:read"``. For the
                superuser path it must be a member of ``superuser_actions``.
            owner_id: The row's owner ``user_id``, or ``None`` when the row
                has no owner (``owner_column is None``) or does not exist.
            not_found_on_deny: Answer 404 instead of 403, so a primary-key
                probe cannot be used to confirm that a foreign row exists.
            payload: The client-supplied keys of a write (dict or iterable of
                column names). ``None`` — reads, deletes and every FEAT-105
                caller — skips the column check entirely. A write caller that
                omits it gets the pre-FEAT-107 blanket owner allow back, so
                every write hook MUST pass it (TASK-151 / TASK-155).
            creating: The payload is for a new row; checked against
                ``creatable_by_admin``. There is no owner create path.

        Returns:
            ``True``. This method **never returns False** — see the module
            docstring; a refusal is raised.

        Raises:
            web.HTTPForbidden: refused (``not_found_on_deny`` is False).
            web.HTTPNotFound: refused (``not_found_on_deny`` is True).
            web.HTTPUnauthorized: no session.
        """
        user_id, is_superuser = await self.acting_user()
        if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):
            if payload is not None:
                await self.authorize_columns(
                    payload, is_owner=True, creating=creating, action=action, owner_id=owner_id
                )
            return True
        if not is_superuser:
            await self.audit_decision(action, False, owner_id, f"user {user_id} is not the owner and not a superuser")
            self._refuse(not_found_on_deny)
        if action not in self.superuser_actions:
            await self.audit_decision(action, False, owner_id, f"action '{action}' is outside superuser_actions")
            self._refuse(not_found_on_deny)
        if not self.policy_name:
            await self.audit_decision(action, False, owner_id, "handler has no policy_name: cross-user access disabled")
            self._refuse(not_found_on_deny)
        allowed, reason, _ = await policy_allows(
            self.policy_name,
            self.request,
            action=action,
            resource=self.request.path,
        )
        await self.audit_decision(action, bool(allowed), owner_id, reason)
        if not allowed:
            self._refuse(not_found_on_deny)
        if payload is not None:
            await self.authorize_columns(payload, is_owner=False, creating=creating, action=action, owner_id=owner_id)
        return True

    async def authorize_columns(
        self,
        payload: Iterable[str],
        *,
        is_owner: bool,
        creating: bool = False,
        action: Optional[str] = None,
        owner_id: Optional[int] = None,
    ) -> None:
        """Refuse a write whose payload touches a column this path may not write.

        Allowlist semantics (spec G3). The applicable set is:

            creating             -> creatable_by_admin (or writable_by_admin)
            updating, owner      -> writable_by_owner
            updating, admin path -> writable_by_admin

        A key in ``privileged_columns`` is refused on every path, owner
        included, create included. There is no owner create path: a create
        always goes through the superuser path of :meth:`authorize_row`.

        Args:
            payload: The client-supplied keys (a dict iterates its keys).
            is_owner: The owner path authorized this write.
            creating: The payload is for a new row.
            action: For the audit record only.
            owner_id: For the audit record only.

        Raises:
            web.HTTPForbidden: A key falls outside the envelope. The body names
                only refused columns that are in ``public_columns``.
            TypeError: ``payload`` is a ``str``/``bytes`` (iterating it would
                yield characters, silently passing the check).
        """
        if isinstance(payload, (str, bytes)):
            raise TypeError("authorize_columns expects column names, not a string")
        keys = {str(key) for key in payload}
        label = action or ("columns:create" if creating else "columns:update")
        if creating and is_owner:
            await self.audit_decision(label, False, owner_id, "no owner create path")
            self._refuse()
        if creating:
            allowed = self.creatable_by_admin if self.creatable_by_admin is not None else self.writable_by_admin
        elif is_owner:
            allowed = self.writable_by_owner
        else:
            allowed = self.writable_by_admin
        refused = (keys & self.privileged_columns) | (keys - allowed)
        if not refused:
            return
        await self.audit_decision(label, False, owner_id, f"columns outside the write envelope: {sorted(refused)}")
        body: dict = {"error": "Forbidden"}
        named = safe_fields(sorted(refused), self.public_columns)
        if named:
            body["columns"] = named
        self.error(response=body, status=403)

    async def authorize_protected_group(
        self,
        group_names: Iterable[str],
        *,
        member_id: Optional[int] = None,
    ) -> None:
        """Gate a change that touches a protected group."""
        involved = {str(name) for name in group_names if name}
        protected = involved & protected_groups()
        if not protected:
            return

        names = sorted(protected)
        allowed, reason, _ = await policy_allows(
            _GRANT_ROLE_POLICY,
            self.request,
            action=_GRANT_ROLE_ACTION,
            resource=self.request.path,
        )
        if not allowed:
            await self.audit_decision(_GRANT_ROLE_ACTION, False, member_id, f"protected {names}: {reason}")
            self._refuse()

        user_id, is_superuser = await self.acting_user()
        if member_id is not None and str(member_id) == str(user_id):
            await self.audit_decision(_GRANT_ROLE_ACTION, False, member_id, f"self-add to protected {names}")
            self._refuse()

        _, userinfo, user = await self._session_info()
        for name in names:
            if name == SUPERUSER_GROUP:
                belongs = is_superuser
            else:
                groups = userinfo.get("groups") if isinstance(userinfo, dict) else None
                belongs = isinstance(groups, (list, tuple, set, frozenset)) and name in groups
                if not belongs and user is not None and hasattr(user, "groups"):
                    belongs = any(
                        (getattr(group, "group", None) or getattr(group, "group_name", None)) == name
                        for group in user.groups
                    )
            if not belongs:
                reason = f"actor does not belong to protected group '{name}'"
                await self.audit_decision(_GRANT_ROLE_ACTION, False, member_id, reason)
                self._refuse()

        await self.audit_decision(_GRANT_ROLE_ACTION, True, member_id, f"protected {names}: {reason}")

    async def sanitize_query(
        self,
        qp: dict,
        fields: Optional[list[str]],
    ) -> tuple[dict, Optional[list[str]]]:
        """Remove the parameter bypasses before any database access.

        Args:
            qp: Query parameters, as ``get_parameters()`` returns them with
                ``fields`` already popped out.
            fields: The caller's ``?fields=`` projection, or ``None``.

        Returns:
            ``(qp, fields)`` — sanitized. ``fields`` is intersected with
            ``public_columns``; ``qp`` keeps only safe keys.

        Raises:
            web.HTTPForbidden: a non-superuser named a foreign
                ``owner_column`` value.
        """
        user_id, is_superuser = await self.acting_user()
        safe = safe_fields(fields, self.public_columns)
        clean = dict(qp or {})
        for key in list(clean):
            if key in self.credential_columns:
                clean.pop(key)
        owner = self.owner_column
        if owner and owner in clean and not is_superuser:
            if str(clean[owner]) != str(user_id):
                self._refuse()
            # Drop rather than merge: the forced `_filter_<owner>` value and a
            # surviving key collide in ``filter(**qp, **_filter)``.
            clean.pop(owner)
        return clean, safe

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------
    def _guard_model(self) -> Any:
        model = getattr(self, "get_model", None) or getattr(self, "model", None)
        if model is None:
            raise RuntimeError("OwnerOrSuperuserGuard host has no model")
        return model

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
            The matching values as ``[{column: value}]``, already restricted to the
            acting user when the caller is not a superuser.

        Raises:
            web.HTTPBadRequest: malformed ``expr``, or a field outside
                ``public_columns`` / absent from the model.
        """
        user_id, is_superuser = await self.acting_user()
        column, sep, value = (expr or "").partition("=")
        column = column.strip()
        if not sep or not column:
            self.error(response={"error": _BAD_FILTER}, status=400)
        model = self._guard_model()
        # public_columns FIRST, one message for both failures: no oracle.
        if column not in self.public_columns or column not in model.get_columns():
            self.error(response={"error": _BAD_FILTER}, status=400)
        # Same shape as upstream's autocomplete filter: only the filtered
        # (public) column is selected and returned, never the whole row.
        selected = f'"{column}"'
        table = model.Meta.name
        schema = getattr(model.Meta, "schema", None)
        qualified = f'"{schema}"."{table}"' if schema else f'"{table}"'
        sql = f"SELECT {selected} FROM {qualified} " f'WHERE "{column}"::text LIKE $1'
        args: list = [f"{value}%"]
        # A superuser widens the filter ONLY when the named policy allows the
        # read action; otherwise (no PDP, undeclared/raising policy) the
        # owner predicate stays and they see their own rows like anyone.
        widen = False
        if is_superuser and self.policy_name:
            action = next(
                (a for a in sorted(self.superuser_actions) if a.endswith(":read")),
                None,
            )
            if action:
                allowed, reason, _ = await policy_allows(
                    self.policy_name,
                    self.request,
                    action=action,
                    resource=self.request.path,
                )
                await self.audit_decision(action, bool(allowed), None, f"filter on '{column}': {reason}")
                widen = bool(allowed)
        if not widen and self.owner_column:
            sql += f' AND "{self.owner_column}" = $2'
            args.append(user_id)
        async with await self.handler(request=self.request) as conn:
            rows = await conn.fetch_all(sql, *args)
        return [dict(r) for r in (rows or [])]

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
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
        try:
            session, userinfo, user = await self._session_info()
            actor = userinfo.get("username") or userinfo.get("user_id")
            answer = PolicyResponse(
                effect=PolicyEffect.ALLOW if allowed else PolicyEffect.DENY,
                response=(
                    f"{'ALLOW' if allowed else 'DENY'}: actor={actor} "
                    f"action={action} target_owner={owner_id} "
                    f"reason={reason}"
                ),
                rule=self.policy_name,
                actions=[action],
            )
            app = self.request.app
            pdp = app.get("abac") or getattr(app.get("security"), "pdp", None)
            auditlog = getattr(pdp, "_auditlog", None) or AuditLog()
            await auditlog.log(answer, "ALLOW" if allowed else "DENY", user or actor)
        except Exception as exc:  # noqa: BLE001 - audit must never break a request
            logger.warning("Error saving guard audit record: %s", exc)
