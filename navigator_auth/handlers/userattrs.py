from datetime import datetime, timezone
from typing import Any
from aiohttp import web
from asyncdb.exceptions import NoDataFound
from asyncdb.exceptions import DriverError
from navigator_session import get_session, AUTH_SESSION_OBJECT
from ..models import UserAccount, UserIdentity, VwUserIdentity
from ..conf import AUTH_USER_IDENTITY_MODEL

# from .model import ModelHandler
from .handler import ModelHandler
from .guards import OwnerOrSuperuserGuard
from .redaction import redact_row, redact_rows, redact_schema, safe_fields


class UserAccountHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Owner-or-superuser CRUD over ``auth.user_accounts`` (FEAT-105).

    Same guard as ``UserIdentityHandler``, different column set. This model
    carries no token material, so ``credential_columns`` is empty and the
    projection is a plain allowlist.
    """

    model: Any = UserAccount  # verified: navigator_auth/models.py:297
    name: str = "User Account"
    pk: str = "account_id"

    owner_column: str = "user_id"
    #: No token material on this model — see spec §2 Data Models.
    credential_columns = frozenset()
    public_columns = frozenset({"account_id", "user_id", "provider", "uid", "address", "account", "created_at"})
    policy_name: str = "user_accounts_admin_access"
    superuser_actions = frozenset({"account:read", "account:revoke", "account:delete"})

    # Per-subclass copies (see UserIdentityHandler). Never RELY on _hidden:
    # no column on UserAccount declares secret=True.
    _hidden: list = []
    _required: list = []
    _primaries: list = []
    #: G9: the provider is bound as $1, never interpolated. The previous form
    #: inlined it inside a quoted literal, so a provider of ``x' OR 1=1 --``
    #: rewrote the statement.
    social_network: str = "SELECT social_url FROM auth.social_networks " "WHERE social_network = $1"

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    async def _set_address(self, value, column, data):
        try:
            userid = data["uid"]
        except KeyError:
            return self.error(reason=f"Invalid User ID for {self.name}", status=410)
        try:
            provider = data["provider"]
        except KeyError:
            provider = None
        if provider:
            try:
                async with await self.handler(request=self.request) as conn:
                    result = await conn.fetchval(self.social_network, provider, column="social_url")
                    if result:
                        return result.format(uid=userid)
            except DriverError:
                pass
        return None

    # ------------------------------------------------------------------
    # Access control and redaction (TASK-126) — mirrors UserIdentityHandler
    # with the ``account:*`` actions. ``UserAccount`` has no revocation
    # column, so a superuser's only mutating power on a foreign row is
    # ``account:delete``; every cross-user PATCH/POST/PUT is refused.
    # ------------------------------------------------------------------
    def _require_owner_column(self) -> str:
        """Return the owner column, or refuse the request with 501."""
        model = getattr(self, "get_model", None) or self.model
        if not self.owner_column or self.owner_column not in model.get_columns():
            raise web.HTTPNotImplemented(
                text='{"error": "Not Implemented"}',
                content_type="application/json",
            )
        return self.owner_column

    async def _pre_get(self, *args, **kwargs) -> bool:
        """Gate the read path: 501, 401, foreign-owner-param refusal."""
        self._require_owner_column()
        await self.acting_user()
        qp = dict(self.query_parameters(self.request))
        qp.pop("fields", None)
        await self.sanitize_query(qp, None)
        return True

    async def _get_data(self, qp: dict, args: dict):
        """Bind every read to an owner; widen + authorize for a superuser.

        The owner predicate is installed as an instance-level
        ``_filter_<owner>`` for non-superusers only (see
        ``UserIdentityHandler._get_data`` for why a class hook cannot carry
        the superuser case).
        """
        owner_col = self._require_owner_column()
        user_id, is_superuser = await self.acting_user()
        qp, _ = await self.sanitize_query(qp, None)
        primary = await self._get_primary_data(args)
        widen = False
        if is_superuser:
            if primary is not None:
                widen = True
            elif owner_col in qp and str(qp[owner_col]) != str(user_id):
                await self.authorize_row("account:read", owner_id=qp[owner_col])
                widen = True
        if not widen:
            qp = {k: v for k, v in qp.items() if k != owner_col}

            async def _bind_owner(value=None, column=None, data=None):
                return user_id

            setattr(self, f"_filter_{owner_col}", _bind_owner)
        try:
            result = await super()._get_data(qp, args)
        except NoDataFound:
            if primary is not None:
                self.error(response={"error": "Not Found"}, status=404)
            raise
        if primary is not None:
            rows = [r for r in (result if isinstance(result, list) else [result]) if r]
            if not rows:
                self.error(response={"error": "Not Found"}, status=404)
            if widen:
                for row in rows:
                    owner = row.get(owner_col) if isinstance(row, dict) else getattr(row, owner_col, None)
                    await self.authorize_row("account:read", owner, not_found_on_deny=True)
        return result

    async def _pre_write(self) -> bool:
        """Shared gate for the four write verbs: 501 then 401."""
        self._require_owner_column()
        await self.acting_user()
        return True

    async def _pre_put(self, *args, **kwargs) -> bool:
        """Gate an insert: a foreign ``user_id`` is refused for every role."""
        await self._pre_write()
        user_id, _ = await self.acting_user()
        try:
            raw = await self.json_data()
        except Exception:  # noqa: BLE001 - malformed body is upstream's 400
            raw = None
        for element in (raw if isinstance(raw, list) else [raw]):
            if (
                isinstance(element, dict)
                and element.get(self.owner_column) is not None
                and str(element[self.owner_column]) != str(user_id)
            ):
                self.error(response={"error": "Forbidden"}, status=403)
        return True

    async def _pre_patch(self, *args, **kwargs) -> bool:
        """Gate a partial update; row ownership is decided in `_set_update`."""
        return await self._pre_write()

    async def _pre_post(self, *args, **kwargs) -> bool:
        """Gate an upsert."""
        return await self._pre_write()

    async def _pre_delete(self, *args, **kwargs) -> bool:
        """Gate a delete; the target is resolved in `_del_primary_data`."""
        return await self._pre_write()

    async def _post_user_id(self, value, column, data):
        """Fill ``user_id`` from the session only when the payload omits it."""
        if value is not None:
            return value
        return await self.get_userid(session=self._session)

    async def _patch_user_id(self, value, column, data):
        """Leave ``user_id`` as sent on PATCH (``_set_user_id`` would clobber)."""
        return value

    async def _post_data(self, *args, **kwargs):
        """Bind the owner on insert/upsert. Covers PUT and POST.

        Delegates to ``super()`` first so ``_set_address`` still runs.
        """
        data = await super()._post_data(*args, **kwargs)
        user_id, _ = await self.acting_user()
        owner_col = self.owner_column
        for element in (data if isinstance(data, list) else [data]):
            if not isinstance(element, dict):
                continue
            value = element.get(owner_col)
            if value is None:
                element[owner_col] = user_id
            elif str(value) != str(user_id):
                self.error(response={"error": "Forbidden"}, status=403)
        return data

    async def _set_update(self, model, data) -> None:
        """Authorize the update against the fetched row, then delegate.

        Only the owner may write a row; there is no revocation column, so a
        superuser has no permitted cross-user payload (403, audited).
        """
        owner_col = self.owner_column
        owner_id = getattr(model, owner_col, None)
        user_id, is_superuser = await self.acting_user()
        if owner_col in data:
            if data[owner_col] is None:
                data.pop(owner_col)
            elif str(data[owner_col]) != str(owner_id):
                self.error(response={"error": "Forbidden"}, status=403)
        if owner_id is None or str(owner_id) != str(user_id):
            if is_superuser:
                await self.audit_decision(
                    "account:revoke", False, owner_id, "cross-user write: user_accounts has no revocation column"
                )
                self.error(response={"error": "Forbidden"}, status=403)
            await self.authorize_row("account:revoke", owner_id)
        return await super()._set_update(model, data)

    async def _del_primary_data(self, args: dict):
        """Resolve and authorize the delete target; 404 on deny.

        A request with no id is refused so upstream cannot fall into its
        body-driven delete paths, which never see a row owner.
        """
        objid = (args or {}).get("id") or (args or {}).get(self.pk)
        if not objid:
            self.error(
                response={"error": "A primary key is required in the URL"},
                status=400,
            )
        row = None
        try:
            async with await self.handler(request=self.request) as conn:
                self.model.Meta.connection = conn
                row = await self.model.get(**{self.pk: objid})
        except Exception:  # noqa: BLE001 - missing/invalid id => no owner
            row = None
        owner_id = getattr(row, self.owner_column, None) if row else None
        await self.authorize_row("account:delete", owner_id, not_found_on_deny=True)
        return objid

    def _scrub(self, result: Any) -> Any:
        """Project a write/delete response body onto ``public_columns``."""
        if isinstance(result, (list, tuple)):
            return [self._scrub(item) for item in result]
        if isinstance(result, dict):
            if set(result) & self.public_columns:
                return redact_row(result, self.public_columns)
            return result
        if result is None or isinstance(result, (str, bytes, int, float, bool)):
            return result
        if any(hasattr(result, c) for c in self.public_columns):
            return redact_row(result, self.public_columns)
        return result

    async def _patch_response(self, result, status: int = 202):
        """Project the PATCH response body."""
        return await super()._patch_response(self._scrub(result), status=status)

    async def _post_response(self, result, status: int = 200, fields: list = None):
        """Project the POST response body."""
        return await super()._post_response(self._scrub(result), status=status, fields=None)

    async def _put_response(self, result, status: int = 200, fields: list = None):
        """Project the PUT response body."""
        return await super()._put_response(self._scrub(result), status=status, fields=None)

    async def _delete_response(self, result, status: int = 200):
        """Project the DELETE response body."""
        return await super()._delete_response(self._scrub(result), status=status)

    async def _model_response(
        self,
        response: Any,
        fields: list = None,
        headers: dict = None,
        status: int = 200,
    ):
        """Project through ``public_columns``, then delegate.

        Required even on navigator-api 4.0.1: upstream's projection is driven
        by ``_hidden``, derived from ``secret=True`` columns only — and no
        column on ``UserAccount`` declares it, so upstream returns the full
        row (and any column added to the model later).
        """
        if not response:
            return await super()._model_response(response, fields=None, headers=headers, status=status)
        safe = safe_fields(fields, self.public_columns)
        redacted = redact_rows(response, self.public_columns, safe)
        return await super()._model_response(redacted, fields=None, headers=headers, status=status)

    async def _get_meta_info(self, meta: str, fields: list):
        """Serve ``:meta`` / ``:sample`` / ``:info`` bounded to ``public_columns``.

        ``redact_schema`` copies, so the model's cached schema is never
        mutated. All seven columns are public, so this strips only columns
        added to the model later.
        """
        if meta == ":meta":
            schema = self.get_model.schema(as_dict=True)
            hidden = frozenset(schema.get("properties", {})) - self.public_columns
            return self.json_response(redact_schema(schema, hidden))
        if meta == ":sample":
            sample = self.get_model.sample()
            if isinstance(sample, dict):
                sample = {k: v for k, v in sample.items() if k in self.public_columns}
            return self.json_response(sample)
        if meta == ":info":
            info = {}
            for _, field in self.get_model.get_columns().items():
                if field.name in self.public_columns:
                    info[field.name] = {
                        "type": str(field.type),
                        "db_type": field.db_type(),
                    }
            return self.json_response(info)
        return None

    async def head(self):
        """Keep ``X-Columns`` to the allowlisted column set."""
        response = await super().head()
        schema = self.get_model.schema(as_dict=True)
        cols = [c for c in schema["properties"] if c in self.public_columns]
        response.headers["X-Columns"] = f"{cols!r}"
        return response

    async def _filtering(self, queryparams: dict):
        """Route ``?_filter=`` through the guard's parameterized safe filter.

        Required even on navigator-api 4.0.1, whose ``_filtering`` is
        parameterized but allowlists "a real column not in ``_hidden``"
        (empty here) and applies no ownership predicate.
        """
        expr = queryparams.get("_filter")
        if not expr:
            return None
        rows = await self.safe_filter(expr)
        if not rows:
            return self.no_content(headers={"X-STATUS": "EMPTY"})
        return await self._model_response(rows)


class UserIdentityHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Owner-or-superuser CRUD over ``auth.user_identities`` (FEAT-105).

    The guard mixin comes first in the MRO so its hooks win over
    ``ModelView``'s. Credential material is never serialized: see
    ``credential_columns`` and the redaction in ``_model_response``.
    """

    model: Any = UserIdentity  # verified: navigator_auth/models.py:77
    model_name: str = AUTH_USER_IDENTITY_MODEL  # verified: navigator_auth/conf.py:150
    name: str = "User Identity"
    pk: str = "identity_id"

    owner_column: str = "user_id"
    credential_columns = frozenset({"access_token", "refresh_token", "id_token", "key_version"})
    public_columns = frozenset(
        {
            "identity_id",
            "user_id",
            "display_name",
            "title",
            "nickname",
            "email",
            "phone",
            "short_bio",
            "avatar",
            "auth_provider",
            "provider_user_id",
            "scopes",
            "token_type",
            "expires_at",
            "refreshed_at",
            "created_at",
            "enabled",
            "auth_data",
            "attributes",
        }
    )
    policy_name: str = "user_identities_admin_access"
    superuser_actions = frozenset({"identity:read", "identity:revoke", "identity:delete"})

    #: Vault-managed columns: never writable through the model surface. The
    #: only legitimate writer is IdentityStore.update_tokens
    #: (verified: navigator_auth/identity/store.py:409). Enforced in TASK-124.
    readonly_columns = frozenset(
        {
            "access_token",
            "refresh_token",
            "id_token",
            "key_version",
            "provider_user_id",
            "token_type",
            "expires_at",
            "refreshed_at",
            "scopes",
        }
    )

    # Per-subclass copies. Harmless on navigator-api 4.0.1 (which already
    # keeps them per instance and derives _hidden from secret=True) and
    # protective on 3.2.2, where ModelView mutated these CLASS-level lists in
    # place and contaminated every sibling handler. Never RELY on _hidden: no
    # credential column on UserIdentity declares secret=True.
    _hidden: list = []
    _required: list = []
    _primaries: list = []

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    def _require_owner_column(self) -> str:
        """Return the owner column, or refuse the request with 501.

        ``AUTH_USER_IDENTITY_MODEL`` (conf.py:150) can swap the model at
        import time. A model without an owner column cannot be ownership-
        bound at all, and a surface that cannot be bound must not serve.

        Returns:
            The owner column name.

        Raises:
            web.HTTPException: 501, when the configured model has no such
                column.
        """
        model = getattr(self, "get_model", None) or self.model
        columns = model.get_columns()
        if not self.owner_column or self.owner_column not in columns:
            # BaseHandler.error() maps no 501 (it would fall through to 400),
            # so raise the exception directly.
            raise web.HTTPNotImplemented(
                text='{"error": "Not Implemented"}',
                content_type="application/json",
            )
        return self.owner_column

    async def _pre_get(self, *args, **kwargs) -> bool:
        """Gate the read path before any parameter parsing or DB access.

        Cannot see the target row (upstream calls this before
        ``get_parameters()``), so it does the checks that need only the
        session and the raw query string; row-level ownership is bound in
        :meth:`_get_data`.

        Returns:
            ``True``. A refusal is raised, never returned — returning a falsy
            value would yield a fixed 412.
        """
        self._require_owner_column()
        await self.acting_user()
        qp = dict(self.query_parameters(self.request))
        qp.pop("fields", None)
        await self.sanitize_query(qp, None)
        return True

    async def _get_data(self, qp: dict, args: dict):
        """Bind every read to an owner before delegating upstream.

        This is the single ownership-injection point, chosen over spec §3's
        ``_filter_user_id`` class hook because that hook cannot express the
        superuser case: raising ``NotSet`` makes ``_get_filters`` return
        ``None`` (then ``**None`` fails) and the return value is always
        stored. For a non-superuser the hook is installed on the *instance*
        for this request only, so upstream merges the owner predicate on the
        primary-key path and on the query path alike; a superuser gets no
        hook, hence no narrowing.

        Args:
            qp: Query parameters with ``fields`` already popped out.
            args: URL arguments, including the primary key.

        Returns:
            Whatever the upstream implementation returns for the bound query.
        """
        owner_col = self._require_owner_column()
        user_id, is_superuser = await self.acting_user()
        qp, _ = await self.sanitize_query(qp, None)
        primary = await self._get_primary_data(args)
        widen = False
        if is_superuser:
            if primary is not None:
                widen = True  # authorized against the fetched row below
            elif owner_col in qp and str(qp[owner_col]) != str(user_id):
                await self.authorize_row("identity:read", owner_id=qp[owner_col])
                widen = True
        if not widen:
            qp = {k: v for k, v in qp.items() if k != owner_col}

            async def _bind_owner(value=None, column=None, data=None):
                return user_id

            setattr(self, f"_filter_{owner_col}", _bind_owner)
        try:
            result = await super()._get_data(qp, args)
        except NoDataFound:
            if primary is not None:
                self.error(response={"error": "Not Found"}, status=404)
            raise
        if primary is not None:
            rows = result if isinstance(result, list) else [result]
            rows = [r for r in rows if r]
            if not rows:
                self.error(response={"error": "Not Found"}, status=404)
            if widen:
                for row in rows:
                    owner = row.get(owner_col) if isinstance(row, dict) else getattr(row, owner_col, None)
                    await self.authorize_row("identity:read", owner, not_found_on_deny=True)
        return result

    # ------------------------------------------------------------------
    # Write path (TASK-124)
    # ------------------------------------------------------------------
    async def _pre_write(self) -> bool:
        """Shared gate for the four write verbs: 501 then 401."""
        self._require_owner_column()
        await self.acting_user()
        return True

    async def _pre_put(self, *args, **kwargs) -> bool:
        """Gate an insert: owner-only, no foreign ``user_id``.

        A ``PUT`` creates a row, so there is no existing owner to authorize
        against and nothing for a superuser to revoke: a foreign owner value
        is refused 403 for every role (spec G5 — no ``identity:create``).
        The body is readable here (aiohttp caches it), so the owner check
        is done now, before upstream parses anything.

        Returns:
            ``True``. Refusals are raised.
        """
        await self._pre_write()
        user_id, _ = await self.acting_user()
        owner_col = self.owner_column
        try:
            raw = await self.json_data()
        except Exception:  # noqa: BLE001 - malformed body is upstream's 400
            raw = None
        for element in (raw if isinstance(raw, list) else [raw]):
            if (
                isinstance(element, dict)
                and element.get(owner_col) is not None
                and str(element[owner_col]) != str(user_id)
            ):
                self.error(response={"error": "Forbidden"}, status=403)
        return True

    async def _pre_patch(self, *args, **kwargs) -> bool:
        """Gate a partial update. Row ownership is decided in `_set_update`."""
        return await self._pre_write()

    async def _pre_post(self, *args, **kwargs) -> bool:
        """Gate an upsert. `POST` may insert OR update."""
        return await self._pre_write()

    async def _pre_delete(self, *args, **kwargs) -> bool:
        """Gate a delete. The target row is resolved in `_del_primary_data`."""
        return await self._pre_write()

    def _reject_readonly(self, data) -> None:
        """Refuse 400 when a payload names a vault-managed column.

        Applies to **everyone, the owner included**: these columns are
        written only by ``IdentityStore.update_tokens``
        (navigator_auth/identity/store.py:409), which re-ciphers the token
        with the current key version.

        Args:
            data: The incoming payload — a ``dict`` or a ``list`` of dicts.

        Raises:
            web.HTTPBadRequest: a ``readonly_columns`` member is present.
        """
        elements = data if isinstance(data, list) else [data]
        refused = sorted(
            {
                key
                for element in elements
                if isinstance(element, dict)
                for key in element
                if key in self.readonly_columns
            }
        )
        if refused:
            self.error(
                response={
                    "error": "Vault-managed columns cannot be written here",
                    "columns": refused,
                    "hint": ("Tokens are managed by IdentityStore.update_tokens " "(/api/v1/user/identities/...)."),
                },
                status=400,
            )

    async def _post_user_id(self, value, column, data):
        """Fill ``user_id`` with the session's when the payload omits it.

        Unlike ``_set_user_id`` this never overwrites an explicit value, so
        a foreign owner can be detected and refused instead of silently
        rewritten (or, worse, silently re-owning a foreign row).
        """
        if value is not None:
            return value
        return await self.get_userid(session=self._session)

    async def _patch_user_id(self, value, column, data):
        """Leave ``user_id`` as sent on PATCH (``_set_user_id`` would clobber).

        ``_set_update`` removes a ``None`` and refuses a changed owner.
        """
        return value

    async def _post_data(self, *args, **kwargs):
        """Reject vault columns and bind the owner before a write.

        Covers ``PUT`` and ``POST`` (navigator/views/model.py:609).
        """
        data = await super()._post_data(*args, **kwargs)
        self._reject_readonly(data)
        user_id, is_superuser = await self.acting_user()
        owner_col = self.owner_column
        for element in (data if isinstance(data, list) else [data]):
            if not isinstance(element, dict):
                continue
            value = element.get(owner_col)
            if value is None:
                element[owner_col] = user_id
                continue
            if str(value) == str(user_id):
                continue
            # Foreign owner: never for a normal user; a superuser may only
            # target it with a pure revoke (POST updating an existing row —
            # authorized again against the fetched row in _set_update).
            extra = set(element) - {owner_col, self.pk, "enabled"}
            is_revoke = (
                is_superuser and not extra and element.get("enabled") is False and element.get(self.pk) is not None
            )
            if not is_revoke:
                self.error(response={"error": "Forbidden"}, status=403)
        return data

    async def _patch_data(self, *args, **kwargs):
        """Reject vault columns on `PATCH` (navigator/views/model.py:756)."""
        data = await super()._patch_data(*args, **kwargs)
        self._reject_readonly(data)
        return data

    async def _set_update(self, model, data) -> None:
        """Authorize the update against the FETCHED row, then delegate.

        The only upstream hook that sees the target row and the incoming
        data together (navigator/views/model.py:732).

        Args:
            model: The row as fetched from the database.
            data: The incoming payload for this row.

        Raises:
            web.HTTPForbidden: not the owner and not an authorized revoke.
            web.HTTPBadRequest: a vault-managed column was named.
        """
        self._reject_readonly(data)
        owner_col = self.owner_column
        owner_id = getattr(model, owner_col, None)
        user_id, is_superuser = await self.acting_user()
        if owner_col in data:
            if data[owner_col] is None:
                data.pop(owner_col)
            elif str(data[owner_col]) != str(owner_id):
                # Re-owning a row is never allowed, by anyone.
                self.error(response={"error": "Forbidden"}, status=403)
        is_owner = owner_id is not None and str(owner_id) == str(user_id)
        if not is_owner:
            if is_superuser:
                extra = set(data) - {owner_col, self.pk, "enabled"}
                if extra or data.get("enabled") is not False:
                    await self.audit_decision(
                        "identity:revoke", False, owner_id, "cross-user write outside the revoke envelope"
                    )
                    self.error(response={"error": "Forbidden"}, status=403)
            await self.authorize_row("identity:revoke", owner_id)
        return await super()._set_update(model, data)

    async def _del_primary_data(self, args: dict):
        """Resolve and authorize the delete target.

        Upstream calls this only when the subclass defines it
        (navigator/views/model.py:1516-1517). A request with no id in the
        URL is refused: upstream would otherwise fall through to its
        body-driven delete paths (``model.remove(**data)`` / bulk), which
        never see a row owner.

        Args:
            args: The URL arguments for this request.

        Returns:
            The primary-key value upstream should delete by.

        Raises:
            web.HTTPNotFound: the row is not the caller's and the caller is
                not an authorized superuser — the same generic 404 for a
                nonexistent row, so the id is no existence oracle.
        """
        objid = (args or {}).get("id") or (args or {}).get(self.pk)
        if not objid:
            self.error(
                response={"error": "A primary key is required in the URL"},
                status=400,
            )
        row = None
        try:
            async with await self.handler(request=self.request) as conn:
                self.model.Meta.connection = conn
                row = await self.model.get(**{self.pk: objid})
        except Exception:  # noqa: BLE001 - missing/invalid id => no owner
            row = None
        owner_id = getattr(row, self.owner_column, None) if row else None
        await self.authorize_row("identity:delete", owner_id, not_found_on_deny=True)
        return objid

    # ------------------------------------------------------------------
    # Response redaction (TASK-125)
    # ------------------------------------------------------------------
    @staticmethod
    def _col(row: Any, name: str, default: Any = None) -> Any:
        """Read one column from a ``dict`` or model row."""
        if isinstance(row, dict):
            return row.get(name, default)
        return getattr(row, name, default)

    def _masked_shape(self, row: dict, original: Any) -> dict:
        """Reshape an allowlisted row into the ``IdentityStore.masked()`` form.

        Keeps the two identity surfaces from drifting (spec §8 Q6):
        ``auth_data`` is emitted as ``profile``, token material becomes
        ``has_refresh_token`` / ``has_id_token``, and ``expired`` is derived
        from ``expires_at`` (a naive datetime is read as UTC).

        Args:
            row: An already-redacted row (credential columns are gone).
            original: The pre-redaction row, the only place the
                ``has_*_token`` booleans can be derived from.

        Returns:
            The reshaped row.
        """
        out = dict(row)
        expires_at = out.get("expires_at")
        expired = False
        if isinstance(expires_at, datetime):
            aware = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at
            expired = aware <= datetime.now(timezone.utc)
        out["expired"] = expired
        if out.get("identity_id") is not None:
            out["identity_id"] = str(out["identity_id"])
        out["scopes"] = list(out.get("scopes") or [])
        for key in ("expires_at", "refreshed_at", "created_at"):
            value = out.get(key)
            out[key] = value.isoformat() if hasattr(value, "isoformat") else value
        out["profile"] = out.pop("auth_data", None) or {}
        out["has_refresh_token"] = self._col(original, "refresh_token") is not None
        out["has_id_token"] = self._col(original, "id_token") is not None
        return out

    async def _model_response(
        self,
        response: Any,
        fields: list = None,
        headers: dict = None,
        status: int = 200,
    ):
        """Project every response through ``public_columns``, then delegate.

        Required even on navigator-api 4.0.1, whose own projection is driven
        by ``_hidden`` — derived from ``secret=True`` columns only, which
        **no** credential column on ``UserIdentity`` declares. Upstream
        therefore returns the full row, token bytes included. This override
        is the only thing that redacts this surface; do not remove it as
        redundant.

        Args:
            response: The row or rows to serialize.
            fields: The caller's ``?fields=`` projection.
            headers: Extra response headers.
            status: HTTP status.

        Returns:
            The upstream response, built from redacted rows.
        """
        if not response:
            return await super()._model_response(response, fields=None, headers=headers, status=status)
        safe = safe_fields(fields, self.public_columns)
        redacted = redact_rows(response, self.public_columns, safe)
        if safe is None:
            if isinstance(response, (list, tuple)):
                redacted = [self._masked_shape(r, o) for r, o in zip(redacted, response)]
            else:
                redacted = self._masked_shape(redacted, response)
        return await super()._model_response(redacted, fields=None, headers=headers, status=status)

    def _scrub(self, result: Any) -> Any:
        """Redact the body of a write/delete response.

        ``_post_response`` / ``_put_response`` / ``_patch_response`` /
        ``_delete_response`` serialize the written row verbatim. Rows are
        projected onto ``public_columns``; error/message dicts that carry no
        column names pass through untouched.
        """
        if isinstance(result, (list, tuple)):
            return [self._scrub(item) for item in result]
        known = self.public_columns | self.credential_columns
        if isinstance(result, dict):
            if set(result) & known:
                return redact_row(result, self.public_columns)
            return result
        if result is None or isinstance(result, (str, bytes, int, float, bool)):
            return result
        if any(hasattr(result, c) for c in known):
            return redact_row(result, self.public_columns)
        return result

    async def _patch_response(self, result, status: int = 202):
        """Redact the PATCH response body."""
        return await super()._patch_response(self._scrub(result), status=status)

    async def _post_response(self, result, status: int = 200, fields: list = None):
        """Redact the POST response body."""
        return await super()._post_response(self._scrub(result), status=status, fields=None)

    async def _put_response(self, result, status: int = 200, fields: list = None):
        """Redact the PUT response body."""
        return await super()._put_response(self._scrub(result), status=status, fields=None)

    async def _delete_response(self, result, status: int = 200):
        """Redact the DELETE response body."""
        return await super()._delete_response(self._scrub(result), status=status)

    async def _get_meta_info(self, meta: str, fields: list):
        """Redact the ``:meta`` / ``:sample`` / ``:info`` payloads.

        ``get()`` serves these BEFORE ``_filtering`` and ``_get_data`` and
        they bypass the row projection, returning the raw model schema —
        which enumerates every credential column. They are built here from
        the redacted schema; any other ``meta`` value returns ``None`` so
        ``get()`` continues into the normal flow.

        Args:
            meta: The ``{meta}`` URL segment, e.g. ``":meta"``.
            fields: The caller's projection (unused).

        Returns:
            The redacted meta response, or ``None``.
        """
        if meta == ":meta":
            # redact_schema copies: schema(as_dict=True) is a cached, shared dict.
            schema = redact_schema(self.get_model.schema(as_dict=True), self.credential_columns)
            return self.json_response(schema)
        if meta == ":sample":
            sample = self.get_model.sample()
            if isinstance(sample, dict):
                sample = {k: v for k, v in sample.items() if k not in self.credential_columns}
            return self.json_response(sample)
        if meta == ":info":
            info = {}
            for _, field in self.get_model.get_columns().items():
                if field.name in self.credential_columns:
                    continue
                info[field.name] = {
                    "type": str(field.type),
                    "db_type": field.db_type(),
                }
            return self.json_response(info)
        return None

    async def head(self):
        """Keep ``X-Columns`` from enumerating the credential columns.

        Upstream builds the header from the full model schema. Not named in
        spec §3 Module 4, but spec G3 forbids enumerating credentials for
        any role, and a HEAD response's headers are a response.
        """
        response = await super().head()
        schema = redact_schema(self.get_model.schema(as_dict=True), self.credential_columns)
        response.headers["X-Columns"] = f"{list(schema['properties'])!r}"
        return response

    async def _filtering(self, queryparams: dict):
        """Route ``?_filter=`` through the guard's parameterized safe filter.

        Required even on navigator-api 4.0.1, whose own ``_filtering`` *is*
        parameterized: its allowlist is "a real column not in ``_hidden``" —
        empty here — so ``?_filter=access_token=x`` is valid upstream and
        returns token bytes; and it applies no ownership predicate.

        Args:
            queryparams: The request query parameters.

        Returns:
            The filter response, or ``None`` when no ``_filter`` was
            requested — ``get()`` checks for ``None`` to continue.
        """
        expr = queryparams.get("_filter")
        if not expr:
            return None
        rows = await self.safe_filter(expr)
        if not rows:
            return self.no_content(headers={"X-STATUS": "EMPTY"})
        return await self._model_response(rows)
