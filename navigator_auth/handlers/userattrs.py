from typing import Any
from aiohttp import web
from asyncdb.exceptions import (
    NoDataFound
)
from asyncdb.exceptions import DriverError
from navigator_session import (
    get_session,
    AUTH_SESSION_OBJECT
)
from ..models import (
    UserAccount, UserIdentity, VwUserIdentity
)
from ..conf import (
    AUTH_USER_IDENTITY_MODEL
)
# from .model import ModelHandler
from .handler import ModelHandler
from .guards import OwnerOrSuperuserGuard


class UserAccountHandler(ModelHandler):
    model: Any = UserAccount
    name: str = "User Account"
    pk: str = "account_id"
    #: G9: the provider is bound as $1, never interpolated. The previous form
    #: inlined it inside a quoted literal, so a provider of ``x' OR 1=1 --``
    #: rewrote the statement.
    social_network: str = (
        "SELECT social_url FROM auth.social_networks "
        "WHERE social_network = $1"
    )

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    async def _set_address(self, value, column, data):
        try:
            userid = data['uid']
        except KeyError:
            return self.error(
                reason=f"Invalid User ID for {self.name}", status=410
            )
        try:
            provider = data['provider']
        except KeyError:
            provider = None
        if provider:
            try:
                async with await self.handler(request=self.request) as conn:
                    result = await conn.fetchval(
                        self.social_network, provider, column='social_url'
                    )
                    if result:
                        return result.format(uid=userid)
            except DriverError:
                pass
        return None

class UserIdentityHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Owner-or-superuser CRUD over ``auth.user_identities`` (FEAT-105).

    The guard mixin comes first in the MRO so its hooks win over
    ``ModelView``'s. Credential material is never serialized: see
    ``credential_columns`` and the redaction in ``_model_response``.
    """

    model: Any = UserIdentity                   # verified: navigator_auth/models.py:77
    model_name: str = AUTH_USER_IDENTITY_MODEL  # verified: navigator_auth/conf.py:150
    name: str = "User Identity"
    pk: str = "identity_id"

    owner_column: str = "user_id"
    credential_columns = frozenset({
        "access_token", "refresh_token", "id_token", "key_version"})
    public_columns = frozenset({
        "identity_id", "user_id", "display_name", "title", "nickname",
        "email", "phone", "short_bio", "avatar", "auth_provider",
        "provider_user_id", "scopes", "token_type", "expires_at",
        "refreshed_at", "created_at", "enabled", "auth_data", "attributes"})
    policy_name: str = "user_identities_admin_access"
    superuser_actions = frozenset({
        "identity:read", "identity:revoke", "identity:delete"})

    #: Vault-managed columns: never writable through the model surface. The
    #: only legitimate writer is IdentityStore.update_tokens
    #: (verified: navigator_auth/identity/store.py:409). Enforced in TASK-124.
    readonly_columns = frozenset({
        "access_token", "refresh_token", "id_token", "key_version",
        "provider_user_id", "token_type", "expires_at", "refreshed_at",
        "scopes"})

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
            elif (
                owner_col in qp
                and str(qp[owner_col]) != str(user_id)
            ):
                await self.authorize_row(
                    "identity:read", owner_id=qp[owner_col]
                )
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
                    owner = (
                        row.get(owner_col) if isinstance(row, dict)
                        else getattr(row, owner_col, None)
                    )
                    await self.authorize_row(
                        "identity:read", owner, not_found_on_deny=True
                    )
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
        refused = sorted({
            key
            for element in elements if isinstance(element, dict)
            for key in element if key in self.readonly_columns
        })
        if refused:
            self.error(
                response={
                    "error": "Vault-managed columns cannot be written here",
                    "columns": refused,
                    "hint": (
                        "Tokens are managed by IdentityStore.update_tokens "
                        "(/api/v1/user/identities/...)."
                    ),
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
                is_superuser and not extra
                and element.get("enabled") is False
                and element.get(self.pk) is not None
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
                        "identity:revoke", False, owner_id,
                        "cross-user write outside the revoke envelope"
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
        await self.authorize_row(
            "identity:delete", owner_id, not_found_on_deny=True
        )
        return objid
