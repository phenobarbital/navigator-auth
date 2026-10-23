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
