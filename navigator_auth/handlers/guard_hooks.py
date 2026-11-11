"""Verb hooks that put a navigator ``ModelView`` behind ``OwnerOrSuperuserGuard``.

Use with ``ModelHandler`` as ``(OwnerOrSuperuserGuard, GuardedModelViewHooks,
ModelHandler)``.  The guard supplies authorization; this mixin supplies the
ModelView-specific verb coverage.
"""

import logging
from typing import Any, Optional

from aiohttp import web
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError

logger = logging.getLogger("navigator.auth.guard_hooks")


class GuardedModelViewHooks:
    """ModelView verb hooks for an ``OwnerOrSuperuserGuard`` host.

    Attributes:
        action_object: The object half of ABAC actions, such as ``"user"``.
    """

    action_object: str = ""
    _guard_write_keys: Optional[frozenset[str]] = None

    def _action(self, verb: str) -> str:
        """Return the configured action for ``verb``.

        Raises:
            web.HTTPNotImplemented: The host did not configure ``action_object``.
        """
        if not self.action_object:
            raise web.HTTPNotImplemented(text='{"error": "Not Implemented"}', content_type="application/json")
        return f"{self.action_object}:{verb}"

    async def _client_keys(self, *, include_query: bool = False) -> frozenset[str]:
        """Capture the raw client-supplied write keys.

        Args:
            include_query: Include model-column query parameters merged by PUT.

        Raises:
            web.HTTPBadRequest: The request body is not a non-empty object/list of objects.
        """
        try:
            data = await self.json_data()
        except Exception:
            data = None
        elements = data if isinstance(data, list) else [data]
        if not elements or any(not isinstance(element, dict) for element in elements):
            self.error(response={"error": "A JSON object is required"}, status=400)
        keys = {key for element in elements for key in element}
        if include_query:
            keys.update(key for key in self.query_parameters(self.request) if key in self.model.get_columns())
        self._guard_write_keys = frozenset(keys)
        return self._guard_write_keys

    async def _pre_get(self, *args, **kwargs) -> bool:
        """Gate reads according to whether the host has an owner column."""
        if self.owner_column is None:
            await self.authorize_row(self._action("read"), None)
            return True
        await self.acting_user()
        qp = dict(self.query_parameters(self.request))
        qp.pop("fields", None)
        await self.sanitize_query(qp, None)
        return True

    async def _get_data(self, qp: dict, args: dict) -> Any:
        """Bind owned reads to the acting user unless a permitted admin widens them."""
        if self.owner_column is None:
            return await super()._get_data(qp, args)
        owner_col = self.owner_column
        user_id, is_superuser = await self.acting_user()
        qp, _ = await self.sanitize_query(qp, None)
        primary = await self._get_primary_data(args)
        widen = False
        if is_superuser:
            if primary is not None:
                widen = True
            elif owner_col in qp and str(qp[owner_col]) != str(user_id):
                await self.authorize_row(self._action("read"), owner_id=qp[owner_col])
                widen = True
        if not widen:
            qp = {key: value for key, value in qp.items() if key != owner_col}

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
            rows = [row for row in (result if isinstance(result, list) else [result]) if row]
            if not rows:
                self.error(response={"error": "Not Found"}, status=404)
            if widen:
                for row in rows:
                    owner = row.get(owner_col) if isinstance(row, dict) else getattr(row, owner_col, None)
                    await self.authorize_row(self._action("read"), owner, not_found_on_deny=True)
        return result

    async def _filtering(self, queryparams: dict) -> Optional[web.Response]:
        """Use the guard's parameterized filter rather than upstream SQL interpolation."""
        expr = (queryparams or {}).get("_filter")
        if not expr:
            return None
        if not self.public_columns:
            self.error(response={"error": "Invalid _filter"}, status=400)
        rows = await self.safe_filter(expr)
        return self.json_response(rows, status=200)

    async def head(self) -> web.Response:
        """Apply the GET authorization gate to HEAD requests."""
        if self.owner_column is None:
            await self.authorize_row(self._action("read"), None)
        else:
            await self.acting_user()
        return await super().head()

    async def _pre_put(self, *args, **kwargs) -> bool:
        """Authorize PUT as a create using raw body and query keys."""
        keys = await self._client_keys(include_query=True)
        await self.authorize_row(self._action("create"), None, payload=keys, creating=True)
        return True

    async def _pre_post(self, *args, **kwargs) -> bool:
        """Authorize POST as an upsert using both create and update envelopes."""
        keys = await self._client_keys()
        if isinstance(self.pk, str):
            try:
                data = await self.json_data()
            except Exception:
                data = None
            objid = data.get(self.pk, data.get("id")) if isinstance(data, dict) else None
            objid = objid if objid is not None else self.get_args().get("id")
            if isinstance(objid, str) and "/" in objid:
                self.error(response={"error": "Invalid primary key"}, status=400)
        await self.authorize_row(self._action("create"), None, payload=keys, creating=True)
        await self.authorize_row(self._action("update"), None, payload=keys)
        return True

    async def _pre_patch(self, *args, **kwargs) -> bool:
        """Require an authenticated request and a structured PATCH body."""
        if self.get_args().get("meta") == ":meta":
            if self.owner_column is None:
                await self.authorize_row(self._action("read"), None)
            else:
                await self.acting_user()
            return True
        await self.acting_user()
        await self._client_keys()
        return True

    async def _pre_delete(self, *args, **kwargs) -> bool:
        """Require an authenticated delete request before target resolution."""
        await self.acting_user()
        return True

    async def _set_update(self, model: Any, data: dict) -> None:
        """Authorize the fetched row using the pre-hook's raw client keys."""
        keys = self._guard_write_keys
        if keys is None:
            self.error(response={"error": "Forbidden"}, status=403)
        owner_id = getattr(model, self.owner_column, None) if self.owner_column else None
        if self.owner_column in data:
            if data[self.owner_column] is None:
                data.pop(self.owner_column)
            elif str(data[self.owner_column]) != str(owner_id):
                self.error(response={"error": "Forbidden"}, status=403)
        await self.authorize_row(self._action("update"), owner_id, payload=keys)
        return await super()._set_update(model, data)

    async def _del_primary_data(self, args: dict) -> Any:
        """Resolve and authorize a DELETE target, answering 404 on denied rows."""
        try:
            objid = self._del_primary(args)
        except (TypeError, KeyError):
            objid = None
        if not objid:
            self.error(response={"error": "A primary key is required in the URL"}, status=400)
        if self.owner_column is None:
            await self.authorize_row(self._action("delete"), None, not_found_on_deny=True)
            return objid
        if isinstance(objid, list):
            self.error(response={"error": "A primary key is required in the URL"}, status=400)
        row = None
        try:
            async with await self.handler(request=self.request) as conn:
                self.model.Meta.connection = conn
                row = await self.model.get(**{self.pk: objid})
        except (NoDataFound, ValidationError):
            row = None
        owner_id = getattr(row, self.owner_column, None) if row else None
        await self.authorize_row(self._action("delete"), owner_id, not_found_on_deny=True)
        return objid
