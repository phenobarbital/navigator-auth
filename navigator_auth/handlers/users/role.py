"""The only way to change a privileged user flag (FEAT-107, spec M5)."""

from typing import Any, Optional

from aiohttp import web

from ...decorators import policy_allows
from ...models import User, UserType
from ..guards import OwnerOrSuperuserGuard
from ..model import ModelHandler

_ACTION = "users:grant_role"
_ROLE_COLUMNS = ("is_superuser", "user_role", "is_staff")


class UserRoleHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Handle the privileged role-change endpoint."""

    model = User
    name: str = "User Role"
    pk: str = "user_id"
    owner_column: Optional[str] = None
    policy_name: str = "users_grant_role"
    superuser_actions = frozenset()

    async def _not_allowed(self):
        raise web.HTTPMethodNotAllowed(self.request.method, ["POST"])

    async def head(self):
        return await self._not_allowed()

    async def get(self):
        return await self._not_allowed()

    async def put(self):
        return await self._not_allowed()

    async def patch(self):
        return await self._not_allowed()

    async def delete(self):
        return await self._not_allowed()

    async def _role_payload(self) -> dict:
        """Return a non-empty, strictly typed privileged-column payload."""
        try:
            payload = await self.json_data()
        except (TypeError, ValueError, AttributeError):
            self.error(reason="Invalid User Role Data", status=400)
        if not isinstance(payload, dict) or not payload:
            self.error(reason="Invalid User Role Data", status=400)
        if any(key not in _ROLE_COLUMNS for key in payload):
            self.error(reason="Invalid User Role Data", status=400)
        for key, value in payload.items():
            if key in ("is_superuser", "is_staff") and type(value) is not bool:
                self.error(reason="Invalid User Role Data", status=400)
            if key == "user_role" and (type(value) is not int or value not in {role.value for role in UserType}):
                self.error(reason="Invalid User Role Data", status=400)
        return payload

    async def _require_grant_action(self) -> None:
        allowed, reason, _ = await policy_allows(
            self.policy_name, self.request, action=_ACTION, resource=self.request.path
        )
        await self.audit_decision(_ACTION, bool(allowed), None, f"grant_role gate: {reason}")
        if not allowed:
            self._refuse()

    async def post(self):
        """Change privileged flags of another user."""
        payload = await self._role_payload()
        actor_id, actor_is_superuser = await self.acting_user()
        await self._require_grant_action()
        target_id = self.match_parameters(self.request).get("id")
        if target_id is None or str(target_id) == str(actor_id):
            await self.audit_decision(_ACTION, False, target_id, f"self-targeted role change by {actor_id}")
            self._refuse()
        target_id = int(target_id)
        columns = ', '.join(f'"{column}"' for column in ("user_id",) + _ROLE_COLUMNS)
        schema = User.Meta.schema
        table = User.Meta.name
        qualified = f'"{schema}"."{table}"'
        select = f"SELECT {columns} FROM {qualified} WHERE \"user_id\" = $1"
        db = self.request.app["authdb"]
        async with await db.acquire() as conn:
            actor = await conn.fetch_one(select, actor_id)
            target = await conn.fetch_one(select, target_id)
            if not target:
                await self.audit_decision(_ACTION, False, target_id, "target not found")
                self.error(response={"error": "Not Found"}, status=404)
            actor_role = actor.get("user_role") if actor else None
            if isinstance(actor_role, UserType):
                actor_role = actor_role.value
            target_role = target.get("user_role") or 0
            if isinstance(target_role, UserType):
                target_role = target_role.value
            for column in payload:
                held = (
                    actor_is_superuser if column == "is_superuser" else
                    bool(actor.get("is_staff")) if column == "is_staff" else
                    actor_role is not None and actor_role >= max(target_role, payload[column])
                )
                if not held:
                    await self.audit_decision(_ACTION, False, target_id, f"{column}: actor does not hold it")
                    self._refuse()
            assignments = ', '.join(f'"{column}" = ${index}' for index, column in enumerate(payload, 2))
            returning = ', '.join(f'"{column}"' for column in ("user_id",) + _ROLE_COLUMNS)
            sql = f"UPDATE {qualified} SET {assignments} WHERE \"user_id\" = $1 RETURNING {returning}"
            updated = await conn.fetch_one(sql, target_id, *payload.values())
            if not updated:
                await self.audit_decision(_ACTION, False, target_id, "write failed")
                self.error(reason="Role update failed", status=500)
            changes = " ".join(f"{column}: {target.get(column)} -> {updated.get(column)}" for column in payload)
        await self.audit_decision(_ACTION, True, target_id, f"actor={actor_id} target={target_id} {changes}")
        return self.json_response(dict(updated), status=200)
