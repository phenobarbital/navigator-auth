import json
from typing import Any, Optional
from uuid import UUID
from datetime import datetime
import jwt
from asyncdb.models import Model, Column
from ..conf import (
    AUTH_DB_SCHEMA,
    AUTH_TOKEN_ISSUER,
    AUTH_JWT_ALGORITHM,
    AUTH_TOKEN_SECRET
)
from ..exceptions import ConfigError
from .model import ModelHandler
from .guards import OwnerOrSuperuserGuard
from .redaction import redact_row, redact_rows, redact_schema, safe_fields

class PartnerKey(Model):
    partner_id: UUID = Column(
        required=True,
        primary_key=True,
        db_default="auto",
        repr=False
    )
    name: str = Column(required=True)
    partner: str = Column(required=True)
    issuer: str = Column(required=True, default='navigator')
    token: str = Column(required=True)
    created_at: datetime = Column(required=False, default=datetime.now)
    revoked: bool = Column(default=False)
    enabled: bool = Column(default=True)
    grants: dict = Column(default_factory=dict)
    programs: list = Column(default_factory=list)

    class Meta:
        name = 'partner_keys'
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None


class PartnerKeyHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Superuser-only CRUD over ``auth.partner_keys`` (FEAT-105, G8).

    Partner keys have no owner, so every verb is superuser-only and
    policy-gated. ``token`` holds a plaintext signed JWT and is returned
    **once**, in the creation response, and never on a read or an update.

    This handler sits on the LOCAL ``handlers/model.py`` base, which has no
    ``_pre_*`` and no ``_filter_*`` hooks — so the guard is invoked at the
    top of each verb below, not through a pre-hook.
    """

    model: Any = PartnerKey                     # verified: partners.py:15
    name: str = "Partner Key Authentication"
    pk: list[str] = ["partner_id"]              # NOTE: a list, not a str

    #: No owner column exists on PartnerKey -> the superuser path is the only
    #: path, for every verb (spec G8).
    owner_column: Optional[str] = None
    credential_columns = frozenset({"token"})
    public_columns = frozenset({
        "partner_id", "name", "partner", "issuer", "created_at", "revoked",
        "enabled", "grants", "programs"})
    policy_name: str = "partner_keys_admin_access"
    superuser_actions = frozenset({
        "partner:read", "partner:create", "partner:revoke", "partner:delete"})

    async def _get_token(self, value, column, data):
        """
        Generate the Token using data.
        """
        try:
            payload = {
                'name': data['name'],
                'partner': data['partner'],
                'issuer': AUTH_TOKEN_ISSUER
            }
        except KeyError as exc:
            raise ConfigError(
                f"Invalid Data for Partner Token Creation: {exc}"
            ) from exc
        try:
            return jwt.encode(
                payload=payload,
                key=AUTH_TOKEN_SECRET,
                algorithm=AUTH_JWT_ALGORITHM,

            )
        except Exception as exc:
            raise RuntimeError(
                f"Unable to generate Token: {exc}"
            ) from exc

    async def _require_superuser(self, action: str) -> None:
        """Refuse unless the caller is a policy-approved superuser.

        ``owner_column`` is ``None``, so :meth:`authorize_row` can never take
        its owner branch and the superuser path is the only path. ``None`` is
        passed as the owner: a partner id is not a user id.

        Args:
            action: One of ``superuser_actions``.

        Raises:
            web.HTTPForbidden: not a superuser, or the policy denied.
            web.HTTPUnauthorized: no session.
        """
        await self.authorize_row(action, None)

    def _redact(self, result: Any) -> Any:
        """Project a result onto ``public_columns`` (drops ``token``)."""
        return redact_rows(result, self.public_columns)

    def _scrub(self, result: Any) -> Any:
        """Redact a decoded response body; message/error dicts pass through."""
        if isinstance(result, (list, tuple)):
            return [self._scrub(item) for item in result]
        if isinstance(result, dict):
            if set(result) & (self.public_columns | self.credential_columns):
                return redact_row(result, self.public_columns)
            return result
        return result

    def _redact_response(self, response):
        """Rebuild a JSON response with its body redacted (same status)."""
        try:
            body = response.body
            payload = json.loads(body.decode() if isinstance(body, bytes) else body)
        except (AttributeError, TypeError, ValueError):
            return response
        return self.json_response(
            self._scrub(payload), status=response.status
        )

    def _meta_requested(self) -> bool:
        try:
            return self.match_parameters(self.request).get("meta") == ":meta"
        except (AttributeError, KeyError, TypeError):
            return False

    async def head(self):
        """Superuser-only; ``X-Columns`` must not enumerate ``token``."""
        await self._require_superuser("partner:read")
        response = await super().head()
        schema = redact_schema(
            self.model.schema(as_dict=True), self.credential_columns
        )
        response.headers["X-Columns"] = f"{list(schema['properties'])!r}"
        return response

    async def get(self):
        """Superuser-only read; ``token`` never returned.

        Handles ``:meta`` before delegating, because the local base serves it
        from the raw model schema and bypasses ``_post_get`` entirely.
        """
        await self._require_superuser("partner:read")
        if self._meta_requested():
            # redact_schema copies: schema(as_dict=True) is a cached dict.
            schema = redact_schema(
                self.model.schema(as_dict=True), self.credential_columns
            )
            return self.json_response(schema)
        return await super().get()

    async def _post_get(self, result: Any, fields: list[str] = None):
        """Redact ``token`` out of every read.

        The local base's single read-response hook; called on both the
        primary-key path and the list path. ``fields`` is applied here
        (intersected with the allowlist) and ``None`` is handed to ``super()``
        so it never re-projects by ``getattr``.
        """
        if not result:
            return self.no_content()
        safe = safe_fields(fields, self.public_columns)
        # Not delegated to super(): the local base answers through
        # ``json_response(content=...)``, a keyword the installed
        # navigator-api (4.0.1) no longer accepts (its parameter is
        # ``response``), and its ``fields`` branch reads from the wrong
        # variable. The positional call works on both.
        return self.json_response(
            redact_rows(result, self.public_columns, safe)
        )

    async def put(self):
        """Superuser-only create; the 201 carries ``token`` ONCE.

        Deliberately NOT redacted: this (and the insert branch of ``post``)
        is the single response allowed to carry the token.
        """
        await self._require_superuser("partner:create")
        return await super().put()

    async def patch(self):
        """Superuser-only update; ``token`` never echoed.

        The local base serves a SECOND ``:meta`` here, returning
        ``self.model.__fields__`` — a different payload that names ``token``.
        """
        await self._require_superuser("partner:revoke")
        if self._meta_requested():
            fields = self.model.__fields__
            if isinstance(fields, dict):
                fields = {
                    k: v for k, v in fields.items()
                    if k not in self.credential_columns
                }
            else:
                fields = [f for f in fields if f not in self.credential_columns]
            return self.json_response(fields)
        return self._redact_response(await super().patch())

    async def post(self):
        """Superuser-only upsert: 201 WITH token when it creates, 202 without.

        ``post()`` chooses insert or update at runtime, so the caller must be
        approved for BOTH ``partner:create`` and ``partner:revoke``: requiring
        only the former would let a policy that grants create-but-not-revoke
        mutate existing keys through this verb. The response status tells the
        branches apart: a 201 (created) is left untouched, anything else is
        redacted.
        """
        await self._require_superuser("partner:create")
        await self._require_superuser("partner:revoke")
        response = await super().post()
        if getattr(response, "status", None) == 201:
            return response
        return self._redact_response(response)

    async def delete(self):
        """Superuser-only delete, audited; response carries no ``token``."""
        await self._require_superuser("partner:delete")
        return self._redact_response(await super().delete())
