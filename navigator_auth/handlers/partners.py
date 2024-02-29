from typing import Any
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
    created_at: datetime = Column(required=False, default=datetime.now())
    revoked: bool = Column(default=False)
    enabled: bool = Column(default=True)
    grants: dict = Column(default_factory=dict)
    programs: list = Column(default_factory=list)

    class Meta:
        name = 'partner_keys'
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None


class PartnerKeyHandler(ModelHandler):
    model: Any = PartnerKey
    name: str = "Partner Key Authentication"
    pk: list[str] = ["partner_id"]

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
