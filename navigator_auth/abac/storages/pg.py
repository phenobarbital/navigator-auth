from typing import Optional
from uuid import UUID
from datetime import datetime
from asyncdb.models import Model, Field

from navigator_auth.exceptions import ConfigError
from .db import DBStorage

class pgStorage(DBStorage):
    """pgStorage.


    Getting Policies from Postgres Database.
    """
    driver: str = 'pg'
    timeout: int = 10

    async def load_policies(
        self,
        org_id: Optional[int] = None,
        client_id: Optional[int] = None,
    ):
        """Load enabled policies from the database.

        When *org_id* and *client_id* are both provided (ABAC_TENANT_SQL_FILTERING
        mode), only the global sentinel rows (org_id=1, client_id=1) plus the
        specific tenant's rows are fetched.  This keeps per-tenant evaluator
        instances small for deployments with many tenants.

        Leave both *None* (the default) to load every enabled policy — the
        Phase-1 / backward-compatible behaviour.
        """
        if org_id is not None and client_id is not None:
            # Parameterized: global + this tenant only.
            policy_table = """
            SELECT policy_id, policy_type, name, resource, actions, conditions,
                   effect, groups, context, environment, description, enforcing,
                   objects, objects_attr, priority, org_id, client_id
            FROM auth.policies
            WHERE enabled = TRUE
              AND org_id IN (1, $1)
              AND client_id IN (1, $2);"""
            async with self.connection() as conn:
                result, error = await conn.query(policy_table, org_id, client_id)
        else:
            # No tenant filter — load everything (Phase-1 / YAML-storage path).
            policy_table = """
            SELECT policy_id, policy_type, name, resource, actions, conditions,
                   effect, groups, context, environment, description, enforcing,
                   objects, objects_attr, priority, org_id, client_id
            FROM auth.policies WHERE enabled = TRUE;"""
            async with self.connection() as conn:
                result, error = await conn.query(policy_table)

        if error:
            raise ConfigError(
                f"ABAC: Error loading policies: {error}"
            )
        return result


###
# Model for Model Handler
###

def now():
    return datetime.now()

class ModelPolicy(Model):
    policy_id: UUID = Field(
        required=False, primary_key=True, db_default="auto", repr=False
    )
    policy_type: str = Field(required=True, default='policy')
    name: str = Field(required=True)
    resource: list[str] = Field(required=False, default_factory=list)
    actions: list[str] = Field(required=False, default_factory=list)
    method: list[str] = Field(required=False, default_factory=list)
    effect: str = Field(required=True, default='ALLOW')
    groups: list[str] = Field(required=False, default_factory=list)
    context: Optional[dict] = Field(required=False, default_factory=dict)
    environment: Optional[dict] = Field(required=False, default_factory=dict)
    objects: Optional[dict] = Field(required=False, default_factory=dict)
    objects_attr: str = Field(required=False)
    description: str = Field(required=False)
    enforcing: bool = Field(required=True, default=False)
    priority: int = Field(required=True, default=1)
    org_id: int = Field(required=True, default=1)
    client_id: int = Field(required=True, default=1)
    created_at: datetime = Field(required=False, default=now)
    updated_at: datetime = Field(required=False, default=now)
    enabled: bool = Field(required=True, default=True)

    class Meta:
        name = "policies"
        schema = "auth"
        strict = True
        connection = None
