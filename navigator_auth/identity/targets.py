"""Vault protected target for identity credentials (``auth.user_identities``).

Registered under the ``navigator_session.vault_targets`` entry-point group so
``navigator-vault`` rotation and v1 → v2 migration cover linked-identity tokens.

Context per token column: ``identity/db (user_id, auth_provider,
provider_user_id, field)`` — the same values ``IdentityStore`` seals with.
Quarantine disables the identity (``enabled = false``) and keeps its tokens so
a restore can bring them back; the user must re-link the provider.
"""
from typing import Any, Mapping, Optional
from uuid import UUID

from navigator_session.vault.targets.postgres import PostgresTarget

from ..conf import AUTH_DB_SCHEMA
from .crypto import IDENTITY_FIELDS, IDENTITY_PURPOSE, normalize_user_id


class IdentityTarget(PostgresTarget):
    """Token columns of ``<AUTH_DB_SCHEMA>.user_identities``."""

    name = "auth.user_identities"
    table = "auth.user_identities"
    purpose = IDENTITY_PURPOSE
    pk_column = "identity_id"
    identity_columns = ("user_id", "auth_provider", "provider_user_id")
    encrypted_fields = IDENTITY_FIELDS
    include_field_in_context = True
    key_version_column = "key_version"
    touch_column = None
    state_columns = ("enabled",)
    quarantine_assignments = "enabled = false"

    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None:
        # Instance attributes shadow the class defaults when the auth schema
        # is not "auth"; the name follows the table for unambiguous backups.
        self.table = f"{schema}.user_identities"
        self.name = self.table
        super().__init__(db_pool)

    def context_value(self, column: str, value: Any) -> Any:
        """Match ``identity_context``: normalized user id, str provider, nullable puid."""
        if column == "user_id":
            return normalize_user_id(value)
        if value is None:
            return None
        return str(value)

    def pk_from_json(self, value: Any) -> Any:
        """``identity_id`` is a UUID."""
        return value if isinstance(value, UUID) else UUID(str(value))

    def state_from_json(self, column: str, value: Any) -> Any:
        """``enabled`` is a boolean."""
        return None if value is None else bool(value)


def factory(resources: Mapping[str, Any]) -> Optional[IdentityTarget]:
    """Entry-point factory: requires ``db_pool`` (the ``authdb`` pool).

    Returns:
        Target, or ``None`` when no database pool is configured.
    """
    pool = resources.get("db_pool")
    if pool is None:
        return None
    return IdentityTarget(pool)
