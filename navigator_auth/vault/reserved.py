"""Session-vault loader that never decrypts reserved MFA rows (FEAT-106)."""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from navigator_session.vault import KeyRing
from navigator_session.vault.envelope import open_sealed
from navigator_session.vault.models import VaultSecretMetadata
from navigator_session.vault.session_vault import INTEGRITY_ERRORS, SessionVault
from navigator_session.vault.targets.postgres import acquire_connection, fetch_rows

from navigator_auth.mfa.types import MFA_VAULT_PREFIX

logger = logging.getLogger("navigator.vault")

_SELECT_ACTIVE_UNRESERVED = """
SELECT key, ciphertext_db, key_version, updated_at
FROM auth.user_vault_secrets
WHERE user_id = $1 AND deleted_at IS NULL AND NOT starts_with(key, $2)
"""


def is_reserved_key(key: Any) -> bool:
    """Return whether a key belongs to the MFA-reserved namespace."""
    return isinstance(key, str) and key.startswith(MFA_VAULT_PREFIX)


class ReservedPrefixSessionVault(SessionVault):
    """SessionVault that cannot read, write, delete or load reserved MFA keys."""

    def _validate_key(self, key: str) -> None:
        """Validate a key and reject the reserved namespace."""
        super()._validate_key(key)
        if is_reserved_key(key):
            raise ValueError("Vault key uses a reserved namespace")

    @classmethod
    async def load_for_session(
        cls,
        session_uuid: str,
        user_id: int,
        db_pool: Any,
        redis: Any = None,
        session_ttl: int = 3600,
        *,
        keyring: Optional[KeyRing] = None,
    ) -> "ReservedPrefixSessionVault":
        """Load active non-reserved secrets and re-seal them for the session."""
        vault = cls(
            session_uuid=session_uuid,
            user_id=user_id,
            db_pool=db_pool,
            redis=redis,
            session_ttl=session_ttl,
            keyring=keyring,
        )
        async with acquire_connection(db_pool) as conn:
            rows = await fetch_rows(conn, _SELECT_ACTIVE_UNRESERVED, vault._user_id, MFA_VAULT_PREFIX)

        failures: list[tuple[str, Optional[int]]] = []
        for row in rows:
            key = row["key"]
            if is_reserved_key(key):
                continue
            try:
                plaintext = open_sealed(bytes(row["ciphertext_db"]), vault._db_context(key), vault._keyring)
            except INTEGRITY_ERRORS as err:
                logger.error(
                    "Vault secret failed integrity check: user=%s key=%s error=%s",
                    vault._user_id,
                    key,
                    type(err).__name__,
                )
                failures.append((key, row["key_version"]))
                continue
            try:
                ciphertext_mem = vault._seal_session(plaintext, key)
                vault._cache[key] = ciphertext_mem
                await vault._redis_set(key, ciphertext_mem)
                vault._metadata[key] = VaultSecretMetadata(
                    key=key,
                    updated_at=row["updated_at"] or datetime.now(timezone.utc),
                    key_version=row["key_version"],
                )
            except Exception as err:  # noqa: BLE001 - one secret must not break login
                vault._cache.pop(key, None)
                logger.error(
                    "Failed to load vault secret key=%s for user=%s: %s",
                    key,
                    vault._user_id,
                    type(err).__name__,
                )

        if failures:
            try:
                async with acquire_connection(db_pool) as conn:
                    for key, key_version in failures:
                        await vault._audit(conn, key, "integrity_fail", key_version)
            except Exception as err:  # noqa: BLE001 - auditing must not break login
                logger.error(
                    "Failed to audit vault integrity failures for user=%s: %s",
                    vault._user_id,
                    type(err).__name__,
                )

        logger.info(
            "Vault loaded for user=%s: %d secret(s), %d integrity failure(s)",
            vault._user_id,
            len(vault._cache),
            len(failures),
        )
        return vault
