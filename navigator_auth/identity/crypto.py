"""Cipher for identity credentials at rest.

Reuses the Session Vault crypto from ``navigator-session`` so identity
credentials share the same master keys (``VAULT_MASTER_KEY_v{N}`` +
``VAULT_ACTIVE_KEY_ID``), key-rotation semantics and ciphertext format
(2-byte big-endian key_id ‖ nonce ‖ ciphertext ‖ tag) as
``auth.user_vault_secrets``.
"""
from typing import Any, Optional

from ..exceptions import ConfigError

try:
    from navigator_session.vault.crypto import (
        encrypt_for_db,
        decrypt_for_db,
        serialize_value,
        deserialize_value,
    )
    from navigator_session.vault.config import (
        load_master_keys,
        get_active_master_key,
    )

    VAULT_CRYPTO_AVAILABLE = True
except ImportError:
    VAULT_CRYPTO_AVAILABLE = False

_UNAVAILABLE_MSG = (
    "Identity Vault requires navigator-session with vault crypto support "
    "and VAULT_MASTER_KEY_v{N} / VAULT_ACTIVE_KEY_ID configured."
)


class IdentityCipher:
    """Encrypt/decrypt identity credential values with the vault master keys.

    Values are serialized with the vault's own serializer, so any
    JSON-representable value (str, dict, list, ...) round-trips.
    """

    def __init__(self, master_keys: Optional[dict] = None):
        if not VAULT_CRYPTO_AVAILABLE:
            raise ConfigError(_UNAVAILABLE_MSG)
        try:
            self._master_keys: dict = (
                master_keys if master_keys is not None else load_master_keys()
            )
            try:
                self._key_id, self._active_key = get_active_master_key(
                    self._master_keys
                )
            except (RuntimeError, KeyError):
                # VAULT_ACTIVE_KEY_ID unset (or stale): use the newest key.
                self._key_id = max(self._master_keys)
                self._active_key = self._master_keys[self._key_id]
        except (RuntimeError, ValueError, KeyError, TypeError) as err:
            raise ConfigError(f"{_UNAVAILABLE_MSG} ({err})") from err

    @property
    def key_id(self) -> int:
        return self._key_id

    def encrypt(self, value: Any) -> bytes:
        """Serialize and encrypt *value* under the active master key.

        The key id travels inside the ciphertext, so decryption only
        needs the key ring.
        """
        plaintext = serialize_value(value)
        return encrypt_for_db(
            plaintext, key_id=self._key_id, master_key=self._active_key
        )

    def decrypt(self, ciphertext: bytes) -> Any:
        """Decrypt and deserialize a value produced by :meth:`encrypt`."""
        if isinstance(ciphertext, memoryview):
            ciphertext = bytes(ciphertext)
        plaintext = decrypt_for_db(ciphertext, self._master_keys)
        return deserialize_value(plaintext)
