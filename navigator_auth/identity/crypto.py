"""Cipher for identity credentials at rest.

Reuses the Session Vault kernel from ``navigator-session`` (envelope v2) so
identity credentials share the vault master keys (``VAULT_MASTER_KEY_v{N}`` +
``VAULT_ACTIVE_KEY_ID``) and key-rotation semantics with
``auth.user_vault_secrets``.

Every token is bound (AEAD associated data) to its identity row and column::

    VaultContext(purpose="identity", layer="db",
                 fields=(user_id, auth_provider, provider_user_id, field))

so a token copied to another user, provider account or column
(``access_token`` ↔ ``refresh_token`` ↔ ``id_token``) fails to decrypt.
"""

import os
from typing import Any, Optional

from ..exceptions import ConfigError

try:
    from navigator_session.vault import (
        KeyRing,
        VaultContext,
        open_value,
        seal_value,
    )
    from navigator_session.vault.config import get_active_key_id, load_master_keys

    VAULT_CRYPTO_AVAILABLE = True
except ImportError:
    VAULT_CRYPTO_AVAILABLE = False

_UNAVAILABLE_MSG = (
    "Identity Vault requires navigator-session with vault crypto support "
    "and VAULT_MASTER_KEY_v{N} / VAULT_ACTIVE_KEY_ID configured."
)

IDENTITY_PURPOSE = "identity"
IDENTITY_FIELDS = ("access_token", "refresh_token", "id_token")


def normalize_user_id(user_id: Any) -> Any:
    """Canonical ``user_id`` for identity contexts.

    Integers (and digit-only strings, as sessions may carry them) become
    ``int``; other non-empty strings (username-keyed backends) stay ``str``.
    Runtime sealing and the migration target must agree on this value.

    Raises:
        ValueError: If ``user_id`` is empty, a bool, or of another type.
    """
    user_id = getattr(user_id, "user_id", user_id)
    if isinstance(user_id, bool):
        raise ValueError("user_id must not be a bool")
    if isinstance(user_id, int):
        return user_id
    if isinstance(user_id, str) and user_id.strip():
        value = user_id.strip()
        return int(value) if value.isdigit() else value
    raise ValueError("user_id is required for identity credentials")


def identity_context(
    *, user_id: Any, auth_provider: str, provider_user_id: Optional[str], field: str
) -> "VaultContext":
    """Build the context binding one identity token column.

    Args:
        user_id: Owner of the identity (normalized with :func:`normalize_user_id`).
        auth_provider: Provider name as stored in ``auth.user_identities``.
        provider_user_id: External account id, or ``None`` (encoded as NULL).
        field: ``access_token``, ``refresh_token`` or ``id_token``.

    Raises:
        ValueError: On an unknown field or missing provider.
    """
    if field not in IDENTITY_FIELDS:
        raise ValueError(f"unknown identity credential field {field!r}")
    if not auth_provider:
        raise ValueError("auth_provider is required for identity credentials")
    return VaultContext(
        purpose=IDENTITY_PURPOSE,
        layer="db",
        fields=(
            ("user_id", normalize_user_id(user_id)),
            ("auth_provider", str(auth_provider)),
            ("provider_user_id", None if provider_user_id is None else str(provider_user_id)),
            ("field", field),
        ),
    )


class IdentityCipher:
    """Encrypt/decrypt identity credential values with the vault master keys.

    Values are serialized with the vault's own serializer, so any
    JSON-representable value (str, dict, list, ...) round-trips.

    Args:
        master_keys: Explicit key ring (tests/tools). The active key is
            ``VAULT_ACTIVE_KEY_ID`` when present in the ring, else the newest key.
        keyring: A ready :class:`~navigator_session.vault.KeyRing` (takes precedence).

    Raises:
        ConfigError: If vault crypto is unavailable or keys are misconfigured.
    """

    def __init__(self, master_keys: Optional[dict] = None, *, keyring: Optional["KeyRing"] = None):
        if not VAULT_CRYPTO_AVAILABLE:
            raise ConfigError(_UNAVAILABLE_MSG)
        try:
            if keyring is not None:
                self._keyring = keyring
            else:
                explicit = master_keys is not None
                keys = master_keys if explicit else load_master_keys()
                try:
                    active = get_active_key_id()
                    if active not in keys:
                        raise KeyError(active)
                except (RuntimeError, KeyError, ValueError):
                    # VAULT_ACTIVE_KEY_ID unset (or stale): use the newest key.
                    active = max(keys)
                self._keyring = KeyRing(
                    keys,
                    active,
                    cipher_backend=os.environ.get("VAULT_CIPHER_BACKEND", "aesgcm"),
                    # The naming key is irrelevant here; with an explicit ring,
                    # do not let VAULT_NAMING_KEY_ID point outside it.
                    naming_key_id=None if explicit else _env_naming_key_id(),
                )
        except (RuntimeError, ValueError, KeyError, TypeError) as err:
            raise ConfigError(f"{_UNAVAILABLE_MSG} ({err})") from err

    @property
    def key_id(self) -> int:
        """Master key version used for new ciphertexts."""
        return self._keyring.active_key_id

    @property
    def keyring(self) -> "KeyRing":
        """Underlying key ring (shared with the vault kernel)."""
        return self._keyring

    def encrypt(
        self,
        value: Any,
        *,
        user_id: Any,
        auth_provider: str,
        provider_user_id: Optional[str],
        field: str,
    ) -> bytes:
        """Serialize and seal *value* bound to its identity row and column."""
        context = identity_context(
            user_id=user_id,
            auth_provider=auth_provider,
            provider_user_id=provider_user_id,
            field=field,
        )
        return seal_value(value, context, self._keyring)

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        user_id: Any,
        auth_provider: str,
        provider_user_id: Optional[str],
        field: str,
    ) -> Any:
        """Open a value sealed by :meth:`encrypt` for the same row and column.

        Raises:
            navigator_session.vault.VaultCryptoError: If the ciphertext was
                tampered with, belongs to another row/column, uses an unknown key
                version or a legacy format.
        """
        if isinstance(ciphertext, memoryview):
            ciphertext = bytes(ciphertext)
        context = identity_context(
            user_id=user_id,
            auth_provider=auth_provider,
            provider_user_id=provider_user_id,
            field=field,
        )
        return open_value(ciphertext, context, self._keyring)


def _env_naming_key_id() -> Optional[int]:
    from navigator_session.vault.config import get_naming_key_id  # pylint: disable=import-outside-toplevel

    return get_naming_key_id()
