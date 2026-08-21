"""Identity Vault.

Support for linking external provider credentials (OAuth2 access/refresh
tokens) to an authenticated user, stored ciphered in ``auth.user_identities``.
"""
from .types import TokenResponse
from .crypto import IdentityCipher, VAULT_CRYPTO_AVAILABLE
from .flow_store import IdentityFlowStore, LINK_KEY_PREFIX
from .migrations import ensure_identity_columns, setup_identity_columns

__all__ = (
    "TokenResponse",
    "IdentityCipher",
    "VAULT_CRYPTO_AVAILABLE",
    "IdentityFlowStore",
    "LINK_KEY_PREFIX",
    "ensure_identity_columns",
    "setup_identity_columns",
)
