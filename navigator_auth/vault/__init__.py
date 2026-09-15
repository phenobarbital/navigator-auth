"""Navigator Auth — Vault integration package."""
from .integration import (
    load_vault_for_session,
    setup_vault_tables,
    get_session_vault,
    setup_vault_keyring,
    VAULT_KEYRING_APP_KEY,
    VAULT_SESSION_KEY,
)
from .migrations import ensure_vault_tables

__all__ = [
    "load_vault_for_session",
    "setup_vault_tables",
    "ensure_vault_tables",
    "get_session_vault",
    "setup_vault_keyring",
    "VAULT_KEYRING_APP_KEY",
    "VAULT_SESSION_KEY",
]
