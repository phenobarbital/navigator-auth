"""Navigator Auth — Vault integration package."""
from .integration import (
    load_vault_for_session,
    setup_vault_tables,
    VAULT_SESSION_KEY,
)
from .migrations import ensure_vault_tables

__all__ = [
    "load_vault_for_session",
    "setup_vault_tables",
    "ensure_vault_tables",
    "VAULT_SESSION_KEY",
]
