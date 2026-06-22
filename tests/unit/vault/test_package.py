"""Unit tests for navigator_session.vault package exports."""
import pytest


class TestVaultPackageImports:
    def test_import_session_vault(self):
        """SessionVault is importable from navigator_session.vault."""
        from navigator_session.vault import SessionVault
        assert SessionVault is not None

    def test_import_rotate_master_key(self):
        """rotate_master_key is importable and callable."""
        from navigator_session.vault import rotate_master_key
        assert callable(rotate_master_key)

    def test_import_vault_config(self):
        """VaultConfig is importable from navigator_session.vault."""
        from navigator_session.vault import VaultConfig
        assert VaultConfig is not None

    def test_import_load_master_keys(self):
        """load_master_keys is importable and callable."""
        from navigator_session.vault import load_master_keys
        assert callable(load_master_keys)

    def test_import_generate_master_key(self):
        """generate_master_key is importable and callable."""
        from navigator_session.vault import generate_master_key
        assert callable(generate_master_key)

    def test_all_exports(self):
        """__all__ contains expected public names."""
        import navigator_session.vault as vault_pkg
        expected = {
            "SessionVault",
            "rotate_master_key",
            "VaultConfig",
            "load_master_keys",
            "generate_master_key",
        }
        assert expected.issubset(set(vault_pkg.__all__))

    def test_no_circular_imports(self):
        """Package can be imported without circular import errors."""
        import importlib
        mod = importlib.import_module("navigator_session.vault")
        assert mod is not None

    def test_threat_model_docstring(self):
        """Package docstring includes threat model note."""
        import navigator_session.vault as vault_pkg
        assert "memory" in vault_pkg.__doc__.lower()
        assert "threat" in vault_pkg.__doc__.lower() or "security" in vault_pkg.__doc__.lower()
