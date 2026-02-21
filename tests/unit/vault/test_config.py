"""Unit tests for navigator_session.vault.config module."""
import os
import base64

import pytest

from navigator_session.vault.config import (
    load_master_keys,
    get_active_key_id,
    get_active_master_key,
    generate_master_key,
    VaultConfig,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key_v1() -> bytes:
    """Deterministic 32-byte master key for testing."""
    return b"\x00" * 32


@pytest.fixture
def master_key_v2() -> bytes:
    return b"\x01" * 32


@pytest.fixture(autouse=True)
def vault_env(master_key_v1, master_key_v2, monkeypatch):
    """Set up vault environment variables for tests."""
    monkeypatch.setenv("VAULT_MASTER_KEY_v1", base64.b64encode(master_key_v1).decode())
    monkeypatch.setenv("VAULT_MASTER_KEY_v2", base64.b64encode(master_key_v2).decode())
    monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "2")


# ---------------------------------------------------------------------------
# load_master_keys
# ---------------------------------------------------------------------------

class TestLoadMasterKeys:
    def test_loads_keys_from_env(self):
        """Reads VAULT_MASTER_KEY_v{N} env vars and returns dict[int, bytes]."""
        keys = load_master_keys()
        assert 1 in keys
        assert 2 in keys
        assert len(keys) == 2

    def test_key_values_are_correct(self, master_key_v1, master_key_v2):
        """Decoded keys match the original bytes."""
        keys = load_master_keys()
        assert keys[1] == master_key_v1
        assert keys[2] == master_key_v2

    def test_key_length_is_32(self):
        """Each loaded key is exactly 32 bytes."""
        keys = load_master_keys()
        for key_bytes in keys.values():
            assert len(key_bytes) == 32

    def test_rejects_wrong_length_16_bytes(self, monkeypatch):
        """Keys that are not exactly 32 bytes after decode are rejected."""
        monkeypatch.setenv(
            "VAULT_MASTER_KEY_v3",
            base64.b64encode(b"\x00" * 16).decode()
        )
        with pytest.raises(ValueError, match="32 bytes"):
            load_master_keys()

    def test_rejects_wrong_length_64_bytes(self, monkeypatch):
        """Keys longer than 32 bytes are also rejected."""
        monkeypatch.setenv(
            "VAULT_MASTER_KEY_v3",
            base64.b64encode(b"\x00" * 64).decode()
        )
        with pytest.raises(ValueError, match="32 bytes"):
            load_master_keys()

    def test_empty_env_raises_runtime_error(self, monkeypatch):
        """No VAULT_MASTER_KEY_v* env vars raises RuntimeError."""
        monkeypatch.delenv("VAULT_MASTER_KEY_v1")
        monkeypatch.delenv("VAULT_MASTER_KEY_v2")
        with pytest.raises(RuntimeError):
            load_master_keys()

    def test_invalid_base64_raises(self, monkeypatch):
        """Non-base64 value raises an error."""
        monkeypatch.setenv("VAULT_MASTER_KEY_v3", "not-valid-base64!!!")
        with pytest.raises(Exception):
            load_master_keys()

    def test_loads_single_key(self, monkeypatch):
        """Works with only one master key in env."""
        monkeypatch.delenv("VAULT_MASTER_KEY_v2")
        keys = load_master_keys()
        assert len(keys) == 1
        assert 1 in keys

    def test_version_numbers_parsed_correctly(self, monkeypatch):
        """Multi-digit version numbers (e.g. v10) are parsed correctly."""
        monkeypatch.setenv(
            "VAULT_MASTER_KEY_v10",
            base64.b64encode(b"\xaa" * 32).decode()
        )
        keys = load_master_keys()
        assert 10 in keys
        assert len(keys[10]) == 32


# ---------------------------------------------------------------------------
# get_active_key_id
# ---------------------------------------------------------------------------

class TestGetActiveKeyId:
    def test_reads_from_env(self):
        """Returns integer from VAULT_ACTIVE_KEY_ID."""
        assert get_active_key_id() == 2

    def test_different_value(self, monkeypatch):
        """Returns correct value when env var changes."""
        monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "1")
        assert get_active_key_id() == 1

    def test_missing_env_raises(self, monkeypatch):
        """Missing VAULT_ACTIVE_KEY_ID raises an error."""
        monkeypatch.delenv("VAULT_ACTIVE_KEY_ID")
        with pytest.raises(Exception):
            get_active_key_id()

    def test_non_integer_raises(self, monkeypatch):
        """Non-integer VAULT_ACTIVE_KEY_ID raises ValueError."""
        monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "abc")
        with pytest.raises(ValueError):
            get_active_key_id()


# ---------------------------------------------------------------------------
# get_active_master_key
# ---------------------------------------------------------------------------

class TestGetActiveMasterKey:
    def test_returns_tuple(self, master_key_v1, master_key_v2):
        """Returns (active_key_id, active_key_bytes) tuple."""
        keys = {1: master_key_v1, 2: master_key_v2}
        key_id, key_bytes = get_active_master_key(keys)
        assert key_id == 2
        assert key_bytes == master_key_v2

    def test_missing_active_key_raises(self, master_key_v1, monkeypatch):
        """Raises KeyError if active_key_id not in master_keys."""
        monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "99")
        keys = {1: master_key_v1}
        with pytest.raises(KeyError):
            get_active_master_key(keys)


# ---------------------------------------------------------------------------
# generate_master_key
# ---------------------------------------------------------------------------

class TestGenerateMasterKey:
    def test_returns_string(self):
        """Returns a base64-encoded string."""
        result = generate_master_key()
        assert isinstance(result, str)

    def test_decodes_to_32_bytes(self):
        """Base64-decoded result is exactly 32 bytes."""
        result = generate_master_key()
        key_bytes = base64.b64decode(result)
        assert len(key_bytes) == 32

    def test_different_each_call(self):
        """Two calls produce different keys (random)."""
        k1 = generate_master_key()
        k2 = generate_master_key()
        assert k1 != k2


# ---------------------------------------------------------------------------
# VaultConfig Pydantic model
# ---------------------------------------------------------------------------

class TestVaultConfig:
    def test_valid_config_defaults(self):
        """Valid config with default values."""
        config = VaultConfig(
            master_keys={1: b"\x00" * 32},
            active_key_id=1,
        )
        assert config.cipher_backend == "aesgcm"
        assert config.max_keys_per_user == 50
        assert config.session_ttl == 3600

    def test_custom_values(self):
        """Custom values are accepted."""
        config = VaultConfig(
            master_keys={1: b"\x00" * 32, 2: b"\x01" * 32},
            active_key_id=2,
            cipher_backend="chacha20",
            max_keys_per_user=100,
            session_ttl=7200,
        )
        assert config.cipher_backend == "chacha20"
        assert config.max_keys_per_user == 100
        assert config.session_ttl == 7200
        assert config.active_key_id == 2

    def test_invalid_cipher_backend(self):
        """Invalid cipher backend is rejected."""
        with pytest.raises(ValueError):
            VaultConfig(
                master_keys={1: b"\x00" * 32},
                active_key_id=1,
                cipher_backend="invalid",
            )

    def test_max_keys_per_user_lower_bound(self):
        """max_keys_per_user must be >= 1."""
        with pytest.raises(ValueError):
            VaultConfig(
                master_keys={1: b"\x00" * 32},
                active_key_id=1,
                max_keys_per_user=0,
            )

    def test_max_keys_per_user_upper_bound(self):
        """max_keys_per_user must be <= 1000."""
        with pytest.raises(ValueError):
            VaultConfig(
                master_keys={1: b"\x00" * 32},
                active_key_id=1,
                max_keys_per_user=1001,
            )

    def test_session_ttl_lower_bound(self):
        """session_ttl must be >= 60."""
        with pytest.raises(ValueError):
            VaultConfig(
                master_keys={1: b"\x00" * 32},
                active_key_id=1,
                session_ttl=30,
            )

    def test_from_env_factory(self):
        """VaultConfig.from_env() loads config from environment."""
        config = VaultConfig.from_env()
        assert 1 in config.master_keys
        assert 2 in config.master_keys
        assert config.active_key_id == 2

    def test_active_key_not_in_master_keys(self):
        """VaultConfig rejects active_key_id not present in master_keys."""
        with pytest.raises(ValueError, match="active_key_id"):
            VaultConfig(
                master_keys={1: b"\x00" * 32},
                active_key_id=99,
            )
