"""Unit tests for navigator_auth.identity.crypto (IdentityCipher)."""
import base64

import pytest

from navigator_auth.exceptions import ConfigError
from navigator_auth.identity import crypto as crypto_mod
from navigator_auth.identity.crypto import IdentityCipher


@pytest.fixture
def master_keys() -> dict[int, bytes]:
    return {1: b"\x00" * 32, 2: b"\x01" * 32}


@pytest.fixture
def vault_env(monkeypatch, master_keys):
    """Expose deterministic master keys through the vault env variables."""
    for key_id, key in master_keys.items():
        monkeypatch.setenv(
            f"VAULT_MASTER_KEY_v{key_id}",
            base64.b64encode(key).decode(),
        )
    monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "2")


class TestIdentityCipher:
    def test_roundtrip_string(self, master_keys):
        cipher = IdentityCipher(master_keys={1: master_keys[1]})
        ct = cipher.encrypt("gh_token_abc123")
        assert isinstance(ct, bytes)
        assert cipher.decrypt(ct) == "gh_token_abc123"

    def test_roundtrip_dict(self, master_keys):
        cipher = IdentityCipher(master_keys={1: master_keys[1]})
        value = {"access_token": "abc", "scopes": ["read:user"], "n": 3}
        assert cipher.decrypt(cipher.encrypt(value)) == value

    def test_ciphertext_not_plaintext(self, master_keys):
        cipher = IdentityCipher(master_keys={1: master_keys[1]})
        ct = cipher.encrypt("super-secret")
        assert b"super-secret" not in ct

    def test_uses_active_key_from_env(self, vault_env):
        cipher = IdentityCipher()
        assert cipher.key_id == 2
        assert cipher.decrypt(cipher.encrypt("x")) == "x"

    def test_wrong_key_fails(self, master_keys):
        cipher_a = IdentityCipher(master_keys={1: master_keys[1]})
        ct = cipher_a.encrypt("value")
        cipher_b = IdentityCipher(master_keys={1: b"\x02" * 32})
        with pytest.raises(Exception):
            cipher_b.decrypt(ct)

    def test_decrypt_memoryview(self, master_keys):
        """DB drivers may hand back memoryview for BYTEA columns."""
        cipher = IdentityCipher(master_keys={1: master_keys[1]})
        ct = cipher.encrypt("value")
        assert cipher.decrypt(memoryview(ct)) == "value"

    def test_key_rotation_old_ciphertext_still_readable(self, master_keys):
        old = IdentityCipher(master_keys={1: master_keys[1]})
        ct_old = old.encrypt("legacy")
        # New cipher holds both keys, active key is the highest id
        new = IdentityCipher(master_keys=master_keys)
        assert new.decrypt(ct_old) == "legacy"
        assert new.key_id == 2

    def test_missing_keys_raises_configerror(self, monkeypatch):
        monkeypatch.delenv("VAULT_MASTER_KEY_v1", raising=False)
        monkeypatch.delenv("VAULT_ACTIVE_KEY_ID", raising=False)
        with pytest.raises(ConfigError):
            IdentityCipher()

    def test_unavailable_crypto_raises_configerror(
        self, monkeypatch, master_keys
    ):
        monkeypatch.setattr(crypto_mod, "VAULT_CRYPTO_AVAILABLE", False)
        with pytest.raises(ConfigError):
            IdentityCipher(master_keys=master_keys)
