"""Unit tests for navigator_auth.identity.crypto (IdentityCipher, envelope v2)."""
import base64
import os

import pytest
from navigator_session.vault import (
    KeyRing,
    UnknownKeyVersionError,
    UnsupportedFormatError,
    VaultIntegrityError,
    read_header,
)

from navigator_auth.exceptions import ConfigError
from navigator_auth.identity import crypto as crypto_mod
from navigator_auth.identity.crypto import IdentityCipher, identity_context, normalize_user_id

CTX = dict(user_id=1, auth_provider="google", provider_user_id="g-1")


@pytest.fixture
def master_keys() -> dict[int, bytes]:
    return {1: b"\x00" * 32, 2: b"\x01" * 32}


@pytest.fixture
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("VAULT_"):
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def vault_env(clean_env, master_keys):
    """Expose deterministic master keys through the vault env variables."""
    for key_id, key in master_keys.items():
        clean_env.setenv(f"VAULT_MASTER_KEY_v{key_id}", base64.b64encode(key).decode())
    clean_env.setenv("VAULT_ACTIVE_KEY_ID", "2")


@pytest.fixture
def cipher(clean_env, master_keys):
    return IdentityCipher(master_keys={1: master_keys[1]})


class TestRoundTrip:
    def test_roundtrip_string(self, cipher):
        ct = cipher.encrypt("gh_token_abc123", field="access_token", **CTX)
        assert isinstance(ct, bytes) and ct[0] == 0xA2
        assert cipher.decrypt(ct, field="access_token", **CTX) == "gh_token_abc123"

    def test_roundtrip_dict(self, cipher):
        value = {"access_token": "abc", "scopes": ["read:user"], "n": 3}
        ct = cipher.encrypt(value, field="id_token", **CTX)
        assert cipher.decrypt(ct, field="id_token", **CTX) == value

    def test_ciphertext_not_plaintext(self, cipher):
        assert b"super-secret" not in cipher.encrypt("super-secret", field="access_token", **CTX)

    def test_decrypt_memoryview(self, cipher):
        """DB drivers may hand back memoryview for BYTEA columns."""
        ct = cipher.encrypt("value", field="refresh_token", **CTX)
        assert cipher.decrypt(memoryview(ct), field="refresh_token", **CTX) == "value"

    def test_uses_active_key_from_env(self, vault_env):
        cipher = IdentityCipher()
        assert cipher.key_id == 2
        ct = cipher.encrypt("x", field="access_token", **CTX)
        assert read_header(ct).key_id == 2
        assert cipher.decrypt(ct, field="access_token", **CTX) == "x"

    def test_key_rotation_old_ciphertext_still_readable(self, clean_env, master_keys):
        old = IdentityCipher(master_keys={1: master_keys[1]})
        ct_old = old.encrypt("legacy", field="access_token", **CTX)
        # New cipher holds both keys; without VAULT_ACTIVE_KEY_ID the newest is active.
        new = IdentityCipher(master_keys=master_keys)
        assert new.key_id == 2
        assert new.decrypt(ct_old, field="access_token", **CTX) == "legacy"

    def test_stale_active_key_falls_back_to_newest(self, clean_env, master_keys):
        clean_env.setenv("VAULT_ACTIVE_KEY_ID", "9")
        assert IdentityCipher(master_keys=master_keys).key_id == 2

    def test_explicit_keyring(self, master_keys):
        ring = KeyRing(master_keys, 1)
        cipher = IdentityCipher(keyring=ring)
        assert cipher.keyring is ring and cipher.key_id == 1


class TestContextBinding:
    @pytest.mark.parametrize(
        "other",
        [
            dict(CTX, user_id=2),
            dict(CTX, auth_provider="github"),
            dict(CTX, provider_user_id="g-2"),
            dict(CTX, provider_user_id=None),
        ],
        ids=["user", "provider", "account", "null-account"],
    )
    def test_moved_between_rows(self, cipher, other):
        ct = cipher.encrypt("acc", field="access_token", **CTX)
        with pytest.raises(VaultIntegrityError):
            cipher.decrypt(ct, field="access_token", **other)

    @pytest.mark.parametrize("target_field", ["refresh_token", "id_token"])
    def test_moved_between_columns(self, cipher, target_field):
        ct = cipher.encrypt("acc", field="access_token", **CTX)
        with pytest.raises(VaultIntegrityError):
            cipher.decrypt(ct, field=target_field, **CTX)

    def test_null_provider_user_id_distinct_from_empty(self, cipher):
        ct = cipher.encrypt("acc", field="access_token", **dict(CTX, provider_user_id=None))
        with pytest.raises(VaultIntegrityError):
            cipher.decrypt(ct, field="access_token", **dict(CTX, provider_user_id=""))

    def test_numeric_string_user_id_matches_int(self, cipher):
        ct = cipher.encrypt("acc", field="access_token", **dict(CTX, user_id="1"))
        assert cipher.decrypt(ct, field="access_token", **CTX) == "acc"

    def test_wrong_key_fails(self, cipher):
        ct = cipher.encrypt("value", field="access_token", **CTX)
        other = IdentityCipher(master_keys={1: b"\x02" * 32})
        with pytest.raises(VaultIntegrityError):
            other.decrypt(ct, field="access_token", **CTX)

    def test_unknown_key_version(self, clean_env, master_keys):
        ct = IdentityCipher(master_keys=master_keys).encrypt("v", field="access_token", **CTX)
        with pytest.raises(UnknownKeyVersionError):
            IdentityCipher(master_keys={1: master_keys[1]}).decrypt(ct, field="access_token", **CTX)

    def test_legacy_v1_blob_rejected(self, cipher):
        v1_blob = b"\x00\x01" + os.urandom(40)
        with pytest.raises(UnsupportedFormatError):
            cipher.decrypt(v1_blob, field="access_token", **CTX)

    def test_unknown_field(self, cipher):
        with pytest.raises(ValueError):
            cipher.encrypt("v", field="password", **CTX)


class TestHelpers:
    @pytest.mark.parametrize("value,expected", [(7, 7), ("7", 7), (" 7 ", 7), ("alice", "alice")])
    def test_normalize_user_id(self, value, expected):
        assert normalize_user_id(value) == expected

    @pytest.mark.parametrize("value", [None, "", True, 1.5])
    def test_normalize_user_id_rejects(self, value):
        with pytest.raises(ValueError):
            normalize_user_id(value)

    def test_context_shape(self):
        ctx = identity_context(user_id="5", auth_provider="azure", provider_user_id=None, field="id_token")
        assert ctx.purpose == "identity" and ctx.layer == "db"
        assert ctx.fields == (("user_id", 5), ("auth_provider", "azure"),
                              ("provider_user_id", None), ("field", "id_token"))


class TestConfiguration:
    def test_missing_keys_raises_configerror(self, clean_env):
        with pytest.raises(ConfigError):
            IdentityCipher()

    def test_unavailable_crypto_raises_configerror(self, monkeypatch, master_keys):
        monkeypatch.setattr(crypto_mod, "VAULT_CRYPTO_AVAILABLE", False)
        with pytest.raises(ConfigError):
            IdentityCipher(master_keys=master_keys)

    def test_explicit_ring_ignores_env_naming_key(self, clean_env, master_keys):
        clean_env.setenv("VAULT_NAMING_KEY_ID", "9")
        assert IdentityCipher(master_keys=master_keys).key_id == 2

    def test_invalid_key_raises_configerror(self, clean_env):
        with pytest.raises(ConfigError):
            IdentityCipher(master_keys={1: b"short"})
