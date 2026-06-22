"""Unit tests for navigator_session.vault.crypto module."""
import struct

import pytest
import orjson

from navigator_session.vault.crypto import (
    derive_key,
    encrypt_for_session,
    decrypt_for_session,
    encrypt_for_db,
    decrypt_for_db,
    serialize_value,
    deserialize_value,
)
import navigator_session.vault.crypto as crypto_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key_v1() -> bytes:
    """Deterministic master key for testing."""
    return b"\x00" * 32


@pytest.fixture
def master_key_v2() -> bytes:
    return b"\x01" * 32


@pytest.fixture
def master_keys(master_key_v1, master_key_v2) -> dict[int, bytes]:
    return {1: master_key_v1, 2: master_key_v2}


@pytest.fixture
def session_uuid() -> str:
    return "550e8400-e29b-41d4-a716-446655440000"


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_deterministic(self):
        """Same seed + context always produces same key."""
        seed = b"\x42" * 32
        k1 = derive_key(seed, "ctx")
        k2 = derive_key(seed, "ctx")
        assert k1 == k2

    def test_output_length_32(self):
        """Derived key is always 32 bytes."""
        key = derive_key(b"seed-material", "context")
        assert len(key) == 32

    def test_different_contexts_produce_different_keys(self):
        """Different contexts produce different keys."""
        seed = b"\x42" * 32
        k1 = derive_key(seed, "vault-session")
        k2 = derive_key(seed, "vault-db-v1")
        assert k1 != k2

    def test_different_seeds_produce_different_keys(self):
        """Different seeds produce different keys."""
        k1 = derive_key(b"\x00" * 32, "ctx")
        k2 = derive_key(b"\x01" * 32, "ctx")
        assert k1 != k2

    def test_uuid_string_input(self, session_uuid):
        """UUID string encoded as bytes produces valid 32-byte key."""
        key = derive_key(session_uuid.encode(), "vault-session")
        assert len(key) == 32
        assert isinstance(key, bytes)


# ---------------------------------------------------------------------------
# Session encryption
# ---------------------------------------------------------------------------

class TestSessionEncryption:
    def test_roundtrip(self, session_uuid):
        """encrypt_for_session → decrypt_for_session returns original."""
        plaintext = b"secret-data-for-session"
        ct = encrypt_for_session(plaintext, session_uuid)
        pt = decrypt_for_session(ct, session_uuid)
        assert pt == plaintext

    def test_ciphertext_differs_from_plaintext(self, session_uuid):
        """Ciphertext is not the same as plaintext."""
        plaintext = b"secret-data"
        ct = encrypt_for_session(plaintext, session_uuid)
        assert ct != plaintext

    def test_ciphertext_has_nonce_prefix(self, session_uuid):
        """ciphertext_mem is at least 12 (nonce) + 16 (tag) bytes."""
        ct = encrypt_for_session(b"x", session_uuid)
        assert len(ct) >= 12 + 16 + 1  # nonce + tag + 1 byte payload

    def test_wrong_session_fails(self, session_uuid):
        """Decryption with wrong session_uuid raises error."""
        ct = encrypt_for_session(b"secret", session_uuid)
        with pytest.raises(Exception):
            decrypt_for_session(ct, "wrong-uuid-value-here-00000000000")

    def test_different_encryptions_differ(self, session_uuid):
        """Two encryptions of same plaintext produce different ciphertexts (random nonce)."""
        pt = b"same-data"
        ct1 = encrypt_for_session(pt, session_uuid)
        ct2 = encrypt_for_session(pt, session_uuid)
        assert ct1 != ct2

    def test_empty_plaintext(self, session_uuid):
        """Empty plaintext round-trips correctly."""
        ct = encrypt_for_session(b"", session_uuid)
        pt = decrypt_for_session(ct, session_uuid)
        assert pt == b""


# ---------------------------------------------------------------------------
# DB encryption
# ---------------------------------------------------------------------------

class TestDbEncryption:
    def test_roundtrip(self, master_keys, master_key_v1):
        """encrypt_for_db → decrypt_for_db returns original."""
        plaintext = b"db-secret-value"
        ct = encrypt_for_db(plaintext, key_id=1, master_key=master_key_v1)
        pt = decrypt_for_db(ct, master_keys)
        assert pt == plaintext

    def test_key_id_in_first_two_bytes(self, master_keys, master_key_v2):
        """First 2 bytes of ciphertext_db encode key_id as uint16 big-endian."""
        ct = encrypt_for_db(b"data", key_id=2, master_key=master_key_v2)
        key_id = struct.unpack("!H", ct[:2])[0]
        assert key_id == 2

    def test_key_id_1(self, master_keys, master_key_v1):
        """key_id=1 is correctly embedded."""
        ct = encrypt_for_db(b"data", key_id=1, master_key=master_key_v1)
        key_id = struct.unpack("!H", ct[:2])[0]
        assert key_id == 1

    def test_ciphertext_minimum_length(self, master_key_v1):
        """ciphertext_db is at least 2 (key_id) + 12 (nonce) + 16 (tag) bytes."""
        ct = encrypt_for_db(b"x", key_id=1, master_key=master_key_v1)
        assert len(ct) >= 2 + 12 + 16 + 1

    def test_wrong_key_fails(self, master_key_v1):
        """Decryption with wrong master key raises error."""
        ct = encrypt_for_db(b"data", key_id=1, master_key=master_key_v1)
        wrong_keys = {1: b"\xff" * 32}
        with pytest.raises(Exception):
            decrypt_for_db(ct, wrong_keys)

    def test_missing_key_version_raises_key_error(self, master_keys, master_key_v1):
        """Missing key_id in master_keys dict raises KeyError."""
        ct = encrypt_for_db(b"data", key_id=1, master_key=master_key_v1)
        with pytest.raises(KeyError):
            decrypt_for_db(ct, {2: master_keys[2]})  # key_id 1 not present

    def test_multi_key_version_coexist(self, master_keys, master_key_v1, master_key_v2):
        """Secrets encrypted with different key versions decrypt correctly."""
        ct1 = encrypt_for_db(b"secret-v1", key_id=1, master_key=master_key_v1)
        ct2 = encrypt_for_db(b"secret-v2", key_id=2, master_key=master_key_v2)
        assert decrypt_for_db(ct1, master_keys) == b"secret-v1"
        assert decrypt_for_db(ct2, master_keys) == b"secret-v2"

    def test_empty_plaintext(self, master_keys, master_key_v1):
        """Empty plaintext round-trips correctly."""
        ct = encrypt_for_db(b"", key_id=1, master_key=master_key_v1)
        pt = decrypt_for_db(ct, master_keys)
        assert pt == b""


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    @pytest.mark.parametrize("value", [
        "hello",
        42,
        3.14,
        {"key": "val", "nested": {"a": 1}},
        [1, 2, 3],
        True,
        False,
        None,
    ])
    def test_roundtrip_json_types(self, value):
        """Round-trip for standard JSON-compatible types."""
        data = serialize_value(value)
        result = deserialize_value(data)
        assert result == value

    def test_roundtrip_bytes(self):
        """bytes values round-trip via base64 wrapper."""
        value = b"\x00\x01\x02\xff\xfe"
        data = serialize_value(value)
        result = deserialize_value(data)
        assert result == value

    def test_bytes_uses_vault_wrapper_key(self):
        """bytes serialization uses __vault_bytes_b64__ key for safe JSON round-trip."""
        data = serialize_value(b"\xff\xfe")
        parsed = orjson.loads(data)
        assert "__vault_bytes_b64__" in parsed

    def test_serialize_returns_bytes(self):
        """serialize_value always returns bytes."""
        assert isinstance(serialize_value("hello"), bytes)
        assert isinstance(serialize_value(42), bytes)
        assert isinstance(serialize_value(b"\x00"), bytes)

    def test_empty_string(self):
        """Empty string round-trips."""
        assert deserialize_value(serialize_value("")) == ""

    def test_empty_bytes(self):
        """Empty bytes round-trips."""
        assert deserialize_value(serialize_value(b"")) == b""

    def test_empty_dict(self):
        """Empty dict round-trips."""
        assert deserialize_value(serialize_value({})) == {}

    def test_empty_list(self):
        """Empty list round-trips."""
        assert deserialize_value(serialize_value([])) == []

    def test_large_int(self):
        """Large integers round-trip."""
        val = 2**63
        assert deserialize_value(serialize_value(val)) == val

    def test_negative_float(self):
        """Negative floats round-trip."""
        val = -3.14159
        result = deserialize_value(serialize_value(val))
        assert abs(result - val) < 1e-10


# ---------------------------------------------------------------------------
# Cipher backend selection
# ---------------------------------------------------------------------------

class TestCipherBackend:
    def test_default_aesgcm_roundtrip(self, session_uuid):
        """Default backend (AES-GCM) encrypts/decrypts correctly."""
        ct = encrypt_for_session(b"data", session_uuid)
        pt = decrypt_for_session(ct, session_uuid)
        assert pt == b"data"

    def test_chacha20_session_roundtrip(self, session_uuid, monkeypatch):
        """ChaCha20-Poly1305 backend encrypts/decrypts for session."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        monkeypatch.setattr(crypto_mod, "CIPHER_CLS", ChaCha20Poly1305)
        ct = encrypt_for_session(b"chacha-data", session_uuid)
        pt = decrypt_for_session(ct, session_uuid)
        assert pt == b"chacha-data"

    def test_chacha20_db_roundtrip(self, monkeypatch):
        """ChaCha20-Poly1305 backend encrypts/decrypts for DB."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        monkeypatch.setattr(crypto_mod, "CIPHER_CLS", ChaCha20Poly1305)
        key = b"\xaa" * 32
        ct = encrypt_for_db(b"chacha-db", key_id=1, master_key=key)
        pt = decrypt_for_db(ct, {1: key})
        assert pt == b"chacha-db"

    def test_aesgcm_and_chacha20_incompatible(self, session_uuid, monkeypatch):
        """Ciphertext from one backend cannot be decrypted by the other."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        # Encrypt with AES-GCM
        monkeypatch.setattr(crypto_mod, "CIPHER_CLS", AESGCM)
        ct = encrypt_for_session(b"data", session_uuid)

        # Try to decrypt with ChaCha20 — should fail
        monkeypatch.setattr(crypto_mod, "CIPHER_CLS", ChaCha20Poly1305)
        with pytest.raises(Exception):
            decrypt_for_session(ct, session_uuid)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_session_ciphertext_too_short(self, session_uuid):
        """decrypt_for_session rejects truncated input with ValueError."""
        with pytest.raises(ValueError, match="too short"):
            decrypt_for_session(b"short", session_uuid)

    def test_db_ciphertext_too_short(self):
        """decrypt_for_db rejects truncated input with ValueError."""
        with pytest.raises(ValueError, match="too short"):
            decrypt_for_db(b"short", {1: b"\x00" * 32})


# ---------------------------------------------------------------------------
# Serialization edge cases
# ---------------------------------------------------------------------------

class TestSerializationEdgeCases:
    def test_dict_with_old_bytes_key_not_confused(self):
        """A dict with the old '__bytes__' key is treated as a normal dict."""
        value = {"__bytes__": "dGVzdA=="}
        data = serialize_value(value)
        result = deserialize_value(data)
        assert result == value
        assert isinstance(result, dict)

    def test_dict_with_vault_wrapper_key_treated_as_bytes(self):
        """A dict containing __vault_bytes_b64__ is the internal bytes sentinel."""
        import base64
        raw = b"\xff\xfe"
        data = serialize_value(raw)
        result = deserialize_value(data)
        assert result == raw
        assert isinstance(result, bytes)
