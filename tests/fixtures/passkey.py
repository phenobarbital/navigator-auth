"""Software WebAuthn authenticator for FEAT-101 passkey tests (no browser)."""
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40

RP_CONFIG = [
    {"origin": "https://a.test", "rp_id": "a.test", "rp_name": "A", "org_id": 5, "client_id": 1},
    {"origin": "https://b.test", "rp_id": "b.test", "rp_name": "B", "org_id": 7, "client_id": 2},
]


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class SoftAuthenticator:
    """ES256 software authenticator producing py_webauthn-compatible JSON."""

    private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))

    def cose_public_key(self) -> bytes:
        """COSE_Key (kty=2, alg=-7, crv=1, x, y) CBOR-encoded."""
        import cbor2  # py_webauthn dependency; lazy so the module imports without it

        nums = self.private_key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2, 3: -7, -1: 1,
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        })

    def _auth_data(self, rp_id: str, sign_count: int, uv: bool, attested: bool) -> bytes:
        flags = FLAG_UP | (FLAG_UV if uv else 0) | (FLAG_AT if attested else 0)
        data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", sign_count)
        )
        if attested:
            data += (
                bytes(16)
                + struct.pack(">H", len(self.credential_id))
                + self.credential_id
                + self.cose_public_key()
            )
        return data

    @staticmethod
    def _client_data(kind: str, origin: str, challenge: bytes) -> bytes:
        return json.dumps({
            "type": kind,
            "challenge": _b64(challenge),
            "origin": origin,
            "crossOrigin": False,
        }).encode()

    def make_attestation(
        self, rp_id: str, origin: str, challenge: bytes, user_handle: bytes, uv: bool = True
    ) -> dict:
        """RegistrationCredential JSON for register/verify (fmt "none")."""
        import cbor2

        auth_data = self._auth_data(rp_id, 0, uv, attested=True)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(self._client_data("webauthn.create", origin, challenge)),
                "attestationObject": _b64(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def make_assertion(
        self,
        rp_id: str,
        origin: str,
        challenge: bytes,
        sign_count: int = 0,
        uv: bool = True,
        user_handle: Optional[bytes] = None,
    ) -> dict:
        """AuthenticationCredential JSON for POST /api/v1/login (X-Auth-Method: PasskeyAuth)."""
        auth_data = self._auth_data(rp_id, sign_count, uv, attested=False)
        client_data = self._client_data("webauthn.get", origin, challenge)
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        response = {
            "clientDataJSON": _b64(client_data),
            "authenticatorData": _b64(auth_data),
            "signature": _b64(signature),
        }
        if user_handle is not None:
            response["userHandle"] = _b64(user_handle)
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": response,
            "clientExtensionResults": {},
        }


@pytest.fixture
def soft_authenticator() -> SoftAuthenticator:
    """A fresh ES256 software authenticator per test."""
    return SoftAuthenticator()


@pytest.fixture
def passkey_rp_config(monkeypatch) -> list[dict]:
    """Two RPs: https://a.test (org 5) and https://b.test (org 7)."""
    import navigator_auth.conf as conf

    monkeypatch.setattr(conf, "PASSKEY_RELYING_PARTIES", RP_CONFIG, raising=False)
    # PasskeyAuth (TASK-93) reads every PASSKEY_* setting as `auth_conf.<NAME>` at call time
    # (`from .. import conf as auth_conf`), so patching navigator_auth.conf is enough.
    return RP_CONFIG
