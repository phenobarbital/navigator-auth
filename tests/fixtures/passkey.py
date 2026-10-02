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


# ---------------------------------------------------------------------------
# Live app fixture (Postgres + Redis) — shared by TASK-94/95/96 tests
# ---------------------------------------------------------------------------
PASSKEY_TEST_USERNAME = "test_passkey_user"
PASSKEY_TEST_PASSWORD = "TestP@ss1234"


@dataclass
class PasskeyApp:
    """Handle on the live passkey test app."""

    client: object
    backend: object
    auth: object
    db_pool: object
    user_id: int
    headers: dict
    username: str = PASSKEY_TEST_USERNAME


def _make_password(password: str) -> str:
    import base64
    import secrets

    salt = secrets.token_hex(6)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 80000, dklen=32)
    return f"pbkdf2_sha256$80000${salt}${base64.b64encode(key).decode().strip()}"


def _build_passkey_app_fixture():
    import pytest_asyncio

    @pytest_asyncio.fixture(scope="module", loop_scope="module")
    async def passkey_app():
        """Real AuthHandler (Basic + Passkey) on live Postgres/Redis with a seeded user."""
        import warnings

        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer

        import navigator_auth.conf as conf

        saved = conf.PASSKEY_RELYING_PARTIES
        conf.PASSKEY_RELYING_PARTIES = RP_CONFIG
        from navigator_auth import AuthHandler

        app = web.Application()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            auth = AuthHandler(
                secure_cookies=False,
                backends=(
                    "navigator_auth.backends.BasicAuth",
                    "navigator_auth.backends.PasskeyAuth",
                ),
            )
            auth.setup(app)
        client = TestClient(TestServer(app))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            await client.start_server()
        db_pool = app.get("authdb")
        assert db_pool is not None, "authdb pool missing"
        await db_pool.execute(
            f"DELETE FROM auth.users WHERE username = '{PASSKEY_TEST_USERNAME}'"
        )
        await db_pool.execute(
            "INSERT INTO auth.users (username, password, email, first_name, last_name, "
            "is_active, is_superuser, is_new, is_staff) VALUES "
            f"('{PASSKEY_TEST_USERNAME}', '{_make_password(PASSKEY_TEST_PASSWORD)}', "
            "'passkey@example.com', 'Pass', 'Key', true, false, false, false)"
        )
        for name in ("BasicAuth", "PasskeyAuth"):
            auth.backends[name]._callbacks = None
        resp = await client.post(
            "/api/v1/login",
            json={"username": PASSKEY_TEST_USERNAME, "password": PASSKEY_TEST_PASSWORD},
            headers={"X-Auth-Method": "BasicAuth"},
        )
        assert resp.status == 200, await resp.text()
        data = await resp.json()
        yield PasskeyApp(
            client=client,
            backend=auth.backends["PasskeyAuth"],
            auth=auth,
            db_pool=db_pool,
            user_id=data["user_id"],
            headers={"Authorization": f"Bearer {data['token']}"},
        )
        try:
            await db_pool.execute(
                f"DELETE FROM auth.users WHERE username = '{PASSKEY_TEST_USERNAME}'"
            )
        except Exception:  # pylint: disable=W0703
            pass
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            await client.close()
        conf.PASSKEY_RELYING_PARTIES = saved

    return passkey_app


passkey_app = _build_passkey_app_fixture()
