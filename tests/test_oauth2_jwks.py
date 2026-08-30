"""Tests for FEAT-095 TASK-043 — asymmetric signing (RS256/ES256) + JWKS.

Covers spec §4:
  test_jwks_document, test_rs256_sign_verify_kid, test_rotation_old_key_verifies,
  test_hs256_default_unchanged, test_no_private_material_in_jwks,
  test_asymmetric_e2e
"""

from unittest.mock import MagicMock

import jwt
import pytest

from navigator_auth.backends.idp.keys import (
    ASYMMETRIC_ALGORITHMS,
    SigningKey,
    SigningKeyRegistry,
    build_jwk_set,
    load_registry,
)


def _rsa_pem_pair():
    """Generate a throwaway RSA keypair as (private_pem, public_pem)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def _ec_pem_pair():
    """Generate a throwaway P-256 keypair as (private_pem, public_pem)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def rsa_pair():
    return _rsa_pem_pair()


@pytest.fixture
def rsa_keypair(rsa_pair, tmp_path):
    """A registry holding one active RS256 key, kid='test-1'."""
    private_pem, public_pem = rsa_pair
    private_file = tmp_path / "test-1.key"
    public_file = tmp_path / "test-1.pub"
    private_file.write_text(private_pem)
    public_file.write_text(public_pem)
    registry = load_registry(
        [
            {
                "kid": "test-1",
                "algorithm": "RS256",
                "private_key_file": str(private_file),
                "public_key_file": str(public_file),
                "active": True,
            }
        ]
    )
    return registry, private_pem, public_pem


# ---------------------------------------------------------------------------
# Registry loading
# ---------------------------------------------------------------------------

class TestRegistryLoading:
    def test_empty_config_yields_empty_registry(self):
        registry = load_registry([])
        assert len(registry) == 0
        assert not registry
        assert registry.signing_key() is None

    def test_loads_from_pem_files(self, rsa_keypair):
        registry, _, public_pem = rsa_keypair
        assert len(registry) == 1
        key = registry.get("test-1")
        assert key.algorithm == "RS256"
        assert key.public_key.strip() == public_pem.strip()
        assert key.active is True

    def test_loads_from_inline_pem(self, rsa_pair):
        private_pem, public_pem = rsa_pair
        registry = load_registry(
            [
                {
                    "kid": "inline-1",
                    "algorithm": "RS256",
                    "private_key": private_pem,
                    "public_key": public_pem,
                    "active": True,
                }
            ]
        )
        assert registry.signing_key().kid == "inline-1"

    def test_active_key_is_the_signer(self, rsa_pair):
        private_pem, public_pem = rsa_pair
        registry = load_registry(
            [
                {"kid": "old", "public_key": public_pem, "active": False},
                {
                    "kid": "new",
                    "private_key": private_pem,
                    "public_key": public_pem,
                    "active": True,
                },
            ]
        )
        assert registry.signing_key().kid == "new"
        # The retired key stays available for verification.
        assert registry.get("old") is not None

    def test_key_without_private_material_cannot_sign(self, rsa_pair):
        _, public_pem = rsa_pair
        registry = load_registry(
            [{"kid": "verify-only", "public_key": public_pem, "active": True}]
        )
        assert registry.signing_key() is None

    @pytest.mark.parametrize(
        "entry",
        [
            {"algorithm": "RS256"},          # no kid
            {"kid": "no-material"},          # no key material
            "not-a-dict",
        ],
    )
    def test_malformed_entries_are_skipped(self, entry):
        """A bad key definition must not stop the service from starting."""
        assert len(load_registry([entry])) == 0

    def test_unreadable_key_file_is_skipped(self, tmp_path):
        registry = load_registry(
            [
                {
                    "kid": "missing",
                    "private_key_file": str(tmp_path / "nope.pem"),
                }
            ]
        )
        assert len(registry) == 0


# ---------------------------------------------------------------------------
# JWK Set
# ---------------------------------------------------------------------------

class TestJWKSDocument:
    def test_jwks_document(self, rsa_keypair):
        registry, _, _ = rsa_keypair
        document = registry.jwk_set()

        assert "keys" in document
        assert len(document["keys"]) == 1
        jwk = document["keys"][0]
        assert jwk["kid"] == "test-1"
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert jwk["n"] and jwk["e"]

    def test_no_private_material_in_jwks(self, rsa_keypair):
        """Private parameters must never be serialised."""
        registry, private_pem, _ = rsa_keypair
        document = registry.jwk_set()
        serialized = str(document)

        # RSA private JWK parameters.
        for private_param in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_param not in document["keys"][0]
        assert "PRIVATE KEY" not in serialized
        assert private_pem not in serialized

    def test_ec_key_serialises_as_jwk(self):
        private_pem, public_pem = _ec_pem_pair()
        registry = load_registry(
            [
                {
                    "kid": "ec-1",
                    "algorithm": "ES256",
                    "private_key": private_pem,
                    "public_key": public_pem,
                    "active": True,
                }
            ]
        )
        jwk = registry.jwk_set()["keys"][0]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["x"] and jwk["y"]
        assert "d" not in jwk

    def test_empty_registry_yields_empty_set(self):
        assert build_jwk_set([]) == {"keys": []}

    def test_key_without_public_material_is_omitted(self, rsa_pair):
        private_pem, _ = rsa_pair
        key = SigningKey(kid="k", algorithm="RS256", private_key=private_pem)
        assert build_jwk_set([key]) == {"keys": []}

    def test_secret_str_does_not_leak_in_repr(self, rsa_keypair):
        registry, private_pem, _ = rsa_keypair
        key = registry.get("test-1")
        assert private_pem not in repr(key)
        assert private_pem not in str(key)


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_rs256_sign_verify_kid(self, rsa_keypair):
        """A token signed by the active key carries its kid."""
        registry, _, public_pem = rsa_keypair
        key = registry.signing_key()

        token = jwt.encode(
            {"sub": "user-1"},
            key.private_pem(),
            algorithm=key.algorithm,
            headers={"kid": key.kid},
        )

        assert jwt.get_unverified_header(token)["kid"] == "test-1"
        decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
        assert decoded["sub"] == "user-1"

    def test_rotation_old_key_verifies(self, rsa_pair):
        """After rotation the retired key still verifies its own tokens."""
        old_private, old_public = rsa_pair
        new_private, new_public = _rsa_pem_pair()

        # Before rotation: 'old' signs.
        token_from_old = jwt.encode(
            {"sub": "before"}, old_private, algorithm="RS256",
            headers={"kid": "old"},
        )

        # Rotate: 'new' becomes active, 'old' stays verify-only.
        registry = load_registry(
            [
                {"kid": "old", "public_key": old_public, "active": False},
                {
                    "kid": "new",
                    "private_key": new_private,
                    "public_key": new_public,
                    "active": True,
                },
            ]
        )

        # Only the new key signs.
        assert registry.signing_key().kid == "new"
        # The old token still verifies against the retired key.
        old_key = registry.get("old")
        assert jwt.decode(
            token_from_old, old_key.public_key, algorithms=["RS256"]
        )["sub"] == "before"
        # Both keys are published for verification.
        assert {k["kid"] for k in registry.jwk_set()["keys"]} == {"old", "new"}


# ---------------------------------------------------------------------------
# IdentityProvider integration
# ---------------------------------------------------------------------------

@pytest.fixture
def idp():
    from navigator_auth.backends.idp import IdentityProvider

    provider = IdentityProvider()
    # Reset the class-level registry cache between tests.
    IdentityProvider._key_registry = None
    yield provider
    IdentityProvider._key_registry = None


#: The HS256 path signs with the deployment's SECRET_KEY.  A short key in a
#: local .env makes PyJWT emit InsecureKeyLengthWarning, which this project's
#: ``filterwarnings = error`` turns into a failure.  That is a property of the
#: environment's secret, not of the code under test.
@pytest.mark.filterwarnings(
    "ignore::jwt.warnings.InsecureKeyLengthWarning"
)
class TestIdentityProviderSigning:
    def test_hs256_default_unchanged(self, idp):
        """Unconfigured ⇒ no kid header, HS256, verifiable with SECRET_KEY."""
        from navigator_auth.conf import SECRET_KEY, AUTH_JWT_ALGORITHM

        assert idp.signing_key() is None

        token, _, _, _ = idp.create_token(data={"user_id": 1})

        header = jwt.get_unverified_header(token)
        assert "kid" not in header
        assert header["alg"] == AUTH_JWT_ALGORITHM == "HS256"
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[AUTH_JWT_ALGORITHM],
            options={"verify_aud": False},
        )
        assert payload["user_id"] == 1

    def test_hs256_roundtrip_through_decode_token(self, idp):
        token, _, _, _ = idp.create_token(data={"user_id": 7})
        _, payload = idp.decode_token(token)
        assert payload["user_id"] == 7

    def test_signing_key_ignored_unless_alg_is_asymmetric(
        self, idp, rsa_keypair, monkeypatch
    ):
        """Keys loaded but OAUTH_JWT_SIGNING_ALG=HS256 ⇒ still symmetric."""
        registry, _, _ = rsa_keypair
        type(idp)._key_registry = registry
        monkeypatch.setattr(
            "navigator_auth.backends.idp.OAUTH_JWT_SIGNING_ALG", "HS256"
        )
        assert idp.signing_key() is None

        token, _, _, _ = idp.create_token(data={"user_id": 1})
        assert "kid" not in jwt.get_unverified_header(token)

    def test_asymmetric_signing_sets_kid(self, idp, rsa_keypair, monkeypatch):
        registry, _, _ = rsa_keypair
        type(idp)._key_registry = registry
        monkeypatch.setattr(
            "navigator_auth.backends.idp.OAUTH_JWT_SIGNING_ALG", "RS256"
        )

        token, _, _, _ = idp.create_token(data={"user_id": 5})

        header = jwt.get_unverified_header(token)
        assert header["kid"] == "test-1"
        assert header["alg"] == "RS256"

    def test_asymmetric_e2e(self, idp, rsa_keypair, monkeypatch):
        """A third party validates using only the JWK Set — no introspection."""
        registry, _, _ = rsa_keypair
        type(idp)._key_registry = registry
        monkeypatch.setattr(
            "navigator_auth.backends.idp.OAUTH_JWT_SIGNING_ALG", "RS256"
        )

        token, _, _, _ = idp.create_token(data={"user_id": 99})

        # --- the third party's side: JWK Set only, no shared secret ---
        jwk_set = registry.jwk_set()
        kid = jwt.get_unverified_header(token)["kid"]
        jwk = next(k for k in jwk_set["keys"] if k["kid"] == kid)
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

        payload = jwt.decode(
            token, public_key, algorithms=["RS256"],
            options={"verify_aud": False},
        )
        assert payload["user_id"] == 99

    def test_decode_dispatches_on_kid(self, idp, rsa_keypair, monkeypatch):
        registry, _, _ = rsa_keypair
        type(idp)._key_registry = registry
        monkeypatch.setattr(
            "navigator_auth.backends.idp.OAUTH_JWT_SIGNING_ALG", "RS256"
        )

        token, _, _, _ = idp.create_token(data={"user_id": 11})
        _, payload = idp.decode_token(token)
        assert payload["user_id"] == 11

    def test_mixed_token_migration_window(self, idp, rsa_keypair, monkeypatch):
        """HS256 tokens minted before rotation still decode afterwards."""
        # Mint while symmetric.
        legacy_token, _, _, _ = idp.create_token(data={"user_id": 3})

        # Now switch the deployment to RS256.
        registry, _, _ = rsa_keypair
        type(idp)._key_registry = registry
        monkeypatch.setattr(
            "navigator_auth.backends.idp.OAUTH_JWT_SIGNING_ALG", "RS256"
        )
        new_token, _, _, _ = idp.create_token(data={"user_id": 4})

        # Both verify.
        assert idp.decode_token(legacy_token)[1]["user_id"] == 3
        assert idp.decode_token(new_token)[1]["user_id"] == 4

    def test_unknown_kid_falls_back_to_secret_key(self, idp, rsa_keypair):
        """An unknown kid must not crash the decode path."""
        from navigator_auth.conf import SECRET_KEY, AUTH_JWT_ALGORITHM

        registry, _, _ = rsa_keypair
        type(idp)._key_registry = registry

        token = jwt.encode(
            {"user_id": 8}, SECRET_KEY, algorithm=AUTH_JWT_ALGORITHM,
            headers={"kid": "not-in-registry"},
        )
        _, payload = idp.decode_token(token)
        assert payload["user_id"] == 8

    def test_create_token_still_returns_a_4_tuple(self, idp):
        """The signature is contractual — callers depend on it."""
        result = idp.create_token(data={"user_id": 1})
        assert isinstance(result, tuple)
        assert len(result) == 4


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

class TestJWKSEndpoint:
    def test_jwks_route_registered_and_public(self):
        from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
        from navigator_auth.backends.oauth2.backend import Oauth2Provider
        from navigator_auth.backends.abstract import BaseAuthBackend

        provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
        routes = []
        exclude = []
        router = MagicMock()
        router.add_route.side_effect = lambda m, p, h, name=None: routes.append(
            (m, p)
        )
        app = MagicMock()
        app.router = router
        app.__getitem__.side_effect = lambda k: exclude
        app.__setitem__.side_effect = lambda k, v: None

        original = BaseAuthBackend.configure
        BaseAuthBackend.configure = lambda self, _app: None
        try:
            provider.configure(app)
        finally:
            BaseAuthBackend.configure = original

        assert ("GET", "/oauth2/jwks") in routes
        assert "/oauth2/jwks" in exclude

    @pytest.mark.asyncio
    async def test_jwks_endpoint_serves_public_set(self, rsa_keypair):
        from navigator_auth.backends.oauth2.backend import Oauth2Provider
        import json

        registry, private_pem, _ = rsa_keypair
        provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
        provider._idp = MagicMock()
        provider._idp.key_registry = registry

        response = await provider.jwks(MagicMock())
        body = json.loads(response.body)

        assert response.status == 200
        assert body["keys"][0]["kid"] == "test-1"
        assert "PRIVATE KEY" not in response.body.decode()
        assert private_pem not in response.body.decode()

    @pytest.mark.asyncio
    async def test_jwks_endpoint_empty_when_unconfigured(self):
        from navigator_auth.backends.oauth2.backend import Oauth2Provider
        import json

        provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
        provider._idp = MagicMock()
        provider._idp.key_registry = SigningKeyRegistry()

        response = await provider.jwks(MagicMock())
        assert json.loads(response.body) == {"keys": []}

    def test_asymmetric_algorithms_cover_rs_and_es(self):
        assert "RS256" in ASYMMETRIC_ALGORITHMS
        assert "ES256" in ASYMMETRIC_ALGORITHMS
        assert "HS256" not in ASYMMETRIC_ALGORITHMS
