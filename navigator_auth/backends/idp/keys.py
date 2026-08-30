"""Signing-key registry for asymmetric JWT signing — FEAT-095 TASK-043 (D4).

Adds an optional RS256/ES256 signing path so third-party and polyglot resource
servers can validate navigator-auth tokens **offline** from a JWK Set, instead
of calling ``/oauth2/introspect`` for every request.

Design rules (spec §3 Module 6, §6):
  - HS256 stays the default.  When ``OAUTH_JWT_KEYS`` is empty the registry is
    empty, ``signing_key()`` returns None, and the token path is byte-identical
    to pre-feature behaviour.
  - **Exactly one** key is the active signer.  Inactive keys remain in the
    registry as verification-only material, which is what makes rotation
    non-disruptive: publish the new key, flip ``active``, and tokens signed by
    the old key keep verifying until they expire.
  - Private material never leaves this module: it is held in ``SecretStr`` and
    the JWK Set serialises public parameters only.

Keys are declared as PEM file paths (``private_key_file`` / ``public_key_file``)
or inline PEM (``private_key`` / ``public_key``).
"""

from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Optional
import logging

from pydantic import BaseModel, Field, SecretStr

__all__ = (
    "ASYMMETRIC_ALGORITHMS",
    "SigningKey",
    "SigningKeyRegistry",
    "build_jwk_set",
    "load_registry",
)

logger = logging.getLogger("navigator.auth.keys")

#: Algorithms that use a key pair.  Anything else is treated as symmetric.
ASYMMETRIC_ALGORITHMS: frozenset = frozenset({"RS256", "RS384", "RS512",
                                              "ES256", "ES384", "ES512"})


class SigningKey(BaseModel):
    """One entry in the signing-key registry (spec §2 Data Models)."""

    kid: str = Field()
    algorithm: str = Field(default="RS256")
    #: Signing material — present on the active key only.  Never serialised.
    private_key: Optional[SecretStr] = Field(default=None)
    #: Verification material — present on every key.
    public_key: Optional[str] = Field(default=None)
    #: Exactly one key in a registry is the active signer.
    active: bool = Field(default=False)

    @property
    def is_asymmetric(self) -> bool:
        return self.algorithm in ASYMMETRIC_ALGORITHMS

    def private_pem(self) -> Optional[str]:
        """The PEM signing key, unwrapped at the point of use."""
        return self.private_key.get_secret_value() if self.private_key else None

    def public_jwk(self) -> Optional[dict]:
        """This key as a public JWK, or None when it cannot be represented.

        Only public parameters are emitted — there is no code path here that
        can serialise private material.
        """
        if not self.public_key:
            return None
        try:
            return _public_pem_to_jwk(self.public_key, self.kid, self.algorithm)
        except Exception as err:  # pylint: disable=W0703
            logger.error(f"Cannot serialise key '{self.kid}' as a JWK: {err}")
            return None


def _b64u(value: bytes) -> str:
    """base64url without padding (RFC 7515 §2)."""
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _int_to_b64u(value: int) -> str:
    """Encode a positive integer as a base64url big-endian octet string."""
    length = (value.bit_length() + 7) // 8 or 1
    return _b64u(value.to_bytes(length, "big"))


def _public_pem_to_jwk(pem: str, kid: str, algorithm: str) -> dict:
    """Convert a public PEM into its JWK representation.

    Supports RSA (``kty: RSA``) and NIST EC curves (``kty: EC``), which covers
    the RS*/ES* algorithms this registry accepts.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem.encode("utf-8"))

    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "alg": algorithm,
            "n": _int_to_b64u(numbers.n),
            "e": _int_to_b64u(numbers.e),
        }

    if isinstance(key, ec.EllipticCurvePublicKey):
        curve_names = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }
        curve = curve_names.get(key.curve.name)
        if curve is None:
            raise ValueError(f"Unsupported EC curve: {key.curve.name}")
        numbers = key.public_numbers()
        size = (key.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "use": "sig",
            "kid": kid,
            "alg": algorithm,
            "crv": curve,
            "x": _b64u(numbers.x.to_bytes(size, "big")),
            "y": _b64u(numbers.y.to_bytes(size, "big")),
        }

    raise ValueError(f"Unsupported public key type: {type(key).__name__}")


def _read_material(entry: dict, inline_field: str, file_field: str) -> Optional[str]:
    """Read key material from an inline value or a PEM file path."""
    inline = entry.get(inline_field)
    if inline:
        return str(inline)
    path = entry.get(file_field)
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as err:
        # Never include the path contents in the log line.
        logger.error(f"Cannot read key file for '{entry.get('kid')}': {err}")
        return None


class SigningKeyRegistry:
    """The loaded set of signing/verification keys.

    Empty by default — an empty registry means "HS256 as before", and callers
    must treat it as the signal to take the untouched symmetric path.
    """

    def __init__(self, keys: Optional[list] = None):
        self._keys: dict = {}
        self._active: Optional[SigningKey] = None
        for key in keys or []:
            self.add(key)

    def add(self, key: SigningKey) -> None:
        self._keys[key.kid] = key
        if key.active:
            if self._active is not None and self._active.kid != key.kid:
                logger.warning(
                    f"More than one active signing key; '{key.kid}' supersedes "
                    f"'{self._active.kid}'. Exactly one key should be active."
                )
            self._active = key

    def __len__(self) -> int:
        return len(self._keys)

    def __bool__(self) -> bool:
        return bool(self._keys)

    @property
    def keys(self) -> list:
        return list(self._keys.values())

    def get(self, kid: str) -> Optional[SigningKey]:
        """Verification key by ``kid``; None when unknown."""
        return self._keys.get(kid)

    def signing_key(self) -> Optional[SigningKey]:
        """The active signer, or None when no asymmetric signing is configured.

        A key without private material cannot sign — returning None keeps the
        caller on the HS256 path rather than failing token issuance.
        """
        key = self._active
        if key is None or not key.private_pem():
            return None
        return key

    def jwk_set(self) -> dict:
        """The public JWK Set (RFC 7517) for ``GET /oauth2/jwks``."""
        return build_jwk_set(self.keys)


def build_jwk_set(keys: list) -> dict:
    """Serialise keys as a public JWK Set — public parameters only."""
    jwks = []
    for key in keys or []:
        jwk = key.public_jwk()
        if jwk:
            jwks.append(jwk)
    return {"keys": jwks}


def load_registry(entries: Optional[list] = None) -> SigningKeyRegistry:
    """Build a registry from ``OAUTH_JWT_KEYS``-shaped dicts.

    Malformed entries are skipped with a warning rather than raising: a bad
    key definition must not stop the service from starting, it must only stop
    that key from being used.
    """
    registry = SigningKeyRegistry()
    for entry in entries or []:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-object entry in OAUTH_JWT_KEYS.")
            continue
        kid = entry.get("kid")
        if not kid:
            logger.warning("Skipping OAUTH_JWT_KEYS entry with no 'kid'.")
            continue
        private_pem = _read_material(entry, "private_key", "private_key_file")
        public_pem = _read_material(entry, "public_key", "public_key_file")
        if not private_pem and not public_pem:
            logger.warning(f"Skipping key '{kid}': no usable key material.")
            continue
        registry.add(
            SigningKey(
                kid=kid,
                algorithm=entry.get("algorithm", "RS256"),
                private_key=SecretStr(private_pem) if private_pem else None,
                public_key=public_pem,
                active=bool(entry.get("active", False)),
            )
        )
    return registry
