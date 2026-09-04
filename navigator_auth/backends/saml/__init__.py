"""Abstract SAML 2.0 backend package (FEAT-097).

This package replaces the single, concrete `backends/_legacy_saml.py`
(`python3-saml`) module with a layered design on `pysaml2`:

- `core.SAMLCore`: the only module that touches `pysaml2` configuration and
  blocking calls (this task, TASK-055).
- `sp.AbstractSAMLBackend`: the SP role (TASK-056/057).
- `idp.AbstractSAMLIdentityProvider`: the IdP role (TASK-058/059).
- Generic reference subclasses `SAMLAuth` / `SAMLIdentityProvider`
  (TASK-060).

Only the types, errors and core are exported here until the bases land.
"""
from .types import (
    SAMLKeyPair,
    ServiceProviderConfig,
    AssertionResult,
    SAMLSessionInfo,
)
from .errors import (
    SAMLError,
    SAMLInvalidResponse,
    SAMLInvalidSignature,
    SAMLExpired,
    SAMLReplay,
    SAMLStaleRequest,
    SAMLAudienceMismatch,
    SAMLDecryptFailed,
    SAMLNotAuthenticated,
    SAMLUserNotFound,
    SAMLForbidden,
    SAMLUnknownSP,
    SAMLSPForbidden,
    SAMLInvalidAuthnRequest,
    SAMLSLOFailed,
    map_pysaml2_error,
)
from .core import SAMLCore
from .sp import AbstractSAMLBackend

__all__ = (
    "SAMLKeyPair",
    "ServiceProviderConfig",
    "AssertionResult",
    "SAMLSessionInfo",
    "SAMLError",
    "SAMLInvalidResponse",
    "SAMLInvalidSignature",
    "SAMLExpired",
    "SAMLReplay",
    "SAMLStaleRequest",
    "SAMLAudienceMismatch",
    "SAMLDecryptFailed",
    "SAMLNotAuthenticated",
    "SAMLUserNotFound",
    "SAMLForbidden",
    "SAMLUnknownSP",
    "SAMLSPForbidden",
    "SAMLInvalidAuthnRequest",
    "SAMLSLOFailed",
    "map_pysaml2_error",
    "SAMLCore",
    "AbstractSAMLBackend",
)
