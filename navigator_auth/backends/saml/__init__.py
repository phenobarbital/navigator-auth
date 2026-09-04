"""Abstract SAML 2.0 backend package (FEAT-097).

This package replaced the single, concrete `backends/_legacy_saml.py`
(`python3-saml`) module with a layered design on `pysaml2`:

- `core.SAMLCore`: the only module that touches `pysaml2` configuration and
  blocking calls (TASK-055).
- `sp.AbstractSAMLBackend`: the SP role (TASK-056/057).
- `idp.AbstractSAMLIdentityProvider`: the IdP role (TASK-058/059).
- `SAMLAuth` / `SAMLIdentityProvider` (this module, TASK-060): generic
  reference subclasses reading the `SAML_*`/`SAML_IDP_*` settings, plus
  `legacy.translate_legacy_settings` for the `python3-saml` `SAML_SETTINGS`
  migration.
"""
import os

from ...conf import (
    SAML_IDP_SERVICE_PROVIDERS,
    SAML_MAPPING,
    SAML_METADATA,
    SAML_PATH,
    SAML_SETTINGS,
)
from ...exceptions import ConfigError
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
from .idp import AbstractSAMLIdentityProvider
from .legacy import translate_legacy_settings


class SAMLAuth(AbstractSAMLBackend):
    """Generic reference SP reading `SAML_*` settings (metadata path/URL,
    mapping)."""

    _service_name: str = "saml"
    config_prefix: str = "SAML"

    def get_idp_metadata(self):
        if SAML_METADATA:
            return SAML_METADATA
        if SAML_PATH:
            metadata_file = os.path.join(SAML_PATH, "idp-metadata.xml")
            if os.path.isfile(metadata_file):
                return metadata_file
            cert_file = os.path.join(SAML_PATH, "certs", "idp.crt")
            if os.path.isfile(cert_file) and SAML_SETTINGS:
                translated = translate_legacy_settings(SAML_SETTINGS)
                if "metadata" in translated:
                    return translated["metadata"]
        raise ConfigError(
            "SAML: no IdP metadata source configured. Set SAML_METADATA, or "
            "SAML_PATH pointing at a directory with idp-metadata.xml (or "
            "certs/idp.crt plus a legacy SAML_SETTINGS idp block)."
        )

    def get_attribute_mapping(self) -> dict:
        return SAML_MAPPING

    async def resolve_user_identifier(self, result: AssertionResult) -> str:
        return (
            result.attributes.get("username")
            or result.attributes.get("email")
            or result.name_id
        )

    def get_settings(self):
        if SAML_SETTINGS:
            return translate_legacy_settings(SAML_SETTINGS)
        return None


class SAMLIdentityProvider(AbstractSAMLIdentityProvider):
    """Generic reference IdP reading `SAML_IDP_*` settings and
    `SAML_IDP_SERVICE_PROVIDERS`."""

    _service_name: str = "saml-idp"
    config_prefix: str = "SAML_IDP"

    def get_service_providers(self) -> dict:
        return {
            entry["sp_id"]: ServiceProviderConfig.from_dict(entry)
            for entry in SAML_IDP_SERVICE_PROVIDERS
        }

    async def build_attributes(self, user, sp: ServiceProviderConfig) -> dict:
        """`SAML_MAPPING` is `user_field -> saml_attr` (consumed by the SP
        role to flatten an inbound assertion); the IdP role applies it in
        the *opposite* direction — user field to SAML attribute name — so
        this is that mapping's inverse. When `sp.attribute_map` (itself
        `saml_attr -> user_field`, spec §2 Data Models) is non-empty, the
        output is restricted to its keys (an explicit per-SP allow-list),
        using its own user-field override where given, else the default
        inverse.
        """
        inverse = {saml_attr: field for field, saml_attr in SAML_MAPPING.items()}
        if sp.attribute_map:
            effective = {
                attr: sp.attribute_map.get(attr, inverse.get(attr))
                for attr in sp.attribute_map
            }
        else:
            effective = inverse
        attrs = {}
        for saml_attr, user_field in effective.items():
            if not user_field:
                continue
            value = getattr(user, user_field, None)
            if value is not None:
                attrs[saml_attr] = [str(value)]
        return attrs


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
    "AbstractSAMLIdentityProvider",
    "SAMLAuth",
    "SAMLIdentityProvider",
    "translate_legacy_settings",
)
