"""Plain dataclasses shared by both SAML roles (no DB).

FEAT-097 §2 "Data Models". Kept free of any `pysaml2` import so the SP and
IdP bases, and any consumer of the public config surface, can import them
cheaply.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class SAMLKeyPair:
    """A PEM key/cert pair used for signing or decryption."""

    key_file: str  # PEM private key path
    cert_file: str  # PEM certificate path
    passphrase: Optional[str] = None


@dataclass(frozen=True)
class ServiceProviderConfig:
    """One relying SP registered on the IdP role (env-declared)."""

    sp_id: str  # slug used in /initiate/<sp_id>
    entity_id: str
    acs_url: str
    acs_binding: str = "HTTP-POST"  # only POST supported for ACS
    slo_url: Optional[str] = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    attribute_map: dict = field(default_factory=dict)  # saml attr -> user field
    sign_assertion: bool = True
    sign_response: bool = False
    want_signed_authn_request: bool = False
    sp_cert_file: Optional[str] = None  # for AuthnRequest signature check / encryption
    assertion_ttl: int = 300
    allowed_relay_hosts: tuple = ()  # extra RelayState hosts besides acs_url host

    @classmethod
    def from_dict(cls, data: dict) -> "ServiceProviderConfig":
        """Build (and validate) one entry of `SAML_IDP_SERVICE_PROVIDERS`."""
        missing = [k for k in ("sp_id", "entity_id", "acs_url") if not data.get(k)]
        if missing:
            raise ValueError(
                f"ServiceProviderConfig is missing required field(s): {missing!r} in {data!r}"
            )
        acs_binding = data.get("acs_binding", "HTTP-POST")
        if acs_binding != "HTTP-POST":
            raise ValueError(
                f"ServiceProviderConfig.acs_binding must be 'HTTP-POST' (got {acs_binding!r})"
            )
        allowed = data.get("allowed_relay_hosts", ())
        kwargs = {
            "sp_id": data["sp_id"],
            "entity_id": data["entity_id"],
            "acs_url": data["acs_url"],
            "acs_binding": acs_binding,
            "slo_url": data.get("slo_url"),
            "attribute_map": data.get("attribute_map", {}),
            "sp_cert_file": data.get("sp_cert_file"),
            "allowed_relay_hosts": tuple(allowed),
        }
        for key in (
            "name_id_format",
            "sign_assertion",
            "sign_response",
            "want_signed_authn_request",
            "assertion_ttl",
        ):
            if key in data:
                kwargs[key] = data[key]
        return cls(**kwargs)


@dataclass(frozen=True)
class AssertionResult:
    """Normalized outcome of a validated inbound SAMLResponse (SP role)."""

    name_id: str
    name_id_format: str
    session_index: Optional[str]
    issuer: str
    assertion_id: str
    not_on_or_after: datetime
    attributes: dict  # flattened per mapping
    raw_attributes: dict  # as delivered
    in_response_to: Optional[str]
    unsolicited: bool


@dataclass(frozen=True)
class SAMLSessionInfo:
    """Persisted in the user session under key 'saml' for SLO."""

    name_id: str
    name_id_format: str
    session_index: Optional[str]
    idp_entity_id: str
    backend: str  # _service_name

    def to_dict(self) -> dict:
        return {
            "name_id": self.name_id,
            "name_id_format": self.name_id_format,
            "session_index": self.session_index,
            "idp_entity_id": self.idp_entity_id,
            "backend": self.backend,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SAMLSessionInfo":
        return cls(
            name_id=data["name_id"],
            name_id_format=data.get("name_id_format", ""),
            session_index=data.get("session_index"),
            idp_entity_id=data.get("idp_entity_id", ""),
            backend=data.get("backend", "saml"),
        )
