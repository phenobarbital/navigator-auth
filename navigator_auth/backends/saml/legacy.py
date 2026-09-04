"""Legacy `python3-saml` `SAML_SETTINGS` → `pysaml2` config translation
(FEAT-097 §6 "Breaking settings change", OQ6: hard fail on unknown keys).

Only the keys documented in `documentation/saml.md` are translated; any
other key (at any nesting level) fails startup, listing every offending
key, per OQ6's default. `security.nameIdEncrypted` is recognized but
explicitly unsupported (§1 Non-Goals: "Encrypted NameID issuance from the
IdP role") and always rejected when truthy.
"""
import tempfile
from typing import Any

from ...exceptions import ConfigError

#: dotted-path -> pysaml2 setter; each setter receives (cnf, value).
_KNOWN_KEYS = {
    "strict",  # acknowledged, no direct pysaml2 equivalent; a no-op here.
    "sp.entityId",
    "sp.assertionConsumerService.url",
    "sp.singleLogoutService.url",
    "sp.x509cert",
    "sp.privateKey",
    "idp.entityId",
    "idp.singleSignOnService.url",
    "idp.singleLogoutService.url",
    "idp.x509cert",
    "security.wantAssertionsSigned",
    "security.wantMessagesSigned",
    "security.authnRequestsSigned",
    "security.nameIdEncrypted",  # recognized, but always rejected below.
}


def _flatten(settings: dict, prefix: str = "") -> dict:
    """`{"sp": {"entityId": "x"}}` -> `{"sp.entityId": "x"}`."""
    flat = {}
    for key, value in settings.items():
        path = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def _pem_to_der_b64(cert_pem: str) -> str:
    """Strip PEM armor/whitespace, leaving the bare base64 body
    `<X509Certificate>` wants. Best-effort: legacy `x509cert` values are
    sometimes stored already-bare (no `-----BEGIN...`); either form works
    since this function is purely string manipulation (no cryptography
    import, no validation — this translator has no pysaml2/openssl
    dependency, by design: it must run standalone, offline, and even on
    the placeholder/malformed cert content unit tests exercise it with)."""
    lines = [ln.strip() for ln in cert_pem.strip().splitlines()]
    body = [ln for ln in lines if ln and not ln.startswith("-----")]
    return "".join(body) if body else cert_pem.strip()


def _build_idp_metadata_xml(entity_id: str, sso_url: str, slo_url: str, cert_pem: str) -> str:
    """A minimal, unsigned `IDPSSODescriptor` metadata document describing
    the *external* legacy IdP, built by plain string templating — no
    `pysaml2`/`xmlsec1` dependency, so this stays a pure, offline
    translation with no external validation of the (user-supplied,
    already-trusted-by-the-operator) certificate content."""
    key_descriptor = ""
    if cert_pem:
        key_descriptor = (
            '<md:KeyDescriptor use="signing"><ds:KeyInfo '
            'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>'
            f"<ds:X509Certificate>{_pem_to_der_b64(cert_pem)}</ds:X509Certificate>"
            "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        )
    slo_element = (
        f'<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{slo_url}"/>'
        if slo_url
        else ""
    )
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}">'
        '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f"{key_descriptor}{slo_element}"
        f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{sso_url}"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )


def _write_pem(content: str, suffix: str) -> str:
    """Legacy settings carry raw PEM *content*; `pysaml2`'s config wants
    file paths, so spill it to a temp file (mirrors the migration's own
    key/cert file model everywhere else in FEAT-097)."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as fh:
        fh.write(content)
        return fh.name


def translate_legacy_settings(settings: dict) -> dict:
    """Translate a `python3-saml`-shaped `SAML_SETTINGS` dict into a
    `pysaml2` config dict (suitable as `SAMLCore(settings=...)`).

    Raises `ConfigError` naming every key that isn't in the known
    translation table (OQ6 default: hard fail), or when
    `security.nameIdEncrypted` is set to a truthy value (unsupported).
    """
    flat = _flatten(settings or {})
    unknown = sorted(k for k in flat if k not in _KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            "SAML: unknown key(s) in legacy SAML_SETTINGS "
            f"(not translatable to pysaml2): {', '.join(unknown)}"
        )

    if flat.get("security.nameIdEncrypted"):
        raise ConfigError(
            "SAML: security.nameIdEncrypted is not supported "
            "(encrypted NameID issuance from the IdP role is out of scope)."
        )

    cnf: dict = {}

    sp_entity_id = flat.get("sp.entityId")
    if sp_entity_id:
        cnf["entityid"] = sp_entity_id

    sp_key = flat.get("sp.privateKey")
    sp_cert = flat.get("sp.x509cert")
    if sp_key:
        cnf["key_file"] = _write_pem(sp_key, suffix=".key")
    if sp_cert:
        cnf["cert_file"] = _write_pem(sp_cert, suffix=".crt")

    sp_service: dict[str, Any] = {}
    acs_url = flat.get("sp.assertionConsumerService.url")
    slo_url_sp = flat.get("sp.singleLogoutService.url")
    if acs_url or slo_url_sp:
        from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

        endpoints = {}
        if acs_url:
            endpoints["assertion_consumer_service"] = [(acs_url, BINDING_HTTP_POST)]
        if slo_url_sp:
            endpoints["single_logout_service"] = [(slo_url_sp, BINDING_HTTP_REDIRECT)]
        sp_service["endpoints"] = endpoints

    if "security.wantAssertionsSigned" in flat:
        sp_service["want_assertions_signed"] = bool(flat["security.wantAssertionsSigned"])
    if "security.wantMessagesSigned" in flat:
        sp_service["want_response_signed"] = bool(flat["security.wantMessagesSigned"])
    if "security.authnRequestsSigned" in flat:
        sp_service["authn_requests_signed"] = bool(flat["security.authnRequestsSigned"])

    if sp_service:
        cnf.setdefault("service", {})["sp"] = sp_service

    idp_entity_id = flat.get("idp.entityId")
    idp_sso_url = flat.get("idp.singleSignOnService.url")
    idp_slo_url = flat.get("idp.singleLogoutService.url")
    idp_cert = flat.get("idp.x509cert")
    if idp_entity_id and idp_sso_url:
        xml = _build_idp_metadata_xml(idp_entity_id, idp_sso_url, idp_slo_url, idp_cert)
        cnf["metadata"] = {"inline": [xml]}

    return cnf
