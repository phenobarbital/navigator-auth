"""Tests for FEAT-097 Module 6: generic SAMLAuth / SAMLIdentityProvider
subclasses, legacy settings translation, package exports (TASK-060).
"""
import pytest

from navigator_auth.backends.saml.legacy import translate_legacy_settings
from navigator_auth.exceptions import ConfigError


def test_legacy_settings_translation():
    cfg = translate_legacy_settings(
        {
            "strict": True,
            "idp": {
                "entityId": "urn:idp",
                "singleSignOnService": {"url": "https://idp/sso"},
                "x509cert": "MIIB...",
            },
        }
    )
    assert cfg["metadata"]["inline"][0]  # inline IdP metadata generated
    assert "urn:idp" in cfg["metadata"]["inline"][0]
    assert "https://idp/sso" in cfg["metadata"]["inline"][0]


def test_legacy_settings_unknown_key():
    with pytest.raises(ConfigError, match="security.unknownFlag"):
        translate_legacy_settings({"security": {"unknownFlag": True}})


def test_legacy_settings_nameid_encrypted_rejected():
    with pytest.raises(ConfigError, match="nameIdEncrypted"):
        translate_legacy_settings({"security": {"nameIdEncrypted": True}})


def test_legacy_settings_nameid_encrypted_false_ok():
    # Explicitly disabled (matches our own default behavior) -> no-op.
    cfg = translate_legacy_settings({"security": {"nameIdEncrypted": False}})
    assert "metadata" not in cfg


def test_legacy_settings_sp_fields():
    cfg = translate_legacy_settings(
        {
            "sp": {
                "entityId": "https://app.example.com/auth/saml/metadata",
                "assertionConsumerService": {"url": "https://app.example.com/auth/saml/callback/"},
                "singleLogoutService": {"url": "https://app.example.com/auth/saml/logout"},
            },
            "security": {
                "wantAssertionsSigned": True,
                "wantMessagesSigned": False,
                "authnRequestsSigned": True,
            },
        }
    )
    assert cfg["entityid"] == "https://app.example.com/auth/saml/metadata"
    endpoints = cfg["service"]["sp"]["endpoints"]
    assert endpoints["assertion_consumer_service"][0][0] == "https://app.example.com/auth/saml/callback/"
    assert endpoints["single_logout_service"][0][0] == "https://app.example.com/auth/saml/logout"
    assert cfg["service"]["sp"]["want_assertions_signed"] is True
    assert cfg["service"]["sp"]["want_response_signed"] is False
    assert cfg["service"]["sp"]["authn_requests_signed"] is True


def test_legacy_settings_empty():
    assert translate_legacy_settings({}) == {}
    assert translate_legacy_settings(None) == {}


def test_generic_samlauth_config(monkeypatch, saml_keys):
    from navigator_auth.backends import SAMLAuth

    monkeypatch.setattr("navigator_auth.backends.saml.SAML_METADATA", saml_keys["idp_metadata"])
    backend = object.__new__(SAMLAuth)
    assert backend.get_idp_metadata() == saml_keys["idp_metadata"]
    assert isinstance(backend.get_attribute_mapping(), dict)


def test_generic_samlauth_no_metadata_source_raises(monkeypatch):
    from navigator_auth.backends import SAMLAuth

    monkeypatch.setattr("navigator_auth.backends.saml.SAML_METADATA", None)
    monkeypatch.setattr("navigator_auth.backends.saml.SAML_PATH", None)
    backend = object.__new__(SAMLAuth)
    with pytest.raises(ConfigError):
        backend.get_idp_metadata()


@pytest.mark.asyncio
async def test_generic_samlauth_resolve_user_identifier():
    from navigator_auth.backends import SAMLAuth
    from navigator_auth.backends.saml import AssertionResult
    from datetime import datetime, timezone

    backend = object.__new__(SAMLAuth)
    result = AssertionResult(
        name_id="fallback-id",
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        session_index=None,
        issuer="urn:idp",
        assertion_id="a1",
        not_on_or_after=datetime.now(tz=timezone.utc),
        attributes={"username": "auser", "email": "a@x.com"},
        raw_attributes={},
        in_response_to=None,
        unsolicited=False,
    )
    assert await backend.resolve_user_identifier(result) == "auser"

    result_no_username = AssertionResult(
        name_id="fallback-id",
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        session_index=None,
        issuer="urn:idp",
        assertion_id="a1",
        not_on_or_after=datetime.now(tz=timezone.utc),
        attributes={"email": "a@x.com"},
        raw_attributes={},
        in_response_to=None,
        unsolicited=False,
    )
    assert await backend.resolve_user_identifier(result_no_username) == "a@x.com"

    result_neither = AssertionResult(
        name_id="fallback-id",
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        session_index=None,
        issuer="urn:idp",
        assertion_id="a1",
        not_on_or_after=datetime.now(tz=timezone.utc),
        attributes={},
        raw_attributes={},
        in_response_to=None,
        unsolicited=False,
    )
    assert await backend.resolve_user_identifier(result_neither) == "fallback-id"


@pytest.mark.asyncio
async def test_generic_samlidp_service_providers(monkeypatch):
    from navigator_auth.backends import SAMLIdentityProvider

    monkeypatch.setattr(
        "navigator_auth.backends.saml.SAML_IDP_SERVICE_PROVIDERS",
        [
            {
                "sp_id": "acme",
                "entity_id": "urn:acme",
                "acs_url": "https://acme.test/acs",
            }
        ],
    )
    backend = object.__new__(SAMLIdentityProvider)
    registry = backend.get_service_providers()
    assert "acme" in registry
    assert registry["acme"].entity_id == "urn:acme"


@pytest.mark.asyncio
async def test_generic_samlidp_build_attributes_default_mapping(monkeypatch):
    from navigator_auth.backends import SAMLIdentityProvider
    from navigator_auth.backends.saml import ServiceProviderConfig

    monkeypatch.setattr(
        "navigator_auth.backends.saml.SAML_MAPPING",
        {"email": "mail-attr", "username": "uid-attr"},
    )
    backend = object.__new__(SAMLIdentityProvider)
    sp = ServiceProviderConfig(sp_id="acme", entity_id="urn:acme", acs_url="https://acme.test/acs")

    class _User:
        email = "a@x.com"
        username = "auser"

    attrs = await backend.build_attributes(_User(), sp)
    assert attrs == {"mail-attr": ["a@x.com"], "uid-attr": ["auser"]}


@pytest.mark.asyncio
async def test_generic_samlidp_build_attributes_restricted_by_sp(monkeypatch):
    from navigator_auth.backends import SAMLIdentityProvider
    from navigator_auth.backends.saml import ServiceProviderConfig

    monkeypatch.setattr(
        "navigator_auth.backends.saml.SAML_MAPPING",
        {"email": "mail-attr", "username": "uid-attr"},
    )
    backend = object.__new__(SAMLIdentityProvider)
    sp = ServiceProviderConfig(
        sp_id="acme",
        entity_id="urn:acme",
        acs_url="https://acme.test/acs",
        attribute_map={"mail-attr": "email"},
    )

    class _User:
        email = "a@x.com"
        username = "auser"

    attrs = await backend.build_attributes(_User(), sp)
    # Restricted to the SP's own allow-list: "uid-attr" is dropped.
    assert attrs == {"mail-attr": ["a@x.com"]}


def test_backend_exports():
    from navigator_auth.backends import (
        SAMLAuth,
        SAMLIdentityProvider,
        AbstractSAMLBackend,
        AbstractSAMLIdentityProvider,
    )

    assert issubclass(SAMLAuth, AbstractSAMLBackend)
    assert issubclass(SAMLIdentityProvider, AbstractSAMLIdentityProvider)
    assert not SAMLAuth.__abstractmethods__
    assert not SAMLIdentityProvider.__abstractmethods__


def test_no_onelogin_import_anywhere():
    import subprocess

    result = subprocess.run(
        ["grep", "-rn", "onelogin", "navigator_auth/"],
        capture_output=True,
        text=True,
        cwd=".",
    )
    assert result.stdout == ""


def test_legacy_saml_module_deleted():
    import os

    assert not os.path.exists("navigator_auth/backends/_legacy_saml.py")
