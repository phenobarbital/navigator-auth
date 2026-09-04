"""Tests for FEAT-097 Module 2: SAMLCore engine wrapper, types and error
codes (TASK-055).
"""
import threading

import pytest

from navigator_auth.backends.saml import SAMLCore, ServiceProviderConfig, AssertionResult
from navigator_auth.exceptions import ConfigError

FIXTURES_DIR = "tests/fixtures/saml"


@pytest.fixture
def saml_keys() -> dict:
    return {
        "idp_key": f"{FIXTURES_DIR}/idp.key",
        "idp_cert": f"{FIXTURES_DIR}/idp.crt",
        "sp_key": f"{FIXTURES_DIR}/sp.key",
        "sp_cert": f"{FIXTURES_DIR}/sp.crt",
    }


@pytest.fixture
def core(saml_keys):
    return SAMLCore(prefix="SAML", settings=None, role="sp", logger=None)


def test_core_build_config_sp(core):
    a = core.build_config("https://a.example.com")
    b = core.build_config("https://b.example.com")
    assert a["entityid"] != b["entityid"]
    assert "https://a.example.com/auth/saml/callback/" in str(a["service"]["sp"]["endpoints"])
    assert "https://b.example.com/auth/saml/callback/" in str(b["service"]["sp"]["endpoints"])


def test_core_build_config_idp():
    core = SAMLCore(prefix="SAML_IDP", settings=None, role="idp", logger=None)
    cnf = core.build_config("https://idp.example.com")
    endpoints = cnf["service"]["idp"]["endpoints"]
    sso_bindings = {b for _, b in endpoints["single_sign_on_service"]}
    slo_bindings = {b for _, b in endpoints["single_logout_service"]}
    assert len(sso_bindings) == 2  # Redirect + POST
    assert len(slo_bindings) == 2
    assert "cert_file" not in cnf or cnf.get("cert_file") is None


def test_core_settings_override_precedence(saml_keys):
    core = SAMLCore(prefix="SAML", settings={"accepted_time_diff": 5}, role="sp", logger=None)
    assert core.build_config("https://x")["accepted_time_diff"] == 5


def test_core_check_xmlsec_missing(monkeypatch, core):
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("navigator_auth.backends.saml.core.SAML_XMLSEC_BINARY", None)
    with pytest.raises(ConfigError, match="SAML_XMLSEC_BINARY"):
        core.check_xmlsec()


def test_core_check_xmlsec_present(core):
    # xmlsec1 is installed in CI/this environment; must not raise.
    core.check_xmlsec()


def test_core_flatten_attributes(core):
    attrs = {"mail": ["a@x"], "groups": ["g1", "g2"]}
    mapping = {"email": "mail", "groups": {"name": "groups", "multi": True}}
    assert core.flatten_attributes(attrs, mapping) == {"email": "a@x", "groups": ["g1", "g2"]}


def test_core_flatten_attributes_unmapped_missing(core):
    attrs = {"mail": ["a@x"], "unused": ["z"]}
    mapping = {"email": "mail", "username": "uid"}
    # "unused" is ignored (not in mapping); "uid" missing from attrs is skipped.
    assert core.flatten_attributes(attrs, mapping) == {"email": "a@x"}


def test_sp_config_from_dict_rejects_missing_acs():
    with pytest.raises(ValueError):
        ServiceProviderConfig.from_dict({"sp_id": "acme", "entity_id": "urn:acme"})


def test_sp_config_from_dict_rejects_non_post_binding():
    with pytest.raises(ValueError):
        ServiceProviderConfig.from_dict(
            {
                "sp_id": "acme",
                "entity_id": "urn:acme",
                "acs_url": "https://acme.example.com/acs",
                "acs_binding": "HTTP-Redirect",
            }
        )


def test_sp_config_from_dict_ok():
    sp = ServiceProviderConfig.from_dict(
        {
            "sp_id": "acme",
            "entity_id": "urn:acme",
            "acs_url": "https://acme.example.com/acs",
        }
    )
    assert sp.sp_id == "acme"
    assert sp.acs_binding == "HTTP-POST"
    assert sp.sign_assertion is True


@pytest.mark.asyncio
async def test_core_run_in_executor(core):
    main = threading.get_ident()
    assert await core.run(threading.get_ident) != main


def test_sp_metadata_and_idp_metadata_render(core):
    xml = core.sp_metadata("https://a.example.com")
    assert "EntityDescriptor" in xml
    assert "https://a.example.com/auth/saml/callback/" in xml

    idp_core = SAMLCore(prefix="SAML_IDP", settings=None, role="idp", logger=None)
    idp_xml = idp_core.idp_metadata("https://idp.example.com")
    assert "EntityDescriptor" in idp_xml


def test_key_helpers(core):
    assert core.req_key("abc") == "saml_req_abc"
    assert core.assert_key("id1") == "saml_assert_id1"
    assert core.slo_key("id2") == "saml_slo_id2"
    assert core.idp_key("flow1") == "saml_idp_flow1"


def test_load_keypair_ok(core, saml_keys):
    from navigator_auth.backends.saml import SAMLKeyPair

    pair = SAMLKeyPair(key_file=saml_keys["idp_key"], cert_file=saml_keys["idp_cert"])
    core.load_keypair(pair)  # must not raise


def test_load_keypair_missing_file(core):
    from navigator_auth.backends.saml import SAMLKeyPair

    pair = SAMLKeyPair(key_file="does/not/exist.key", cert_file="does/not/exist.crt")
    with pytest.raises(ConfigError):
        core.load_keypair(pair)
