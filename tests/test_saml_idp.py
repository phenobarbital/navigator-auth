"""Tests for FEAT-097 Module 5: AbstractSAMLIdentityProvider — SP
registry, metadata, IdP-initiated SSO, audit (TASK-058); SP-initiated SSO,
the no-session detour, and SLO (TASK-059).
"""
import warnings
from unittest.mock import MagicMock

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.saml import (
    AbstractSAMLIdentityProvider,
    SAMLCore,
    SAMLKeyPair,
    ServiceProviderConfig,
)
from navigator_auth.exceptions import ConfigError

SCHEME = "https"
IDP_KEY = "tests/fixtures/saml/idp.key"
IDP_CERT = "tests/fixtures/saml/idp.crt"


class MinimalIdP(AbstractSAMLIdentityProvider):
    def get_service_providers(self):
        return {
            "acme": ServiceProviderConfig(
                sp_id="acme",
                entity_id=f"{SCHEME}://sp.example.com/auth/saml/metadata",
                acs_url=f"{SCHEME}://sp.example.com/auth/saml/callback/",
            )
        }

    async def build_attributes(self, user, sp):
        return {"mail": [user.email]}


class _FakeUser:
    is_authenticated = True

    def __init__(self, email="u@x.com", username="u", user_id=1, auth_method=None):
        self.email = email
        self.username = username
        self.user_id = user_id
        self.auth_method = auth_method


@pytest.fixture
def idp_backend(force_https_scheme):
    backend = object.__new__(MinimalIdP)
    backend.logger = MagicMock()
    backend.core = SAMLCore(
        prefix="SAML_IDP",
        settings={"key_file": IDP_KEY, "cert_file": IDP_CERT},
        role="idp",
        logger=backend.logger,
    )
    backend._sp_registry = backend._parse_service_providers()
    backend._trust_registered_sps()
    backend._flow_store = _FakeFlowStore()
    return backend


class _FakeFlowStore:
    """Dict-backed IdentityFlowStore double (single-use semantics)."""

    def __init__(self):
        self.storage = {}

    async def set(self, key, payload, ttl):
        self.storage[key] = dict(payload)

    async def get(self, key):
        return self.storage.get(key)

    async def getdel(self, key):
        return self.storage.pop(key, None)

    def keys(self):
        return self.storage.keys()


_UNSET = object()


@pytest.fixture
def authed_request():
    def _factory(sp_id: str, user=_UNSET):
        request = make_mocked_request(
            "GET",
            f"{SCHEME}://idp.example.com/auth/saml-idp/initiate/{sp_id}",
            headers={"Host": "idp.example.com"},
            match_info={"sp_id": sp_id},
        )
        request.user = _FakeUser() if user is _UNSET else user
        return request

    return _factory


def test_idp_registry_parse_and_validate(idp_backend):
    registry = idp_backend._sp_registry
    assert "acme" in registry
    assert registry["acme"].entity_id == f"{SCHEME}://sp.example.com/auth/saml/metadata"


def test_idp_registry_duplicate_sp_id_rejected():
    class DupIdP(AbstractSAMLIdentityProvider):
        def get_service_providers(self):
            # A dict can't have two keys "acme", but a subclass could
            # return duplicate *sp_id* values under different dict keys.
            return {
                "acme-1": ServiceProviderConfig(sp_id="acme", entity_id="urn:a", acs_url="https://a/acs"),
                "acme-2": ServiceProviderConfig(sp_id="acme", entity_id="urn:b", acs_url="https://b/acs"),
            }

        async def build_attributes(self, user, sp):
            return {}

    backend = object.__new__(DupIdP)
    backend.logger = MagicMock()
    with pytest.raises(ConfigError, match="duplicate"):
        backend._parse_service_providers()


def test_idp_registry_missing_fields_rejected():
    class BadIdP(AbstractSAMLIdentityProvider):
        def get_service_providers(self):
            return {"bad": {"sp_id": "bad", "entity_id": "urn:bad"}}  # missing acs_url

        async def build_attributes(self, user, sp):
            return {}

    backend = object.__new__(BadIdP)
    backend.logger = MagicMock()
    with pytest.raises(ValueError):
        backend._parse_service_providers()


@pytest.mark.asyncio
async def test_idp_metadata_valid(idp_backend):
    request = make_mocked_request(
        "GET", f"{SCHEME}://idp.example.com/auth/saml-idp/metadata",
        headers={"Host": "idp.example.com"},
    )
    resp = await idp_backend.metadata(request)
    assert resp.status == 200
    assert "EntityDescriptor" in resp.text
    assert "SingleSignOnService" in resp.text


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_idp_initiate_ok(idp_backend, authed_request):
    resp = await idp_backend.initiate(authed_request(sp_id="acme"))
    assert resp.status == 200
    assert 'name="SAMLResponse"' in resp.text
    # Audit: last logger.info call names the issued-assertion event.
    last_info = idp_backend.logger.info.call_args[0][0]
    assert "saml.assertion.issued" in last_info
    assert "sp_id=acme" in last_info


@pytest.mark.asyncio
async def test_idp_initiate_unknown_sp(idp_backend, authed_request):
    with pytest.raises(Exception) as exc_info:
        await idp_backend.initiate(authed_request(sp_id="nope"))
    resp = exc_info.value
    assert getattr(resp, "status", None) == 404 or getattr(resp, "status_code", None) == 404
    assert "acme" not in str(resp)


@pytest.mark.asyncio
async def test_idp_initiate_forbidden(idp_backend, authed_request):
    async def _deny(request, user, sp):
        return False

    idp_backend.authorize_sp_access = _deny
    # BaseAuthBackend.auth_error() passes a deprecated `body=` kwarg to
    # web.HTTPForbidden/HTTPUnauthorized on this aiohttp version; a
    # pre-existing, unrelated issue only surfaced by this repo's strict
    # filterwarnings config exercising a real web.Request. Not in scope
    # here (abstract.py is not a FEAT-097 file); suppressed locally.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(Exception) as exc_info:
            await idp_backend.initiate(authed_request(sp_id="acme"))
    resp = exc_info.value
    assert getattr(resp, "status", None) == 403 or getattr(resp, "status_code", None) == 403
    last_warning = idp_backend.logger.warning.call_args[0][0]
    assert "saml.sp.forbidden" in last_warning
    idp_backend.logger.info.assert_not_called()


@pytest.mark.asyncio
async def test_idp_initiate_unauthenticated(idp_backend, authed_request):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(Exception) as exc_info:
            await idp_backend.initiate(authed_request(sp_id="acme", user=None))
    resp = exc_info.value
    assert getattr(resp, "status", None) == 401 or getattr(resp, "status_code", None) == 401


def test_idp_hidden_from_auth_methods(idp_backend):
    assert idp_backend.hidden is True
    assert idp_backend._external_auth is False


@pytest.mark.asyncio
async def test_idp_omitted_from_api_auth_methods_endpoint(idp_backend):
    """`AuthHandler.auth_methods` (`/api/v1/auth/methods`) must omit any
    backend with `hidden = True` — exercises the real, modified method."""
    from navigator_auth.auth import AuthHandler

    class _VisibleBackend:
        hidden = False

        def get_backend_info(self):
            return {"name": "Basic"}

    handler = object.__new__(AuthHandler)
    handler.backends = {"Basic": _VisibleBackend(), "MinimalIdP": idp_backend}

    request = make_mocked_request("GET", "/api/v1/auth/methods")
    resp = await handler.auth_methods(request)
    assert b"MinimalIdP" not in resp.body
    assert b"Basic" in resp.body


@pytest.mark.asyncio
async def test_idp_nameid_default_email():
    backend = object.__new__(MinimalIdP)
    sp = ServiceProviderConfig(sp_id="acme", entity_id="urn:acme", acs_url="https://acme/acs")
    user = _FakeUser(email="a@x.com", username="auser")
    assert await backend.get_nameid(user, sp) == "a@x.com"


@pytest.mark.asyncio
async def test_idp_nameid_default_unspecified():
    backend = object.__new__(MinimalIdP)
    sp = ServiceProviderConfig(
        sp_id="acme",
        entity_id="urn:acme",
        acs_url="https://acme/acs",
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )
    user = _FakeUser(email="a@x.com", username="auser")
    assert await backend.get_nameid(user, sp) == "auser"


def test_idp_backend_exports():
    from navigator_auth.backends.saml import AbstractSAMLIdentityProvider as _AbstractIdP

    assert _AbstractIdP is AbstractSAMLIdentityProvider


# ---------------------------------------------------------------------------
# TASK-059: SP-initiated SSO (with/without session), signed AuthnRequest,
# RelayState validation, SLO.
# ---------------------------------------------------------------------------

SP_KEY = "tests/fixtures/saml/sp.key"
SP_CERT = "tests/fixtures/saml/sp.crt"


@pytest.fixture
def sp_client_for_idp(force_https_scheme):
    """A real `pysaml2` SP client trusting the committed IdP metadata
    fixture, entity/ACS matching MinimalIdP's registered "acme" SP —
    stands in for the external SP sending AuthnRequests/LogoutRequests."""
    from navigator_auth.backends.saml import SAMLCore

    core = SAMLCore(
        prefix="SAML",
        settings={
            "key_file": SP_KEY,
            "cert_file": SP_CERT,
            "metadata": {"local": ["tests/fixtures/saml/idp-metadata.xml"]},
        },
        role="sp",
        logger=None,
    )
    return core


@pytest.fixture
def authn_request(sp_client_for_idp):
    """Factory: `(encoded_request, relay_state, request_id)` for the
    Redirect binding, optionally signed with the SP's own key."""

    def _factory(relay_state: str = f"{SCHEME}://sp.example.com/after", sign: bool = False):
        from urllib.parse import parse_qs, urlparse

        from saml2 import BINDING_HTTP_REDIRECT
        from saml2.client import Saml2Client

        # Synchronous (like pysaml2's own API): building the client and
        # request doesn't need an event loop, and this fixture is called
        # directly from already-running async test bodies.
        cnf = sp_client_for_idp._load_sp_config(f"{SCHEME}://sp.example.com")
        client = Saml2Client(config=cnf)
        req_id, info = client.prepare_for_authenticate(
            relay_state=relay_state, binding=BINDING_HTTP_REDIRECT, sign=sign
        )
        headers = dict(info["headers"])
        qs = parse_qs(urlparse(headers["Location"]).query)
        return (
            qs["SAMLRequest"][0],
            qs.get("RelayState", [None])[0],
            qs.get("SigAlg", [None])[0],
            qs.get("Signature", [None])[0],
            req_id,
        )

    return _factory


def _sso_url(query: dict) -> str:
    from urllib.parse import urlencode

    return f"{SCHEME}://idp.example.com/auth/saml-idp/sso?{urlencode(query)}"


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_idp_sso_sp_initiated_with_session(idp_backend, authn_request, authed_request):
    encoded_req, relay_state, sigalg, signature, req_id = authn_request()
    query = {"SAMLRequest": encoded_req, "RelayState": relay_state}
    request = make_mocked_request(
        "GET", _sso_url(query), headers={"Host": "idp.example.com"}
    )
    request.user = _FakeUser()
    resp = await idp_backend.sso(request)
    assert resp.status == 200
    assert 'name="SAMLResponse"' in resp.text
    last_info = idp_backend.logger.info.call_args[0][0]
    assert "saml.assertion.issued" in last_info

    # InResponseTo on the issued assertion matches the AuthnRequest's ID.
    import base64
    import re

    b64 = re.search(r'name="SAMLResponse" value="([^"]+)"', resp.text).group(1)
    import html

    xml = base64.b64decode(html.unescape(b64)).decode("utf-8")
    assert f'InResponseTo="{req_id}"' in xml


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_idp_sso_no_session_detour(idp_backend, authn_request):
    encoded_req, relay_state, _sigalg, _signature, req_id = authn_request()
    query = {"SAMLRequest": encoded_req, "RelayState": relay_state}
    request = make_mocked_request(
        "GET", _sso_url(query), headers={"Host": "idp.example.com"}
    )
    request.user = None
    resp = await idp_backend.sso(request)
    assert resp.status == 302
    # The parked-flow resume URL ("sso?flow=<id>") travels percent-encoded
    # as this login redirect's own `redirect_uri` query value.
    from urllib.parse import parse_qs, urlparse

    login_qs = parse_qs(urlparse(resp.headers["Location"]).query)
    resume_url = login_qs["redirect_uri"][0]
    assert "sso?flow=" in resume_url
    assert sum(1 for k in idp_backend._flow_store.keys() if k.startswith("saml_idp_")) == 1

    # Resume: the parked flow is single-use (GETDEL).
    flow_id = resume_url.split("sso?flow=")[1]
    resume_request = make_mocked_request(
        "GET", _sso_url({"flow": flow_id}), headers={"Host": "idp.example.com"}
    )
    resume_request.user = _FakeUser()
    resumed = await idp_backend.sso(resume_request)
    assert resumed.status == 200
    assert 'name="SAMLResponse"' in resumed.text

    # Second hit on the same flow fails (already consumed).
    replay_request = make_mocked_request(
        "GET", _sso_url({"flow": flow_id}), headers={"Host": "idp.example.com"}
    )
    replay_request.user = _FakeUser()
    replayed = await idp_backend.sso(replay_request)
    assert replayed.status == 400
    assert "SAML_STALE_REQUEST" in replayed.text


@pytest.mark.asyncio
async def test_idp_sso_signed_authn_request_missing_signature_rejected(idp_backend, authn_request):
    """`sp.want_signed_authn_request=True` and no Signature/SigAlg on the
    request -> rejected, no assertion issued."""
    idp_backend._sp_registry["acme"] = ServiceProviderConfig(
        sp_id="acme",
        entity_id=f"{SCHEME}://sp.example.com/auth/saml/metadata",
        acs_url=f"{SCHEME}://sp.example.com/auth/saml/callback/",
        want_signed_authn_request=True,
    )
    encoded_req, relay_state, _sigalg, _signature, _req_id = authn_request(sign=False)
    query = {"SAMLRequest": encoded_req, "RelayState": relay_state}
    request = make_mocked_request(
        "GET", _sso_url(query), headers={"Host": "idp.example.com"}
    )
    request.user = _FakeUser()
    resp = await idp_backend.sso(request)
    assert resp.status == 400
    assert "SAML_INVALID_AUTHN_REQUEST" in resp.text
    idp_backend.logger.info.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_idp_relaystate_validation(idp_backend, authed_request):
    """RelayState must match the SP's ACS host or `allowed_relay_hosts`;
    an off-host value is dropped (assertion is still issued)."""
    resp = await idp_backend.initiate(authed_request(sp_id="acme"))
    assert resp.status == 200
    # Off-host RelayState never reaches issue_assertion's form.
    idp_backend.logger.reset_mock()
    from aiohttp.test_utils import make_mocked_request as _mmr

    request = _mmr(
        "GET",
        f"{SCHEME}://idp.example.com/auth/saml-idp/initiate/acme?RelayState=https://evil.test/steal",
        headers={"Host": "idp.example.com"},
        match_info={"sp_id": "acme"},
    )
    request.user = _FakeUser()
    resp2 = await idp_backend.initiate(request)
    assert resp2.status == 200
    assert "evil.test" not in resp2.text


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_idp_slo_inbound_logout_request(idp_backend, sp_client_for_idp):
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.saml import NameID

    idp_backend._sp_registry["acme"] = ServiceProviderConfig(
        sp_id="acme",
        entity_id=f"{SCHEME}://sp.example.com/auth/saml/metadata",
        acs_url=f"{SCHEME}://sp.example.com/auth/saml/callback/",
        slo_url=f"{SCHEME}://sp.example.com/auth/saml/logout",
    )
    idp_backend._trust_registered_sps()
    sp_client = await sp_client_for_idp.sp_client(f"{SCHEME}://sp.example.com")
    name_id = NameID(
        format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        text="u@x.com",
        name_qualifier=f"{SCHEME}://idp.example.com/auth/saml-idp/metadata",
        sp_name_qualifier=sp_client.config.entityid,
    )
    req_id, logout_req = sp_client.create_logout_request(
        f"{SCHEME}://idp.example.com/auth/saml-idp/slo",
        f"{SCHEME}://idp.example.com/auth/saml-idp/metadata",
        name_id=name_id,
        session_indexes=["idx-1"],
    )
    req_info = sp_client.apply_binding(
        BINDING_HTTP_REDIRECT, str(logout_req), f"{SCHEME}://idp.example.com/auth/saml-idp/slo", ""
    )
    from urllib.parse import parse_qs, urlparse

    qs = parse_qs(urlparse(dict(req_info["headers"])["Location"]).query)
    encoded_request = qs["SAMLRequest"][0]

    request = make_mocked_request(
        "GET", _sso_url({"SAMLRequest": encoded_request}).replace("/sso?", "/slo?"),
        headers={"Host": "idp.example.com"},
    )
    resp = await idp_backend.slo(request)
    assert resp.status == 302
    assert "SAMLResponse=" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_idp_slo_unregistered_sp_rejected(idp_backend):
    request = make_mocked_request(
        "GET", _sso_url({}).replace("/sso?", "/slo"), headers={"Host": "idp.example.com"}
    )
    resp = await idp_backend.slo(request)
    assert resp.status == 400
    assert "SAML_SLO_FAILED" in resp.text
