"""Tests for FEAT-097 Module 4: AbstractSAMLBackend Single Logout
(SP-initiated and inbound) (TASK-057).
"""
import warnings

import pytest
from aiohttp.test_utils import make_mocked_request

SCHEME = "https"


class _FakeSession(dict):
    """Minimal `SessionData` double: dict-like + `.invalidate()`."""

    def invalidate(self):
        self.clear()
        self["_invalidated"] = True


def _attach_fake_session(request, session_index):
    """Inject a `_FakeSession` under `NAV_SESSION` so `get_session()` (which
    checks `request.get(SESSION_OBJECT)` first) returns it without needing
    real session middleware. Returns the session for direct inspection."""
    from navigator_session.conf import SESSION_OBJECT

    session = _FakeSession(
        saml={
            "name_id": "abc123",
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "session_index": session_index,
            "idp_entity_id": f"{SCHEME}://idp.example.com/auth/saml-idp/metadata",
            "backend": "saml",
        }
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        request[SESSION_OBJECT] = session
        request["_fake_session"] = session
    return session


@pytest.fixture
def session_with_saml():
    def _factory(session_index):
        request = make_mocked_request(
            "GET", f"{SCHEME}://sp.example.com/api/v1/auth/saml/logout",
            headers={"Host": "sp.example.com"},
        )
        _attach_fake_session(request, session_index)
        return request

    return _factory


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_slo_sp_initiated(sp_backend, session_with_saml, redis_stub):
    request = session_with_saml(session_index="idx-1")
    resp = await sp_backend.logout(request)
    assert resp.status == 302
    assert "SAMLRequest=" in resp.headers["Location"]
    assert any(k.startswith("saml_slo_") for k in redis_stub.keys())
    assert request["_fake_session"].get("_invalidated") is True


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_slo_no_session_index(sp_backend, session_with_saml):
    request = session_with_saml(session_index=None)
    resp = await sp_backend.logout(request)
    assert "SAMLRequest" not in resp.headers.get("Location", "")
    assert request["_fake_session"].get("_invalidated") is True


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_slo_logout_response(sp_backend, redis_stub):
    """Full SP -> IdP -> SP round trip for the LogoutResponse leg."""
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.saml import NameID

    domain_url = f"{SCHEME}://sp.example.com"
    sp_client = await sp_backend.core.sp_client(domain_url)
    idp_entity_id = f"{SCHEME}://idp.example.com/auth/saml-idp/metadata"
    slo_url = f"{SCHEME}://idp.example.com/auth/saml-idp/slo"

    name_id = NameID(
        format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        text="abc123",
        name_qualifier=idp_entity_id,
        sp_name_qualifier=sp_client.config.entityid,
    )
    req_id, logout_req = sp_client.create_logout_request(
        slo_url, idp_entity_id, name_id=name_id, session_indexes=["idx-1"]
    )
    await redis_stub.set(
        sp_backend.core.slo_key(req_id),
        {"session_index": "idx-1", "return_to": "/after-logout"},
        ttl=600,
    )
    # BINDING_HTTP_REDIRECT expects the deflated/base64/urlencoded query
    # param, not the raw XML — apply_binding produces it exactly like the
    # real `logout()` handler does.
    req_bind_info = sp_client.apply_binding(BINDING_HTTP_REDIRECT, str(logout_req), slo_url, "")
    from urllib.parse import parse_qs, urlparse

    req_qs = parse_qs(urlparse(dict(req_bind_info["headers"])["Location"]).query)
    encoded_logout_request = req_qs["SAMLRequest"][0]

    # IdP side: parse the request and build a signed LogoutResponse.
    from navigator_auth.backends.saml import SAMLCore

    idp_core = SAMLCore(
        prefix="SAML_IDP",
        settings={
            "key_file": "tests/fixtures/saml/idp.key",
            "cert_file": "tests/fixtures/saml/idp.crt",
            "metadata": {"local": ["tests/fixtures/saml/sp-metadata.xml"]},
        },
        role="idp",
        logger=None,
    )
    idp_cnf = idp_core._load_idp_config("https://idp.example.com")
    from saml2.server import Server

    idp_server = Server(config=idp_cnf)
    req_info = idp_server.parse_logout_request(encoded_logout_request, BINDING_HTTP_REDIRECT)
    logout_resp = idp_server.create_logout_response(
        req_info.message, [BINDING_HTTP_REDIRECT], sign=True
    )
    resp_info = idp_server.apply_binding(
        BINDING_HTTP_REDIRECT, str(logout_resp), domain_url + "/auth/saml/logout", "", response=True
    )
    headers = dict(resp_info.get("headers") or [])
    location = headers["Location"]
    from urllib.parse import urlparse, parse_qs

    qs = parse_qs(urlparse(location).query)
    saml_response = qs["SAMLResponse"][0]

    from urllib.parse import urlencode

    request = make_mocked_request(
        "GET",
        f"{domain_url}/auth/saml/logout?{urlencode({'SAMLResponse': saml_response})}",
        headers={"Host": "sp.example.com"},
    )
    resp = await sp_backend.finish_logout(request)
    assert resp.status == 302
    assert resp.headers["Location"].endswith("/after-logout")
    # single-use: the flow record is gone
    assert await redis_stub.get(sp_backend.core.slo_key(req_id)) is None


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_slo_inbound_logout_request(sp_backend):
    """The IdP notifies us of a logout it processed elsewhere; our matching
    local session (by SessionIndex) is cleared and a signed
    LogoutResponse is returned."""
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.saml import NameID
    from saml2.server import Server

    from navigator_auth.backends.saml import SAMLCore

    domain_url = f"{SCHEME}://sp.example.com"
    idp_entity_id = f"{SCHEME}://idp.example.com/auth/saml-idp/metadata"

    idp_core = SAMLCore(
        prefix="SAML_IDP",
        settings={
            "key_file": "tests/fixtures/saml/idp.key",
            "cert_file": "tests/fixtures/saml/idp.crt",
            "metadata": {"local": ["tests/fixtures/saml/sp-metadata.xml"]},
        },
        role="idp",
        logger=None,
    )
    idp_cnf = idp_core._load_idp_config("https://idp.example.com")
    idp_server = Server(config=idp_cnf)

    sp_client = await sp_backend.core.sp_client(domain_url)
    name_id = NameID(
        format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        text="abc123",
        name_qualifier=idp_entity_id,
        sp_name_qualifier=sp_client.config.entityid,
    )
    req_id, logout_req = idp_server.create_logout_request(
        domain_url + "/auth/saml/logout",
        sp_client.config.entityid,
        name_id=name_id,
        session_indexes=["idx-1"],
    )
    info = idp_server.apply_binding(
        BINDING_HTTP_REDIRECT, str(logout_req), domain_url + "/auth/saml/logout", ""
    )
    headers = dict(info.get("headers") or [])
    from urllib.parse import urlparse, parse_qs

    qs = parse_qs(urlparse(headers["Location"]).query)
    saml_request = qs["SAMLRequest"][0]

    from urllib.parse import urlencode

    full_url = f"{domain_url}/auth/saml/logout?{urlencode({'SAMLRequest': saml_request})}"
    request2 = make_mocked_request("GET", full_url, headers={"Host": "sp.example.com"})
    session = _attach_fake_session(request2, "idx-1")

    resp = await sp_backend.finish_logout(request2)
    # The inbound LogoutRequest arrived via Redirect binding; the signed
    # LogoutResponse is replied on the same binding -> a 302 with the
    # encoded response in the query string (not an HTML-form POST body).
    assert resp.status == 302
    assert "SAMLResponse=" in resp.headers["Location"]
    assert session.get("_invalidated") is True
