"""AbstractSAMLBackend — the SP role (FEAT-097 §2/§3 Module 3/4).

Plugs `SAMLCore` into the existing `ExternalAuth` login/callback/logout/
redirect machinery: SP-initiated login, IdP-initiated (unsolicited) login,
ACS validation, SP metadata (this module), and Single Logout (TASK-057,
appended to this same module).
"""
import asyncio
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, Union

from aiohttp import web

from ...conf import (
    AUTH_EXCLUDE_LIST_KEY,
    SAML_ALLOW_UNSOLICITED,
    SAML_BINDING,
    SAML_FLOW_TTL,
    SAML_MAPPING,
    SAML_METADATA_RELOAD,
)
from ...exceptions import UserNotFound
from ..external import OAUTH2_RESUME_COOKIE, ExternalAuth
from .core import SAMLCore
from .errors import SAMLError, map_pysaml2_error
from .types import AssertionResult, SAMLKeyPair, SAMLSessionInfo

#: Cross-call cache of the parsed POST body for one ACS request, shared by
#: `get_callback_state` (consulted first, by `_auth_callback_dispatch`) and
#: `auth_callback` so the request stream is read exactly once.
_SAML_POST_KEY = web.RequestKey("saml_post", dict)


def _flatten_raw(ava: dict) -> dict:
    """First-value-per-attribute view of a raw `pysaml2` AVA dict
    (``{saml_attr_name: [values]}}``), keyed by the *SAML* attribute name —
    the shape `BaseAuthBackend.build_user_info`/`get_user_mapping` expects
    (mirrors the legacy `backends/_legacy_saml.py` flattening)."""
    flat = {}
    for key, val in (ava or {}).items():
        if isinstance(val, (list, tuple)):
            flat[key] = val[0] if val else None
        else:
            flat[key] = val
    return flat


class AbstractSAMLBackend(ExternalAuth, ABC):
    """Abstract SAML 2.0 Service Provider backend on `pysaml2`."""

    _service_name: str = "saml"
    config_prefix: str = "SAML"
    user_mapping: dict = SAML_MAPPING
    BACKEND_QUERY_PARAMS: frozenset = frozenset()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        settings = dict(self.get_settings() or {})
        settings.setdefault("metadata", self._idp_metadata_settings())
        self.core = SAMLCore(
            prefix=self.config_prefix,
            settings=settings,
            role="sp",
            logger=self.logger,
        )

    def _idp_metadata_settings(self) -> dict:
        meta = self.get_idp_metadata()
        if isinstance(meta, dict):
            return meta
        if isinstance(meta, str) and meta.startswith(("http://", "https://")):
            return {"remote": [{"url": meta}]}
        return {"local": [meta]}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def configure(self, app):
        super().configure(app)
        router = app.router
        # ACS is HTTP-POST only; re-register the inherited GET callback
        # route (identity-link/OAuth2-AS dispatch) for POST too.
        router.add_route(
            "POST",
            f"/auth/{self._service_name}/callback/",
            self._auth_callback_dispatch,
            name=f"{self._service_name}_complete_login_post",
        )
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/metadata",
            self.metadata,
            name=f"{self._service_name}_metadata",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/auth/{self._service_name}/metadata")

    async def on_startup(self, app: web.Application):
        await super().on_startup(app)
        self.core.check_xmlsec()
        key_file = self.get_sp_keypair_files()
        if key_file:
            self.core.load_keypair(SAMLKeyPair(key_file=key_file[0], cert_file=key_file[1]))
        loop = asyncio.get_running_loop()
        self.core.start_metadata_reload(loop, SAML_METADATA_RELOAD, self._background_tasks)

    async def on_cleanup(self, app: web.Application):
        self.core.shutdown()
        await super().on_cleanup(app)

    def get_sp_keypair_files(self) -> Optional[tuple]:
        """Optional SP key pair (AuthnRequest signing / assertion
        decryption); `None` when unconfigured."""
        from navconfig import config as nav_config

        key_file = nav_config.get(f"{self.config_prefix}_SP_KEY_FILE", fallback=None)
        cert_file = nav_config.get(f"{self.config_prefix}_SP_CERT_FILE", fallback=None)
        if key_file and cert_file:
            return (key_file, cert_file)
        return None

    # ------------------------------------------------------------------
    # SP-initiated / unsolicited login
    # ------------------------------------------------------------------
    async def authenticate(self, request: web.Request) -> web.Response:
        domain_url = self.get_domain(request)
        relay = secrets.token_urlsafe(32)
        qs = self.queryparams(request)
        redirect = qs.get("redirect_uri") if qs else None
        internal_redirect = self.validate_redirect_host(redirect) if redirect else None
        oauth2_flow = request.cookies.get(OAUTH2_RESUME_COOKIE)
        binding = (
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            if SAML_BINDING == "post"
            else "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        )
        try:
            client = await self.core.sp_client(domain_url)
            request_id, info = await self.core.run(
                client.prepare_for_authenticate, relay_state=relay, binding=binding
            )
            await self._flow_store.set(
                self.core.req_key(relay),
                {
                    "request_id": request_id,
                    "internal_redirect": internal_redirect,
                    "acs_url": f"{domain_url}/auth/{self._service_name}/callback/",
                    "oauth2_flow": oauth2_flow,
                },
                ttl=SAML_FLOW_TTL,
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(err)
            raise web.HTTPForbidden(reason=f"SAML: Unable to Authenticate: {err}")
        return self._render_binding_response(info)

    def _render_binding_response(self, info: dict) -> web.Response:
        headers = dict(info.get("headers") or [])
        if "Location" in headers:
            return web.HTTPFound(headers["Location"])
        data = info.get("data")
        if data:
            html = data if isinstance(data, str) else "".join(data)
            return web.Response(text=html, content_type="text/html")
        raise web.HTTPForbidden(reason="SAML: could not build AuthnRequest")

    async def get_callback_state(self, request: web.Request) -> Optional[str]:
        """`RelayState` (POST form field) for the ACS callback; falls back
        to the query ``state`` for any non-SAML GET hit on this route.
        Overrides `ExternalAuth.get_callback_state`, awaited by
        `_auth_callback_dispatch`."""
        if request.method == "POST":
            cached = request.get(_SAML_POST_KEY)
            if cached is None:
                cached = dict(await request.post())
                request[_SAML_POST_KEY] = cached
            return cached.get("RelayState")
        return request.rel_url.query.get("state")

    async def auth_callback(self, request: web.Request) -> web.Response:
        if request.method == "GET":
            return web.Response(
                status=405,
                text="SAML ACS requires HTTP POST binding (HTTP-POST is the only supported binding)",
            )
        domain_url = self.get_domain(request)
        post_data = request.get(_SAML_POST_KEY)
        if post_data is None:
            post_data = dict(await request.post())
            request[_SAML_POST_KEY] = post_data
        saml_response = post_data.get("SAMLResponse")
        relay_state = post_data.get("RelayState")
        if not saml_response:
            self._audit_rejected(request, "SAML_INVALID_RESPONSE", issuer=None)
            return self.failed_redirect(
                request, error="SAML_INVALID_RESPONSE", message="Missing SAMLResponse"
            )

        flow = None
        if relay_state:
            flow = await self._flow_store.getdel(self.core.req_key(relay_state))

        try:
            from saml2 import BINDING_HTTP_POST

            client = await self.core.sp_client(domain_url)
            outstanding = {flow["request_id"]: "/"} if flow else None
            authn_response = await self.core.run(
                client.parse_authn_request_response,
                saml_response,
                BINDING_HTTP_POST,
                outstanding,
            )
            if authn_response is None:
                raise SAMLError("Empty SAML response")
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: ACS validation failed: {err}")
            saml_err = err if isinstance(err, SAMLError) else map_pysaml2_error(err)
            self._audit_rejected(request, saml_err.code, issuer=None)
            return self.failed_redirect(
                request, error=saml_err.code, message="SAML authentication failed"
            )

        in_response_to = authn_response.response.in_response_to
        issuer = authn_response.issuer()
        unsolicited = False
        if flow:
            if in_response_to != flow["request_id"]:
                self._audit_rejected(request, "SAML_INVALID_RESPONSE", issuer)
                return self.failed_redirect(
                    request,
                    error="SAML_INVALID_RESPONSE",
                    message="InResponseTo does not match the outstanding request",
                )
        else:
            if in_response_to:
                self._audit_rejected(request, "SAML_STALE_REQUEST", issuer)
                return self.failed_redirect(
                    request,
                    error="SAML_STALE_REQUEST",
                    message="No matching AuthnRequest for this response",
                )
            if not SAML_ALLOW_UNSOLICITED:
                self._audit_rejected(request, "SAML_FORBIDDEN", issuer)
                return self.failed_redirect(
                    request, error="SAML_FORBIDDEN", message="Unsolicited responses are disabled"
                )
            unsolicited = True

        assertion_id = authn_response.assertion.id
        if unsolicited:
            existing = await self._flow_store.get(self.core.assert_key(assertion_id))
            if existing:
                self._audit_rejected(request, "SAML_REPLAY", issuer)
                return self.failed_redirect(
                    request, error="SAML_REPLAY", message="This SAML response was already used"
                )

        not_on_or_after = datetime.fromtimestamp(authn_response.not_on_or_after, tz=timezone.utc)
        ttl = max(1, int((not_on_or_after - datetime.now(tz=timezone.utc)).total_seconds()))
        await self._flow_store.set(
            self.core.assert_key(assertion_id),
            {"issuer": issuer, "consumed_at": datetime.now(tz=timezone.utc).isoformat()},
            ttl=ttl,
        )

        session_index = None
        try:
            session_index = authn_response.assertion.authn_statement[0].session_index
        except (AttributeError, IndexError, TypeError):
            pass

        raw_ava = authn_response.ava or {}
        mapping = self.get_attribute_mapping()
        result = AssertionResult(
            name_id=authn_response.name_id.text,
            name_id_format=authn_response.name_id.format,
            session_index=session_index,
            issuer=issuer,
            assertion_id=assertion_id,
            not_on_or_after=not_on_or_after,
            attributes=self.core.flatten_attributes(raw_ava, mapping),
            raw_attributes=raw_ava,
            in_response_to=in_response_to,
            unsolicited=unsolicited,
        )

        try:
            identifier = await self.resolve_user_identifier(result)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: resolve_user_identifier failed: {err}")
            self._audit_rejected(request, "SAML_INVALID_RESPONSE", issuer)
            return self.failed_redirect(
                request, error="SAML_INVALID_RESPONSE", message="Could not resolve the SAML identity"
            )

        if not await self.authorize(request, result, identifier):
            self._audit_rejected(request, "SAML_FORBIDDEN", issuer)
            return self.failed_redirect(request, error="SAML_FORBIDDEN", message="Access denied")

        userdata, uid = self.build_user_info(
            _flatten_raw(raw_ava), token=result.name_id, mapping=mapping
        )
        userdata[self.username_attribute] = identifier

        try:
            data = await self.validate_user_info(request, uid, userdata, token=result.name_id)
        except UserNotFound:
            self._audit_rejected(request, "SAML_USER_NOT_FOUND", issuer)
            return self.failed_redirect(
                request, error="SAML_USER_NOT_FOUND", message="User not found"
            )
        except web.HTTPForbidden:
            self._audit_rejected(request, "SAML_FORBIDDEN", issuer)
            raise

        await self._persist_saml_session(request, result)
        self._audit_issued(request, result, uid)

        try:
            await self.on_assertion(request, result, data)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: on_assertion hook failed: {err}")

        if flow and flow.get("oauth2_flow"):
            request["oauth2_flow"] = flow["oauth2_flow"]

        redirect_uri = None
        if flow:
            redirect_uri = self.validate_redirect_host(flow.get("internal_redirect"))

        return self.home_redirect(request, token=data.get("token"), uri=redirect_uri)

    async def _persist_saml_session(self, request: web.Request, result: AssertionResult) -> None:
        try:
            from navigator_session import get_session

            session = await get_session(request, new=False)
            if session is not None:
                info = SAMLSessionInfo(
                    name_id=result.name_id,
                    name_id_format=result.name_id_format,
                    session_index=result.session_index,
                    idp_entity_id=result.issuer,
                    backend=self._service_name,
                )
                session["saml"] = info.to_dict()
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: could not persist SAML session info: {err}")

    def _audit_issued(self, request: web.Request, result: AssertionResult, user_id) -> None:
        self.logger.info(
            "saml.assertion.issued "
            f"backend={self._service_name} issuer={result.issuer} user_id={user_id} "
            f"assertion_id={result.assertion_id} not_on_or_after={result.not_on_or_after.isoformat()} "
            f"in_response_to={result.in_response_to} remote={getattr(request, 'remote', None)}"
        )

    def _audit_rejected(self, request: web.Request, code: str, issuer: Optional[str]) -> None:
        self.logger.warning(
            "saml.assertion.rejected "
            f"backend={self._service_name} issuer={issuer} reason={code} "
            f"remote={getattr(request, 'remote', None)}"
        )

    async def metadata(self, request: web.Request) -> web.Response:
        domain_url = self.get_domain(request)
        xml = await self.core.run(self.core.sp_metadata, domain_url)
        return web.Response(text=xml, content_type="text/xml")

    async def check_credentials(self, request: web.Request) -> bool:
        return True

    # ------------------------------------------------------------------
    # Single Logout — TASK-057 scope. Stubs only here so this abstract
    # class satisfies `ExternalAuth`'s `logout`/`finish_logout` contract
    # and a minimal SP-only subclass (this task's tests) can instantiate;
    # TASK-057 replaces both with the real SP-initiated/inbound SLO flow.
    # ------------------------------------------------------------------
    async def logout(self, request: web.Request) -> web.Response:
        raise NotImplementedError(
            f"{self._service_name}: Single Logout is implemented in TASK-057"
        )

    async def finish_logout(self, request: web.Request) -> web.Response:
        raise NotImplementedError(
            f"{self._service_name}: Single Logout is implemented in TASK-057"
        )

    # ------------------------------------------------------------------
    # Provider hooks
    # ------------------------------------------------------------------
    @abstractmethod
    def get_idp_metadata(self) -> Union[str, dict]:
        """Path/URL to IdP metadata XML, or inline `pysaml2` metadata dict."""

    @abstractmethod
    def get_attribute_mapping(self) -> dict:
        """`user_field -> SAML attribute name` mapping (`SAML_MAPPING` shape)."""

    @abstractmethod
    async def resolve_user_identifier(self, result: AssertionResult) -> str:
        """Return the login identifier used for `validate_user_info`."""

    async def authorize(
        self, request: web.Request, result: AssertionResult, identifier: str
    ) -> bool:
        """Post-validation access decision (default: allow)."""
        return True

    async def on_assertion(self, request: web.Request, result: AssertionResult, user) -> None:
        """Called after the session is created (default: no-op)."""

    def get_settings(self) -> Optional[dict]:
        """Optional `pysaml2` overrides (default: `<prefix>_SETTINGS` JSON)."""
        from navconfig import config as nav_config
        from ...libs.json import json_decoder

        raw = nav_config.get(f"{self.config_prefix}_SETTINGS", fallback=None)
        if not raw:
            return None
        try:
            return json_decoder(raw)
        except ValueError:
            self.logger.exception(f"{self._service_name}: invalid {self.config_prefix}_SETTINGS")
            return None
