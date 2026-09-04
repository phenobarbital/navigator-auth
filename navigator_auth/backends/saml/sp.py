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
        # The inherited route is GET only (LogoutResponse/inbound
        # LogoutRequest via Redirect binding); POST binding needs its own
        # route (same handler, `finish_logout` branches on `request.method`).
        router.add_route(
            "POST",
            f"/auth/{self._service_name}/logout",
            self.finish_logout,
            name=f"{self._service_name}_complete_logout_post",
        )

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
    # Single Logout (TASK-057) — both directions, using the
    # `SAMLSessionInfo` persisted under session["saml"] by `auth_callback`.
    #
    # Limitation (spec-acknowledged, out of scope here): SP-initiated
    # logout resolves the IdP SLO endpoint from the trusted IdP metadata
    # and builds the `LogoutRequest` directly from the persisted
    # NameID/SessionIndex (stateless); it does not use `pysaml2`'s
    # in-process `Saml2Client.global_logout`/`self.users` session cache,
    # which would not survive across worker processes. Likewise, the
    # inbound `LogoutRequest` handler can only clear *this* request's own
    # browser session (matched by `SessionIndex`) — there is no
    # cross-session lookup by `SessionIndex` in a shared store; a
    # multi-session-per-user SLO would need one (documented follow-up).
    # ------------------------------------------------------------------
    async def _get_saml_session(self, request: web.Request):
        """Return `(session, SAMLSessionInfo | None)`; never raises."""
        try:
            from navigator_session import get_session

            session = await get_session(request, new=False)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: could not read session: {err}")
            return None, None
        if session is None:
            return None, None
        raw = session.get("saml")
        if not raw:
            return session, None
        return session, SAMLSessionInfo.from_dict(raw)

    def _clear_local_session(self, session) -> None:
        if session is None:
            return
        try:
            session.invalidate()
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: could not invalidate local session: {err}")

    async def logout(self, request: web.Request) -> web.Response:
        domain_url = self.get_domain(request)
        session, saml_info = await self._get_saml_session(request)
        qs = self.queryparams(request) or {}
        return_to = None
        if qs.get("redirect_uri"):
            return_to = self.validate_redirect_host(qs.get("redirect_uri"))

        # Local session is always cleared, even if the IdP-side request
        # cannot be built.
        self._clear_local_session(session)

        if saml_info is None or not saml_info.session_index:
            return self.home_redirect(request, uri=return_to or "/")

        try:
            from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
            from saml2.mdstore import locations
            from saml2.saml import NameID

            client = await self.core.sp_client(domain_url)
            binding = BINDING_HTTP_REDIRECT
            loc = next(
                locations(
                    client.metadata.single_logout_service(
                        saml_info.idp_entity_id, typ="idpsso", binding=binding
                    )
                ),
                None,
            )
            if not loc:
                binding = BINDING_HTTP_POST
                loc = next(
                    locations(
                        client.metadata.single_logout_service(
                            saml_info.idp_entity_id, typ="idpsso", binding=binding
                        )
                    ),
                    None,
                )
            if not loc:
                raise SAMLError("IdP metadata does not advertise a SLO endpoint")

            name_id = NameID(
                format=saml_info.name_id_format,
                text=saml_info.name_id,
                name_qualifier=saml_info.idp_entity_id,
                sp_name_qualifier=client.config.entityid,
            )
            request_id, logout_req = await self.core.run(
                client.create_logout_request,
                loc,
                saml_info.idp_entity_id,
                name_id=name_id,
                session_indexes=[saml_info.session_index],
            )
            await self._flow_store.set(
                self.core.slo_key(request_id),
                {"session_index": saml_info.session_index, "return_to": return_to},
                ttl=SAML_FLOW_TTL,
            )
            info = await self.core.run(client.apply_binding, binding, str(logout_req), loc, "")
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"{self._service_name}: could not build SP-initiated LogoutRequest: {err}"
            )
            return self.home_redirect(request, uri=return_to or "/")
        return self._render_binding_response(info)

    async def finish_logout(self, request: web.Request) -> web.Response:
        from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

        if request.method == "POST":
            params = dict(await request.post())
            binding = BINDING_HTTP_POST
        else:
            params = dict(request.rel_url.query)
            binding = BINDING_HTTP_REDIRECT

        domain_url = self.get_domain(request)
        client = await self.core.sp_client(domain_url)

        if params.get("SAMLResponse"):
            return await self._finish_logout_response(request, client, params, binding)
        if params.get("SAMLRequest"):
            return await self._finish_logout_request(request, client, params, binding)
        return self.failed_redirect(
            request, error="SAML_SLO_FAILED", message="Missing SAMLRequest/SAMLResponse"
        )

    async def _finish_logout_response(self, request, client, params, binding) -> web.Response:
        """The IdP's reply to our SP-initiated `LogoutRequest`."""
        try:
            resp = await self.core.run(
                client.parse_logout_request_response, params["SAMLResponse"], binding
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: SLO LogoutResponse parse failed: {err}")
            resp = None

        in_response_to = getattr(resp, "in_response_to", None) if resp else None
        flow = None
        if in_response_to:
            flow = await self._flow_store.getdel(self.core.slo_key(in_response_to))

        if resp is None:
            self.logger.warning(
                f"{self._service_name}: {SAMLError.__name__}: SAML_SLO_FAILED (invalid LogoutResponse)"
            )
        return_to = self.validate_redirect_host((flow or {}).get("return_to")) if flow else None
        return self.home_redirect(request, uri=return_to or "/")

    async def _finish_logout_request(self, request, client, params, binding) -> web.Response:
        """An inbound, IdP-initiated `LogoutRequest` (another SP's SLO, or
        the IdP itself, notifying us that the IdP session ended)."""
        try:
            req_info = await self.core.run(
                client.parse_logout_request, params["SAMLRequest"], binding
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: inbound LogoutRequest parse failed: {err}")
            return self.failed_redirect(
                request, error="SAML_SLO_FAILED", message="Invalid LogoutRequest"
            )

        session_index = None
        try:
            session_index = req_info.message.session_index[0].text
        except (AttributeError, IndexError, TypeError):
            pass

        session, saml_info = await self._get_saml_session(request)
        if saml_info is not None and (
            not session_index or saml_info.session_index == session_index
        ):
            self._clear_local_session(session)

        try:
            resp_args = client.response_args(req_info.message, [binding])
            logout_resp = await self.core.run(
                client.create_logout_response, req_info.message, [binding]
            )
            resp_info = await self.core.run(
                client.apply_binding,
                resp_args.get("binding", binding),
                str(logout_resp),
                resp_args.get("destination", ""),
                params.get("RelayState", ""),
                response=True,
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: could not build LogoutResponse: {err}")
            return self.failed_redirect(
                request, error="SAML_SLO_FAILED", message="Could not build LogoutResponse"
            )
        return self._render_binding_response(resp_info)

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
