"""AbstractSAMLIdentityProvider — the IdP role (FEAT-097 §2/§3 Module 5).

Issues signed SAML assertions for the *current* Navigator session to
env-registered SPs (`ServiceProviderConfig`). Loaded through the same
`AUTHENTICATION_BACKENDS` mechanism as every other backend for lifecycle
(`configure`, `on_startup`, `on_cleanup`), but never authenticates anyone:
it defines no `auth_middleware`, sets `_external_auth = False`, and hides
itself from the auth-methods listing (`hidden = True`).

This module (TASK-058) covers the registry, IdP metadata, and the
IdP-initiated flow (`initiate`/`issue_assertion`). SP-initiated `sso` and
`slo` are TASK-059 (placeholders here raise 501).
"""
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as aioredis
from aiohttp import web

from ...conf import (
    AUTH_EXCLUDE_LIST_KEY,
    REDIS_AUTH_URL,
    SAML_IDP_REQUIRE_AUTH_METHODS,
)
from ...exceptions import ConfigError
from ...identity.flow_store import IdentityFlowStore
from .core import SAMLCore
from .types import SAMLKeyPair, ServiceProviderConfig

from ..abstract import BaseAuthBackend


class AbstractSAMLIdentityProvider(BaseAuthBackend, ABC):
    """Abstract SAML 2.0 Identity Provider backend on `pysaml2`."""

    _service_name: str = "saml-idp"
    _external_auth: bool = False
    config_prefix: str = "SAML_IDP"
    hidden: bool = True
    _description: str = "SAML 2.0 Identity Provider"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.core = SAMLCore(
            prefix=self.config_prefix,
            settings=self.get_settings(),
            role="idp",
            logger=self.logger,
        )
        self._sp_registry: dict = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def configure(self, app):
        super().configure(app)
        router = app.router
        # Session required (not excluded from the auth middleware chain).
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/initiate/{{sp_id}}",
            self.initiate,
            name=f"{self._service_name}_initiate",
        )
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/metadata",
            self.metadata,
            name=f"{self._service_name}_metadata",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/auth/{self._service_name}/metadata")
        # TASK-059 placeholders.
        router.add_route(
            "*",
            f"/auth/{self._service_name}/sso",
            self.sso,
            name=f"{self._service_name}_sso",
        )
        router.add_route(
            "*",
            f"/auth/{self._service_name}/slo",
            self.slo,
            name=f"{self._service_name}_slo",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/auth/{self._service_name}/sso")
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/auth/{self._service_name}/slo")

    async def on_startup(self, app: web.Application):
        self.core.check_xmlsec()
        self.core.load_keypair(self.get_keypair())
        self._sp_registry = self._parse_service_providers()
        self._pool = aioredis.ConnectionPool.from_url(
            REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        self._flow_store = IdentityFlowStore(self._pool)

    async def on_cleanup(self, app: web.Application):
        self.core.shutdown()
        try:
            await self._pool.disconnect(inuse_connections=True)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(err)
        if hasattr(self, "_background_tasks"):
            for task in self._background_tasks:
                task.cancel()
            if self._background_tasks:
                await asyncio.gather(*self._background_tasks, return_exceptions=True)

    def _parse_service_providers(self) -> dict:
        """Parse and validate `get_service_providers()` at startup:
        duplicate `sp_id` or a config that fails `ServiceProviderConfig`
        validation both raise `ConfigError`."""
        raw = self.get_service_providers()
        registry = {}
        seen_sp_ids = set()
        for sp_id, sp in raw.items():
            if isinstance(sp, dict):
                sp = ServiceProviderConfig.from_dict(sp)
            if sp.sp_id in seen_sp_ids:
                raise ConfigError(
                    f"SAML IdP: duplicate sp_id in service provider registry: {sp.sp_id!r}"
                )
            seen_sp_ids.add(sp.sp_id)
            registry[sp_id] = sp
        return registry

    # ------------------------------------------------------------------
    # Inert auth surface — this backend never authenticates anyone.
    # ------------------------------------------------------------------
    async def authenticate(self, request: web.Request):
        return None

    async def check_credentials(self, request: web.Request):
        return False

    async def get_payload(self, request: web.Request):
        return None

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------
    async def metadata(self, request: web.Request) -> web.Response:
        domain_url = self.get_domain(request)
        xml = await self.core.run(self.core.idp_metadata, domain_url)
        return web.Response(text=xml, content_type="text/xml")

    # ------------------------------------------------------------------
    # IdP-initiated SSO
    # ------------------------------------------------------------------
    async def initiate(self, request: web.Request) -> web.Response:
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            raise self.Unauthorized(reason="SAML_NOT_AUTHENTICATED")

        sp_id = request.match_info.get("sp_id")
        sp = self._sp_registry.get(sp_id)
        if sp is None:
            # 404, generic body: never reveal which SPs exist.
            raise web.HTTPNotFound(reason="SAML_UNKNOWN_SP")

        if SAML_IDP_REQUIRE_AUTH_METHODS:
            auth_method = getattr(user, "auth_method", None) or request.get("auth_method")
            if auth_method not in SAML_IDP_REQUIRE_AUTH_METHODS:
                self._audit_sp_forbidden(request, sp, user)
                raise self.ForbiddenAccess(reason="SAML_SP_FORBIDDEN")

        if not await self.authorize_sp_access(request, user, sp):
            self._audit_sp_forbidden(request, sp, user)
            raise self.ForbiddenAccess(reason="SAML_SP_FORBIDDEN")

        qs = self.queryparams(request) or {}
        extra_hosts = list(sp.allowed_relay_hosts)
        from urllib.parse import urlparse

        acs_host = urlparse(sp.acs_url).netloc
        if acs_host:
            extra_hosts.append(acs_host)
        relay = self.validate_redirect_host(qs.get("RelayState"), extra_hosts=extra_hosts)

        return await self.issue_assertion(request, sp, user, relay_state=relay)

    async def issue_assertion(
        self,
        request: web.Request,
        sp: ServiceProviderConfig,
        user,
        in_response_to: Optional[str] = None,
        relay_state: Optional[str] = None,
    ) -> web.Response:
        """Build, sign, audit, and render the auto-POST form to `sp.acs_url`."""
        from saml2 import BINDING_HTTP_POST
        from saml2.saml import AUTHN_PASSWORD, NameID
        from saml2.time_util import instant

        domain_url = self.get_domain(request)
        attrs = await self.build_attributes(user, sp)
        name_id_value = await self.get_nameid(user, sp)
        server = await self.core.idp_server(domain_url)
        name_id = NameID(format=sp.name_id_format, text=name_id_value)
        not_on_or_after = datetime.now(tz=timezone.utc) + timedelta(seconds=sp.assertion_ttl)

        try:
            resp = await self.core.run(
                server.create_authn_response,
                attrs,
                in_response_to,
                sp.acs_url,
                sp.entity_id,
                name_id=name_id,
                sign_assertion=sp.sign_assertion,
                sign_response=sp.sign_response,
                session_not_on_or_after=instant(time_stamp=int(not_on_or_after.timestamp())),
                authn={"class_ref": AUTHN_PASSWORD, "authn_auth": server.config.entityid},
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"{self._service_name}: could not issue assertion: {err}")
            raise web.HTTPInternalServerError(reason="SAML_INVALID_RESPONSE") from err

        http_args = await self.core.run(
            server.apply_binding, BINDING_HTTP_POST, str(resp), sp.acs_url, relay_state or "",
            response=True,
        )
        assertion_id = getattr(resp, "id", None)
        self._audit_issued(request, sp, user, assertion_id, not_on_or_after)

        html = self._render_autosubmit_form(http_args)
        return web.Response(
            text=html,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    def _render_autosubmit_form(self, http_args: dict) -> str:
        """`apply_binding(..., BINDING_HTTP_POST, response=True)` already
        renders a POST-binding HTML form (`data`); pysaml2's default form
        includes an inline `onload` auto-submit plus a manual submit
        button, safe under a CSP that allows this response's own inline
        script (no external script src)."""
        data = http_args.get("data")
        return data if isinstance(data, str) else "".join(data or [])

    def _audit_issued(self, request, sp, user, assertion_id, not_on_or_after) -> None:
        user_id = getattr(user, "user_id", None) or getattr(user, "id", None)
        self.logger.info(
            "saml.assertion.issued "
            f"sp_id={sp.sp_id} entity_id={sp.entity_id} user_id={user_id} "
            f"assertion_id={assertion_id} not_on_or_after={not_on_or_after.isoformat()} "
            f"remote={getattr(request, 'remote', None)}"
        )

    def _audit_sp_forbidden(self, request, sp, user) -> None:
        user_id = getattr(user, "user_id", None) or getattr(user, "id", None)
        self.logger.warning(
            f"saml.sp.forbidden sp_id={sp.sp_id} user_id={user_id} "
            f"remote={getattr(request, 'remote', None)}"
        )

    # ------------------------------------------------------------------
    # SP-initiated SSO / SLO — TASK-059
    # ------------------------------------------------------------------
    async def sso(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="SAML SP-initiated SSO is implemented in TASK-059")

    async def slo(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="SAML IdP-side SLO is implemented in TASK-059")

    # ------------------------------------------------------------------
    # Provider hooks
    # ------------------------------------------------------------------
    @abstractmethod
    def get_service_providers(self) -> dict:
        """`{sp_id: ServiceProviderConfig}` (env-declared SP registry)."""

    @abstractmethod
    async def build_attributes(self, user, sp: ServiceProviderConfig) -> dict:
        """SAML attribute statement for `user`, scoped to `sp`."""

    async def get_nameid(self, user, sp: ServiceProviderConfig) -> str:
        """Default: `user.email` for the emailAddress format, else
        `user.username`."""
        if "emailAddress" in sp.name_id_format:
            return getattr(user, "email", None) or getattr(user, "username", "")
        return getattr(user, "username", None) or getattr(user, "email", "")

    async def authorize_sp_access(self, request: web.Request, user, sp: ServiceProviderConfig) -> bool:
        """Default: allow. `False` -> `SAML_SP_FORBIDDEN`, nothing rendered."""
        return True

    def get_keypair(self) -> SAMLKeyPair:
        from navconfig import config as nav_config

        key_file = nav_config.get(f"{self.config_prefix}_KEY_FILE", fallback=None)
        cert_file = nav_config.get(f"{self.config_prefix}_CERT_FILE", fallback=None)
        passphrase = nav_config.get(f"{self.config_prefix}_KEY_PASSPHRASE", fallback=None)
        if not key_file or not cert_file:
            raise ConfigError(
                f"SAML IdP: {self.config_prefix}_KEY_FILE/{self.config_prefix}_CERT_FILE "
                "are required for the IdP role."
            )
        return SAMLKeyPair(key_file=key_file, cert_file=cert_file, passphrase=passphrase)

    def get_settings(self) -> Optional[dict]:
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
