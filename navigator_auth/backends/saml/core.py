"""SAMLCore: the single module allowed to touch `pysaml2` configuration and
blocking calls (FEAT-097 §2/§3 Module 2).

Both `AbstractSAMLBackend` (SP role, TASK-056/057) and
`AbstractSAMLIdentityProvider` (IdP role, TASK-058/059) consume this through
a small API: build a `pysaml2` config for a request's domain, get a cached
`Saml2Client`/`Server`, run a blocking call off the event loop, render
metadata, flatten attributes, validate redirects, and compute the
flow-store/replay-cache keys shared by both roles.
"""
import asyncio
import copy
import shutil
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Iterable, Literal, Optional

from navconfig import config as nav_config

from ... import conf
from ...conf import SAML_XMLSEC_BINARY
from ...exceptions import ConfigError

_XMLSEC_BINARY_NAMES = ("xmlsec1",)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into ``base``, returning ``base``.

    Only dict values are merged recursively; any other type (including
    lists/tuples) in ``override`` replaces the value in ``base`` outright.
    """
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


class SAMLCore:
    """Shared `pysaml2` engine wrapper for the SP and IdP bases.

    Nothing per-request is stored on the core after construction except the
    per-base-URL client/server cache (write-once per key); backends are
    process-wide singletons, so no per-flow state ever lives on ``self``.
    """

    def __init__(
        self,
        *,
        prefix: str,
        settings: Optional[dict],
        role: Literal["sp", "idp"],
        logger=None,
        executor_workers: int = None,
    ):
        self.prefix = prefix
        self.settings = settings or {}
        self.role = role
        self.logger = logger
        # Default service slug matches the existing `_service_name`
        # convention ("SAML" -> "saml", "SAML_IDP" -> "saml-idp") so the
        # bases' default `_service_name` and the core-derived URLs agree
        # without a redundant constructor parameter.
        self.svc = prefix.lower().replace("_", "-")
        self._executor_workers = executor_workers or conf.SAML_EXECUTOR_WORKERS
        self._executor = ThreadPoolExecutor(max_workers=self._executor_workers)
        # Per-base-URL client/server cache; written once per key, never
        # mutated afterwards.
        self._sp_clients: dict = {}
        self._idp_servers: dict = {}

    # ------------------------------------------------------------------
    # Config resolution: <prefix>_<NAME> env override, falling back to the
    # already-parsed `navigator_auth.conf.SAML_<NAME>` default. This makes
    # `config_prefix` overrides (e.g. `VERIZON_SAML`) transparent: the
    # generic `SAMLAuth`/`SAMLIdentityProvider` use `prefix == "SAML"` /
    # `"SAML_IDP"`, which resolve to themselves.
    # ------------------------------------------------------------------
    def _conf(self, name: str, default: Any = None) -> Any:
        override = nav_config.get(f"{self.prefix}_{name}", fallback=None)
        if override is not None:
            return override
        return getattr(conf, f"SAML_{name}", default)

    def _log(self, level: str, message: str) -> None:
        if self.logger is not None:
            getattr(self.logger, level, self.logger.debug)(message)

    # ------------------------------------------------------------------
    # Config building
    # ------------------------------------------------------------------
    def build_config(self, base_url: str) -> dict:
        """Build the `pysaml2` config dict for this request's domain.

        Entity ID and every endpoint are derived from ``base_url`` so two
        calls with different domains never share instance state; the
        `settings` dict passed at construction (or `get_settings()` on the
        owning backend) is deep-merged last and always wins.
        """
        # Local import: avoids importing `pysaml2` (and, transitively,
        # `xmlsec1`-dependent modules) at package-import time for callers
        # that only need `SAMLCore` for its non-pysaml2 helpers.
        from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
        from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED

        base_url = base_url.rstrip("/")
        accepted_time_diff = int(self._conf("CLOCK_SKEW", 60))
        xmlsec_binary = self._conf("XMLSEC_BINARY", None) or shutil.which("xmlsec1")

        cnf: dict = {
            "xmlsec_binary": xmlsec_binary,
            "accepted_time_diff": accepted_time_diff,
            "allow_unknown_attributes": True,
            "delete_tmpfiles": True,
        }

        if self.role == "sp":
            entity_id = f"{base_url}/auth/{self.svc}/metadata"
            acs_url = f"{base_url}/auth/{self.svc}/callback/"
            slo_url = f"{base_url}/auth/{self.svc}/logout"
            cnf["entityid"] = entity_id
            key_file = self._conf("SP_KEY_FILE", None)
            cert_file = self._conf("SP_CERT_FILE", None)
            if key_file:
                cnf["key_file"] = key_file
            if cert_file:
                cnf["cert_file"] = cert_file
            metadata = self._resolve_metadata()
            if metadata:
                cnf["metadata"] = metadata
            cnf["service"] = {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [(acs_url, BINDING_HTTP_POST)],
                        "single_logout_service": [
                            (slo_url, BINDING_HTTP_REDIRECT),
                            (slo_url, BINDING_HTTP_POST),
                        ],
                    },
                    "allow_unsolicited": bool(self._conf("ALLOW_UNSOLICITED", True)),
                    "want_assertions_signed": bool(
                        self._conf("WANT_ASSERTIONS_SIGNED", True)
                    ),
                    "want_response_signed": bool(
                        self._conf("WANT_RESPONSE_SIGNED", False)
                    ),
                }
            }
        else:  # role == "idp"
            entity_id = self._conf("ENTITY_ID", None) or f"{base_url}/auth/{self.svc}/metadata"
            sso_url = f"{base_url}/auth/{self.svc}/sso"
            slo_url = f"{base_url}/auth/{self.svc}/slo"
            cnf["entityid"] = entity_id
            key_file = self._conf("KEY_FILE", None)
            cert_file = self._conf("CERT_FILE", None)
            if key_file:
                cnf["key_file"] = key_file
            if cert_file:
                cnf["cert_file"] = cert_file
            cnf["service"] = {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [
                            (sso_url, BINDING_HTTP_REDIRECT),
                            (sso_url, BINDING_HTTP_POST),
                        ],
                        "single_logout_service": [
                            (slo_url, BINDING_HTTP_REDIRECT),
                            (slo_url, BINDING_HTTP_POST),
                        ],
                    },
                    "name_id_format": [
                        NAMEID_FORMAT_EMAILADDRESS,
                        NAMEID_FORMAT_UNSPECIFIED,
                    ],
                    "sign_response": True,
                    "sign_assertion": True,
                }
            }

        _deep_merge(cnf, copy.deepcopy(self.settings))
        return cnf

    def _resolve_metadata(self) -> Optional[dict]:
        """`metadata` may arrive pre-shaped (pysaml2's own `{"local": [...]}`
        / `{"remote": [...]}` form) through `settings["metadata"]`; that is
        deep-merged in by `build_config` already. `SAMLCore` itself has no
        opinion on *where* the IdP/SP counterpart metadata lives beyond
        that — the owning backend's `get_idp_metadata()` /
        `get_service_providers()` hook decides and passes it in via
        `settings`.
        """
        return None

    # ------------------------------------------------------------------
    # Client/server factories (cached per base URL)
    # ------------------------------------------------------------------
    async def sp_client(self, base_url: str):
        if base_url not in self._sp_clients:
            from saml2.client import Saml2Client
            from saml2.config import SPConfig

            cnf = await self.run(self._load_sp_config, base_url)
            self._sp_clients[base_url] = Saml2Client(config=cnf)
        return self._sp_clients[base_url]

    def _load_sp_config(self, base_url: str):
        from saml2.config import SPConfig

        return SPConfig().load(self.build_config(base_url))

    async def idp_server(self, base_url: str):
        if base_url not in self._idp_servers:
            cnf = await self.run(self._load_idp_config, base_url)
            from saml2.server import Server

            self._idp_servers[base_url] = Server(config=cnf)
        return self._idp_servers[base_url]

    def _load_idp_config(self, base_url: str):
        from saml2.config import IdPConfig

        return IdPConfig().load(self.build_config(base_url))

    # ------------------------------------------------------------------
    # Executor
    # ------------------------------------------------------------------
    async def run(self, fn, *args, **kwargs):
        """Run a blocking `pysaml2`/`xmlsec1` call off the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, partial(fn, *args, **kwargs))

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # Metadata rendering
    # ------------------------------------------------------------------
    def sp_metadata(self, base_url: str) -> str:
        from saml2.config import SPConfig
        from saml2.metadata import entity_descriptor

        cnf = SPConfig().load(self.build_config(base_url))
        return str(entity_descriptor(cnf))

    def idp_metadata(self, base_url: str) -> str:
        from saml2.config import IdPConfig
        from saml2.metadata import entity_descriptor

        cnf = IdPConfig().load(self.build_config(base_url))
        return str(entity_descriptor(cnf))

    # ------------------------------------------------------------------
    # Attribute flattening
    # ------------------------------------------------------------------
    def flatten_attributes(self, attrs: dict, mapping: dict) -> dict:
        """``mapping`` is ``user_field -> saml_attr`` (the existing
        `SAML_MAPPING` shape). A mapping value may be a
        ``{"name": ..., "multi": True}`` dict to keep the full list of
        values; otherwise the first element is used. Unmapped keys in
        ``attrs`` are ignored; a mapped key missing from ``attrs`` is
        logged at warning (mirrors `BaseAuthBackend.get_user_mapping`).
        """
        result = {}
        for field_name, spec in mapping.items():
            if isinstance(spec, dict):
                attr_name = spec.get("name")
                multi = bool(spec.get("multi", False))
            else:
                attr_name = spec
                multi = False
            values = attrs.get(attr_name)
            if values is None:
                self._log(
                    "warning",
                    f"SAMLCore: mapped attribute not present in assertion: {attr_name!r}",
                )
                continue
            if multi:
                result[field_name] = list(values) if isinstance(values, (list, tuple)) else [values]
            elif isinstance(values, (list, tuple)):
                result[field_name] = values[0] if values else None
            else:
                result[field_name] = values
        return result

    # ------------------------------------------------------------------
    # Redirect validation (delegated to BaseAuthBackend.validate_redirect_host)
    # ------------------------------------------------------------------
    def validate_redirect(
        self, validator, uri: Optional[str], extra_hosts: Iterable[str] = ()
    ) -> Optional[str]:
        """Delegate to the owning backend's bound
        ``validate_redirect_host`` method (passed in as ``validator``)."""
        return validator(uri, extra_hosts=extra_hosts)

    # ------------------------------------------------------------------
    # Flow-store / replay-cache key helpers
    # ------------------------------------------------------------------
    @staticmethod
    def req_key(relay: str) -> str:
        return f"saml_req_{relay}"

    @staticmethod
    def assert_key(assertion_id: str) -> str:
        return f"saml_assert_{assertion_id}"

    @staticmethod
    def slo_key(request_id: str) -> str:
        return f"saml_slo_{request_id}"

    @staticmethod
    def idp_key(flow: str) -> str:
        return f"saml_idp_{flow}"

    # ------------------------------------------------------------------
    # xmlsec1 / key-pair validation
    # ------------------------------------------------------------------
    def check_xmlsec(self) -> None:
        """Raise `ConfigError` naming the binary and the setting when the
        `xmlsec1` binary cannot be found."""
        configured = nav_config.get(f"{self.prefix}_XMLSEC_BINARY", fallback=None) or SAML_XMLSEC_BINARY
        binary = configured or shutil.which("xmlsec1")
        if not binary:
            raise ConfigError(
                "SAML: the 'xmlsec1' binary was not found. Install the "
                "xmlsec1 system package or set SAML_XMLSEC_BINARY to its path."
            )

    def load_keypair(self, pair) -> None:
        """Read PEM files and validate they parse with `cryptography`."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        try:
            with open(pair.key_file, "rb") as f:
                load_pem_private_key(
                    f.read(),
                    password=pair.passphrase.encode() if pair.passphrase else None,
                )
        except (OSError, ValueError) as exc:
            raise ConfigError(f"SAML: unable to load key file {pair.key_file!r}: {exc}") from exc
        try:
            from cryptography import x509

            with open(pair.cert_file, "rb") as f:
                x509.load_pem_x509_certificate(f.read())
        except (OSError, ValueError) as exc:
            raise ConfigError(f"SAML: unable to load cert file {pair.cert_file!r}: {exc}") from exc

    # ------------------------------------------------------------------
    # Metadata reload (SP role: IdP metadata; both roles reload their own
    # cached client/server so key/cert rotation on disk is picked up)
    # ------------------------------------------------------------------
    def start_metadata_reload(self, loop: asyncio.AbstractEventLoop, interval: int, task_set: set) -> Optional[asyncio.Task]:
        """Create a background task that rebuilds cached clients/servers
        every ``interval`` seconds (``0`` disables reload)."""
        if not interval:
            return None

        async def _reload_loop():
            while True:
                await asyncio.sleep(interval)
                self._sp_clients.clear()
                self._idp_servers.clear()
                self._log("debug", "SAMLCore: cached client/server cache cleared for reload")

        task = loop.create_task(_reload_loop())
        task_set.add(task)
        return task
