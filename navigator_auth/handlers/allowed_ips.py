"""Allowed-IPs Management Handler.

Adds public IPs / CIDR ranges at runtime to the ``authz_allowed_ips``
authorization backend so they are excluded (allowed) from the authnz
flow. The endpoint is restricted to members of the ``superuser`` group
and only answers POST requests.
"""
import ipaddress
import logging
from aiohttp import web
from navigator.views import BaseView
from navigator_auth.decorators import allowed_groups
from navigator_auth.responses import JSONResponse
from navigator_auth.authorizations.allowed_ips import authz_allowed_ips


@allowed_groups(groups=["superuser"])
class AllowedIPHandler(BaseView):
    """AllowedIPHandler.

    Register public IP addresses or CIDR ranges into the ``allowed_ips``
    authorization backend at runtime. Newly added networks are honored
    immediately by ``authz_allowed_ips.check_authorization``.

    Security:
        Restricted to the ``superuser`` group via the ``allowed_groups``
        decorator. Only the ``POST`` method is exposed.

    Request body (JSON)::

        {"ips": ["203.0.113.10", "198.51.100.0/24"]}

    or a single entry::

        {"ip": "203.0.113.10"}
    """

    def _get_ip_backend(self) -> authz_allowed_ips | None:
        """Locate the ``authz_allowed_ips`` backend on the AuthHandler."""
        auth = self.request.app.get("auth")
        if auth is None:
            return None
        for backend in getattr(auth, "_authz_backends", []):
            if isinstance(backend, authz_allowed_ips):
                return backend
        return None

    async def post(self) -> web.StreamResponse:
        """Add one or more public IPs/CIDRs to the allowed_ips backend."""
        try:
            data = await self.request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(
                {"message": "Invalid or missing JSON body."}, status=400
            )

        # Accept either a list under "ips" or a single "ip"/"cidr" entry:
        entries = data.get("ips")
        if entries is None:
            single = data.get("ip") or data.get("cidr")
            entries = [single] if single else []
        if isinstance(entries, str):
            entries = [entries]

        if not entries:
            return JSONResponse(
                {"message": "No IPs provided. Send 'ips' (list) or 'ip'."},
                status=400,
            )

        # Validate up-front so we can report the invalid ones explicitly:
        valid: list[str] = []
        invalid: list[str] = []
        for entry in entries:
            try:
                ipaddress.ip_network(str(entry).strip(), strict=False)
                valid.append(str(entry).strip())
            except (ValueError, TypeError):
                invalid.append(entry)

        if not valid:
            return JSONResponse(
                {
                    "message": "No valid IP/CIDR entries provided.",
                    "invalid": invalid,
                },
                status=400,
            )

        backend = self._get_ip_backend()
        if backend is None:
            return JSONResponse(
                {
                    "message": (
                        "allowed_ips backend is not enabled "
                        "(add it to AUTHORIZATION_BACKENDS)."
                    )
                },
                status=409,
            )

        added = backend.add_networks(valid)
        logging.info(
            "AllowedIPHandler: superuser added %s allowed IP/CIDR ranges",
            added,
        )
        return JSONResponse(
            {
                "message": f"Added {added} IP/CIDR range(s) to allowed_ips.",
                "added": added,
                "accepted": valid,
                "invalid": invalid,
            },
            status=201,
        )
