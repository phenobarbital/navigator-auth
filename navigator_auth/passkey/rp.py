"""Origin → relying-party resolution for passkey ceremonies (FEAT-101)."""

from typing import Optional
from urllib.parse import urlsplit

from aiohttp import web
from pydantic import ValidationError

from ..exceptions import ConfigError, InvalidAuth
from .types import RelyingParty


def _normalise_origin(value: Optional[str], *, allow_path: bool = False) -> Optional[str]:
    """Return ``scheme://host[:port]`` lowercased, or ``None`` if not a bare origin.

    Args:
        value: Raw origin (or URL when ``allow_path`` is True, e.g. a Referer).
        allow_path: Accept a path/query/fragment and discard it (Referer fallback).
    """
    if not value:
        return None
    value = value.strip()
    if not value or value.lower() == "null":
        return None
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http") or not parts.netloc or not hostname:
        return None
    if "@" in parts.netloc:  # userinfo
        return None
    if not allow_path and (parts.path not in ("", "/") or parts.query or parts.fragment):
        return None
    host = hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port is not None else "")


class RelyingPartyResolver:
    """Exact-match ``Origin`` → ``RelyingParty`` allow-list. Never reads Host / X-Forwarded-*."""

    def __init__(self, parties: list[dict]) -> None:
        """Validate entries into ``RelyingParty``.

        Raises:
            ConfigError: When the map is empty, an entry is invalid, or an origin repeats.
        """
        if not parties:
            raise ConfigError("PasskeyAuth: PASSKEY_RELYING_PARTIES is empty.")
        self._by_origin: dict[str, RelyingParty] = {}
        self._by_rp_id: dict[str, RelyingParty] = {}
        for idx, entry in enumerate(parties):
            try:
                party = RelyingParty.model_validate(entry)
            except ValidationError as err:
                raise ConfigError(f"PasskeyAuth: invalid PASSKEY_RELYING_PARTIES[{idx}]: {err}") from err
            origin = _normalise_origin(party.origin)
            if origin is None:
                raise ConfigError(
                    f"PasskeyAuth: invalid origin in PASSKEY_RELYING_PARTIES[{idx}]: " f"{party.origin!r}"
                )
            if origin in self._by_origin:
                raise ConfigError(f"PasskeyAuth: duplicate origin in PASSKEY_RELYING_PARTIES[{idx}]: " f"{origin!r}")
            party = party.model_copy(update={"origin": origin})
            self._by_origin[origin] = party
            self._by_rp_id.setdefault(party.rp_id, party)

    def resolve(self, request: web.Request) -> RelyingParty:
        """Return the RP for the request's ``Origin`` (``Referer`` origin as exact fallback).

        Raises:
            InvalidAuth: 401 when the origin is absent, ``null`` or not allow-listed.
        """
        raw = request.headers.get("Origin")
        if raw is not None:
            origin = _normalise_origin(raw)
        else:
            origin = _normalise_origin(request.headers.get("Referer"), allow_path=True)
        party = self._by_origin.get(origin) if origin else None
        if party is None:
            raise InvalidAuth("Passkey: origin not allowed", status=401)
        return party

    def by_rp_id(self, rp_id: str) -> Optional[RelyingParty]:
        """Return the RP configured for ``rp_id``, or ``None``."""
        return self._by_rp_id.get(rp_id)
