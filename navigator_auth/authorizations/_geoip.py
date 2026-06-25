"""Country geolocation via the MaxMind GeoLite2 database (optional).

The ``geoip2`` package and a GeoLite2-Country ``.mmdb`` file are only required
when ``USERAGENT_SECURITY`` is enabled. The reader is opened lazily, once, and
cached for the lifetime of the process. Any failure (missing package, missing
database, lookup error) resolves to ``None`` so callers can *fail closed*.
"""
import logging
from ..conf import GEOIP_DATABASE

_reader = None
_loaded = False


def _load_reader():
    """Open the GeoLite2 reader once; return None if unavailable."""
    global _reader, _loaded
    _loaded = True
    try:
        import geoip2.database
    except ImportError:
        logging.warning(
            "authz: USERAGENT_SECURITY requires the 'geoip2' package "
            "(pip install navigator-auth[geoip]); geo-fencing will deny."
        )
        return None
    try:
        _reader = geoip2.database.Reader(GEOIP_DATABASE)
        logging.info(f"authz: GeoIP database loaded from {GEOIP_DATABASE}")
    except (FileNotFoundError, OSError, ValueError) as exc:
        logging.warning(
            f"authz: cannot open GeoIP database '{GEOIP_DATABASE}': {exc}; "
            "geo-fencing will deny."
        )
        _reader = None
    return _reader


def lookup_country(ip: str | None) -> str | None:
    """Return the ISO-3166 country code for ``ip`` (e.g. ``'US'``) or None."""
    if not ip:
        return None
    if not _loaded:
        _load_reader()
    if _reader is None:
        return None
    try:
        return _reader.country(ip).country.iso_code
    except Exception as exc:  # noqa: BLE001 - AddressNotFound, ValueError, etc.
        logging.debug(f"authz: GeoIP lookup miss for {ip}: {exc}")
        return None


def reset_reader() -> None:
    """Drop the cached reader (used by tests)."""
    global _reader, _loaded
    if _reader is not None:
        try:
            _reader.close()
        except Exception:  # noqa: BLE001
            pass
    _reader = None
    _loaded = False
