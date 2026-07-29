"""Geolocation via the MaxMind GeoLite2 databases (optional).

Two independent, lazily-opened readers:

- **Country** (``GEOIP_DATABASE`` → GeoLite2-Country): :func:`lookup_country`
  returns an ISO country code, used by ``USERAGENT_SECURITY`` geo-fencing.
- **City** (``GEOIP_CITY_DATABASE`` → GeoLite2-City): :func:`lookup_location`
  returns ``(latitude, longitude)``. Only the City database carries
  coordinates. Used as a GPS-off fallback (cell/city granularity) — e.g.
  stamping a punch's lat/lon when a client sends no GPS.

The ``geoip2`` package and the ``.mmdb`` files are optional
(``pip install navigator-auth[geoip]``). Any failure (missing package,
missing database, lookup error) resolves to ``None`` so callers *fail
closed* / degrade gracefully.
"""
import logging
from ..conf import GEOIP_DATABASE, GEOIP_CITY_DATABASE

_reader = None
_loaded = False

_city_reader = None
_city_loaded = False


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


def _load_city_reader():
    """Open the GeoLite2-City reader once; return None if unavailable."""
    global _city_reader, _city_loaded
    _city_loaded = True
    try:
        import geoip2.database
    except ImportError:
        logging.warning(
            "authz: IP geolocation requires the 'geoip2' package "
            "(pip install navigator-auth[geoip]); lookup_location returns None."
        )
        return None
    try:
        _city_reader = geoip2.database.Reader(GEOIP_CITY_DATABASE)
        logging.info(f"authz: GeoIP City database loaded from {GEOIP_CITY_DATABASE}")
    except (FileNotFoundError, OSError, ValueError) as exc:
        logging.warning(
            f"authz: cannot open GeoIP City database '{GEOIP_CITY_DATABASE}': "
            f"{exc}; lookup_location returns None."
        )
        _city_reader = None
    return _city_reader


def lookup_location(ip: str | None) -> tuple[float, float] | None:
    """Return ``(latitude, longitude)`` for ``ip`` at city granularity, or None.

    Uses the GeoLite2-City database (``GEOIP_CITY_DATABASE``) — distinct from the
    country database used by :func:`lookup_country`, since only the City database
    carries coordinates. Fail-safe: a missing package/database, an unknown
    address, or an entry without coordinates all resolve to ``None`` so callers
    degrade gracefully (e.g. store null coords rather than blocking a punch).
    """
    if not ip:
        return None
    if not _city_loaded:
        _load_city_reader()
    if _city_reader is None:
        return None
    try:
        loc = _city_reader.city(ip).location
        if loc is None or loc.latitude is None or loc.longitude is None:
            return None
        return (loc.latitude, loc.longitude)
    except Exception as exc:  # noqa: BLE001 - AddressNotFound, ValueError, etc.
        logging.debug(f"authz: GeoIP City lookup miss for {ip}: {exc}")
        return None


def reset_reader() -> None:
    """Drop the cached readers (used by tests)."""
    global _reader, _loaded, _city_reader, _city_loaded
    if _reader is not None:
        try:
            _reader.close()
        except Exception:  # noqa: BLE001
            pass
    _reader = None
    _loaded = False
    if _city_reader is not None:
        try:
            _city_reader.close()
        except Exception:  # noqa: BLE001
            pass
    _city_reader = None
    _city_loaded = False
