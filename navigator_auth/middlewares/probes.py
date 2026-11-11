"""Detect hosts that repeatedly probe the server without authentication.

One unauthenticated request answered with a 4xx is normal; many from the
same client in a short time is a scanner or a brute-force attempt (``/.env``,
``/owa/auth/logon.aspx``, ``/api/v1/pods``, bad tokens...). ``ProbeTracker``
counts them per client IP over a sliding window and logs one security warning
when a host crosses the threshold, then stays quiet about that host until the
cooldown has passed.

``protected_paths_middleware`` (the outermost middleware) feeds the shared
tracker through ``track_rejection``, so it works with or without ABAC.

Hosts inside ``AUTH_PROBE_IGNORE_IPS`` (e.g. a load balancer's health
checks) are never counted.

State lives in memory, per worker process: with several workers each one
counts its own share of the traffic.
"""
import ipaddress
import logging
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from aiohttp import web
from ..authorizations._client_ip import (
    IPNetwork,
    get_client_ip,
    parse_networks,
    parse_proxies,
)
from ..conf import (
    AUTH_PROBE_COOLDOWN,
    AUTH_PROBE_IGNORE_IPS,
    AUTH_PROBE_MAX_HOSTS,
    AUTH_PROBE_THRESHOLD,
    AUTH_PROBE_WINDOW,
    ALLOWED_IP_TRUSTED_PROXIES,
)

SECURITY_LOGGER = "navigator_auth.security"

# Longest path kept for the log line, so a huge URL cannot flood the logs.
_MAX_PATH_LENGTH = 200


@dataclass
class _HostRecord:
    """Recent rejected requests seen from one client IP."""

    hits: deque[float]
    paths: deque[str]
    total: int = 0
    last_alert: float | None = field(default=None)


class ProbeTracker:
    """Count rejected unauthenticated requests per client IP and warn on bursts.

    Args:
        threshold: Rejected requests within ``window`` that trigger a warning.
            ``0`` (or less) disables tracking.
        window: Sliding window length, in seconds.
        cooldown: Seconds before the same host can be reported again.
        max_hosts: Hosts kept in memory; the least recently seen host is
            dropped first, so a distributed scan cannot exhaust memory.
        ignored: Networks whose hosts are never counted (load balancer
            health checks, monitoring probes...).
        clock: Monotonic time source, injectable for tests.
        logger: Logger for the warning; defaults to ``navigator_auth.security``.
    """

    SAMPLE_PATHS = 5

    def __init__(
        self,
        threshold: int,
        window: float,
        cooldown: float,
        max_hosts: int,
        ignored: Iterable[IPNetwork] = (),
        clock: Callable[[], float] = time.monotonic,
        logger: logging.Logger | None = None,
    ) -> None:
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.max_hosts = max(1, max_hosts)
        self.ignored = tuple(ignored)
        self._clock = clock
        self.logger = logger or logging.getLogger(SECURITY_LOGGER)
        self._hosts: OrderedDict[str, _HostRecord] = OrderedDict()

    @property
    def enabled(self) -> bool:
        """Whether tracking is active (threshold greater than zero)."""
        return self.threshold > 0

    def is_ignored(self, host: str) -> bool:
        """Whether ``host`` falls inside one of the ignored networks.

        Args:
            host: Client IP address.

        Returns:
            True when the host must not be counted.
        """
        if not self.ignored:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        # Dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d.
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address in network for network in self.ignored)

    def record(self, host: str, path: str, status: int) -> bool:
        """Record one rejected unauthenticated request from ``host``.

        Args:
            host: Client IP address.
            path: Requested path (attacker-controlled; only logged with repr).
            status: HTTP status of the rejection.

        Returns:
            True when this request made the host cross the threshold and a
            warning was logged.
        """
        if not self.enabled or self.is_ignored(host):
            return False
        now = self._clock()
        record = self._hosts.get(host)
        if record is None:
            record = _HostRecord(
                hits=deque(maxlen=self.threshold),
                paths=deque(maxlen=self.SAMPLE_PATHS),
            )
            self._hosts[host] = record
            if len(self._hosts) > self.max_hosts:
                self._hosts.popitem(last=False)
        else:
            self._hosts.move_to_end(host)
        record.hits.append(now)
        record.total += 1
        path = path[:_MAX_PATH_LENGTH]
        if path not in record.paths:
            record.paths.append(path)
        # ``hits`` keeps the last ``threshold`` timestamps: the burst is real
        # when it is full and its oldest entry is still inside the window.
        elapsed = now - record.hits[0]
        if len(record.hits) < self.threshold or elapsed > self.window:
            return False
        if record.last_alert is not None and now - record.last_alert < self.cooldown:
            return False
        record.last_alert = now
        self.logger.warning(
            "Security: host %s made %d unauthenticated requests rejected "
            "within %.0fs (%d in total, last status %d); possible scan or "
            "attack. Recent paths: %r",
            host,
            self.threshold,
            elapsed,
            record.total,
            status,
            list(record.paths),
        )
        return True

    def reset(self) -> None:
        """Forget every tracked host."""
        self._hosts.clear()


# Shared, process-wide tracker and the proxies allowed to set X-Forwarded-For.
probe_tracker = ProbeTracker(
    threshold=AUTH_PROBE_THRESHOLD,
    window=AUTH_PROBE_WINDOW,
    cooldown=AUTH_PROBE_COOLDOWN,
    max_hosts=AUTH_PROBE_MAX_HOSTS,
    ignored=parse_networks(AUTH_PROBE_IGNORE_IPS, "AUTH_PROBE_IGNORE_IPS"),
)
trusted_proxies = parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)


def client_ip(request: web.Request) -> str | None:
    """Return the real client IP, honouring ``ALLOWED_IP_TRUSTED_PROXIES``."""
    return get_client_ip(request, trusted_proxies)


def track_rejection(request: web.Request, status: int) -> None:
    """Count a 4xx answer against the request's client IP.

    Args:
        request: The rejected request.
        status: HTTP status sent back; only 4xx statuses are counted.
    """
    if not probe_tracker.enabled or not 400 <= status < 500:
        return
    # No usable forwarded address (e.g. only trusted hops): count the peer.
    host = client_ip(request) or request.remote
    if host:
        probe_tracker.record(host, request.path, status)
