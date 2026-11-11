"""Hard deny for system paths, plus per-host tracking of rejected requests.

``protected_paths_middleware`` is installed as the OUTERMOST middleware by
both ``AuthHandler.setup()`` and ``PDP.setup()``. It does two things:

1. Answers 404 to system paths (hidden files, the env/, etc/ and logs/
   directories, config/secret/log/backup/source files) before
   authentication, the auth exclude list, the authorization backends (IP,
   host, User-Agent) or any ABAC/PBAC policy run, so none of them can open
   these paths: a too-permissive policy, a wildcard in the exclude list or a
   disabled ABAC backend all leave the guard in place. The built-in rules
   cannot be switched off; ``AUTH_DENY_PATHS`` only adds patterns.
2. Counts every request that ends unauthenticated with a 4xx (blocked here,
   rejected by authentication, unknown route, refused by a handler) against
   its client IP, so a host that keeps probing is reported once
   (see ``probes.ProbeTracker``), with or without ABAC.

The 404 is the same plain answer an unknown route gets, so a scanner cannot
tell a blocked file from a missing one.
"""
from collections.abc import Awaitable, Callable, Iterable
import contextlib
import fnmatch
import logging
from aiohttp import web
from aiohttp.web_urldispatcher import StaticResource
from .. import conf
from .probes import SECURITY_LOGGER, client_ip, track_rejection

# Hidden segments that are allowed anywhere: RFC 8615 well-known URIs
# (OAuth / OpenID metadata, JWKS, security.txt, ACME challenges).
ALLOWED_DOT_SEGMENTS = frozenset({".well-known"})

# Top-level directories of a navconfig project (env/.env, etc/*.ini, logs/).
DENIED_ROOT_DIRS = frozenset({"env", "etc", "logs"})

# File types that hold configuration, secrets, logs, backups or source code.
DENIED_EXTENSIONS = frozenset({
    "env", "ini", "cfg", "conf", "toml", "yaml", "yml",
    "log",
    "pem", "key", "p12", "pfx", "jks",
    "sql", "sqlite", "sqlite3", "db",
    "bak", "old", "orig", "swp",
    "py", "pyc", "pyo",
})

# Secret files without an extension. Only checked on file-serving routes:
# API routes such as /api/v1/users/credentials must keep working.
DENIED_FILE_NAMES = frozenset({
    "credentials", "passwd", "shadow",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})

# Suffixes looked through before checking the extension: ``dump.sql.gz``,
# ``error.log.1``, ``config.ini.tar``.
_WRAPPER_SUFFIXES = frozenset({"gz", "bz2", "xz", "zst", "zip", "tar", "tgz"})

logger = logging.getLogger(SECURITY_LOGGER)


def _segments(path: str) -> list[str]:
    return [segment for segment in path.lower().split("/") if segment]


def _extension(segment: str) -> str | None:
    """Return the meaningful extension of ``segment``, skipping wrappers."""
    parts = segment.split(".")[1:]
    while parts and (parts[-1].isdigit() or parts[-1] in _WRAPPER_SUFFIXES):
        parts.pop()
    return parts[-1] if parts else None


def protected_path_reason(
    path: str,
    extra_patterns: Iterable[str] = (),
    file_paths: Iterable[str] = (),
) -> str | None:
    """Tell why a request must never be served, or None when it may be.

    Args:
        path: Decoded request path (``request.path``).
        extra_patterns: Additional lower-case fnmatch patterns
            (``AUTH_DENY_PATHS``) matched against the whole path.
        file_paths: Paths relative to a served directory (the ``filename`` of
            a static route, or a ``{tail:.*}``-style route parameter). They
            catch ``/files/etc/passwd`` when a directory is mounted under a
            prefix or in a sub-application.

    Returns:
        A short reason for the log, or None if nothing matches.
    """
    segments = _segments(path)
    for segment in segments:
        if segment == "..":
            return "path traversal"
        if segment.startswith(".") and segment not in ALLOWED_DOT_SEGMENTS:
            return "hidden file or directory"
    if segments and segments[0] in DENIED_ROOT_DIRS:
        return "system directory"
    if segments and _extension(segments[-1]) in DENIED_EXTENSIONS:
        return "sensitive file type"
    for file_path in file_paths:
        parts = _segments(file_path)
        if not parts:
            continue
        if parts[0] in DENIED_ROOT_DIRS:
            return "system directory"
        if parts[-1] in DENIED_FILE_NAMES:
            return "sensitive file name"
    lowered = path.lower()
    for pattern in extra_patterns:
        if fnmatch.fnmatchcase(lowered, pattern):
            return "AUTH_DENY_PATHS pattern"
    return None


def _file_paths(request: web.Request) -> list[str]:
    """Route parameters that name a file inside a served directory."""
    is_static = False
    with contextlib.suppress(AttributeError):
        is_static = isinstance(request.match_info.route.resource, StaticResource)
    return [
        value
        for value in request.match_info.values()
        if isinstance(value, str) and (is_static or "/" in value.strip("/"))
    ]


@web.middleware
async def protected_paths_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """Refuse protected system paths and count unauthenticated 4xx answers."""
    reason = protected_path_reason(request.path, conf.AUTH_DENY_PATHS, _file_paths(request))
    if reason is not None:
        logger.info(
            "Security: blocked %s %r from %s (%s)",
            request.method,
            request.path,
            client_ip(request),
            reason,
        )
        track_rejection(request, web.HTTPNotFound.status_code)
        raise web.HTTPNotFound()
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        if not request.get("authenticated", False):
            track_rejection(request, exc.status)
        raise
    if not request.get("authenticated", False):
        track_rejection(request, response.status)
    return response


def install_protected_paths(app: web.Application) -> None:
    """Make ``protected_paths_middleware`` the first (outermost) middleware.

    Idempotent: calling it again moves the guard back to the front instead of
    adding a second copy.

    Args:
        app: Application being set up (middlewares not frozen yet).
    """
    middlewares = app.middlewares
    if protected_paths_middleware in middlewares:
        middlewares.remove(protected_paths_middleware)
    middlewares.insert(0, protected_paths_middleware)
