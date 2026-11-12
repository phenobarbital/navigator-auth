"""End-to-end Passkey (WebAuthn) example.

A single aiohttp application with a one-page client, so the whole passkey life
cycle can be walked through in one browser tab with nothing but Redis:

  1. sign in with a password (``BasicAuth``) — enrollment needs a session;
  2. enroll a passkey (``/api/v1/auth/passkey/register/*``);
  3. list, rename and delete the passkeys of the signed-in user;
  4. sign out, then sign in with the passkey only
     (``/api/v1/auth/passkey/login/options`` + ``POST /api/v1/login`` with
     ``X-Auth-Method: PasskeyAuth``);
  5. call ``GET /api/v1/me``, which shows ``auth_method`` / ``mfa`` / ``amr``.

Run it **from the repository root**::

    pip install "navigator-auth[passkey]"       # installs webauthn (py_webauthn)
    mkdir -p env/dev && touch env/dev/.env      # navconfig needs this once
    redis-server --daemonize yes                # sessions and challenges live in Redis
    python examples/passkey_server.py

then open http://localhost:5000/ — use ``localhost``, not ``127.0.0.1``: the
relying party is bound to the exact origin, and browsers only allow WebAuthn on
plain http for ``localhost``. Demo credentials: ``demo`` / ``demo123``.

Notes
-----
* ``enable_authdb=False`` keeps the example free of PostgreSQL. Three things
  replace the database, and a real deployment drops all three (see
  ``docs/passkey.rst``):

  - :class:`DemoIdentityProvider` instead of ``auth.users``;
  - :class:`MemoryPasskeyStore` instead of ``PasskeyStore`` (the
    ``user_credentials`` / ``user_passkey_handles`` tables);
  - :func:`_memory_transition` instead of the ``authdb`` transaction that wraps
    a credential change.

* Enrolled passkeys are forgotten when the server stops, but they stay on your
  authenticator. Delete them from the page before stopping it (or remove the
  ``localhost`` entries from your password manager afterwards).
* Everything else — option generation, challenge storage and single use,
  attestation and assertion verification, origin / relying-party checks, the
  session and the JWT — is the real ``navigator_auth`` implementation.
"""

import os

# ---------------------------------------------------------------------------
# Environment MUST be set before navconfig / navigator_auth get imported.
# ---------------------------------------------------------------------------
# Passed to AuthHandler(backends=...) as well: navigator_auth.conf ends with
# ``from settings.settings import *``, so local dev settings would otherwise decide
# the backend list. The env var is kept for tools that read it.
_BACKENDS: list[str] = [
    "navigator_auth.backends.BasicAuth",
    "navigator_auth.backends.PasskeyAuth",
]
os.environ.setdefault("AUTHENTICATION_BACKENDS", ",".join(_BACKENDS))
os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me")

import functools  # noqa: E402
import logging  # noqa: E402
import secrets  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, AsyncIterator, Optional  # noqa: E402

import redis.asyncio as aioredis  # noqa: E402
from aiohttp import web  # noqa: E402

import navigator_auth.backends.passkey as passkey_backend  # noqa: E402
import navigator_auth.conf as nav_conf  # noqa: E402
from navigator_auth import AuthHandler  # noqa: E402
from navigator_auth.backends.basic import BasicAuth  # noqa: E402
from navigator_auth.backends.idp import IdentityProvider  # noqa: E402
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY  # noqa: E402
from navigator_auth.decorators import is_authenticated, user_session  # noqa: E402
from navigator_auth.exceptions import ConfigError, UserNotFound  # noqa: E402
from navigator_auth.models import User  # noqa: E402
from navigator_auth.passkey import StoredCredential  # noqa: E402

#: RFC 7518 §3.2: an HS256 key must be at least 32 bytes.
_MIN_SECRET_BYTES = 32

HERE = Path(__file__).parent
STATIC_DIR = HERE / "static"

HOST = os.getenv("EXAMPLE_HOST", "localhost")
PORT = int(os.getenv("EXAMPLE_PORT", "5000"))
BASE_URL = f"http://{HOST}:{PORT}"

#: One relying party: the page this example serves. ``origin`` must be exactly what
#: the browser sends in the ``Origin`` header; ``rp_id`` is the host passkeys are scoped to.
RELYING_PARTIES: list[dict] = [
    {
        "origin": BASE_URL,
        "rp_id": HOST,
        "rp_name": "Navigator Passkey Example",
        "org_id": 1,
        "client_id": 1,
    },
]

DEMO_USERS = [
    {
        "user_id": 1,
        "username": "demo",
        "password": "demo123",
        "first_name": "Demo",
        "last_name": "User",
        "email": "demo@example.com",
    },
    {
        "user_id": 2,
        "username": "alice",
        "password": "alice123",
        "first_name": "Alice",
        "last_name": "Liddell",
        "email": "alice@example.com",
    },
]


def _warn_on_short_secret() -> None:
    """Log a warning when navigator_auth.conf.SECRET_KEY is shorter than 32 bytes.

    The key comes from navconfig (``env/.env`` wins over ``os.environ.setdefault``),
    so the example cannot override it. The key itself is never logged.
    """
    key = nav_conf.SECRET_KEY
    key_length = (
        len(key.encode("utf-8")) if isinstance(key, str) else len(key) if key else 0
    )
    if key_length < _MIN_SECRET_BYTES:
        logging.warning(
            "AUTH_SECRET_KEY is %d bytes; use at least %d bytes.",
            key_length,
            _MIN_SECRET_BYTES,
        )


# ---------------------------------------------------------------------------
# Example-only replacements for the auth database
# ---------------------------------------------------------------------------


class DemoIdentityProvider(IdentityProvider):
    """In-memory :class:`IdentityProvider` (replaces the ``auth.users`` table).

    Only the database-bound lookups are overridden; password hashing and
    verification, token creation and token decoding are the real ones.
    """

    def __init__(self, users: list[dict]) -> None:
        """Build the directory, hashing each password as navigator-auth stores it.

        Args:
            users: Entries with ``user_id``, ``username``, ``password``, names and email.
        """
        super().__init__()
        self._users: dict[str, User] = {}
        for entry in users:
            data = dict(entry)
            raw_password = data.pop("password")
            user = User(
                **data,
                display_name=f"{data['first_name']} {data['last_name']}",
                is_active=True,
                is_superuser=False,
            )
            user.password = self.set_password(raw_password)
            self._users[user.username] = user

    async def get_user(self, login: str) -> Any:
        """Return the user called ``login``, or raise ``UserNotFound``."""
        try:
            return self._users[str(login)]
        except KeyError as exc:
            raise UserNotFound(f"Invalid Credentials for {login!r}") from exc

    async def user_from_id(self, uid: Any, conn: Any = None) -> Any:
        """Return the user whose id is ``uid``, or raise ``UserNotFound`` (``conn`` is unused)."""
        for user in self._users.values():
            if str(user.user_id) == str(uid):
                return user
        raise UserNotFound(f"Invalid Credentials for user_id={uid!r}")


class MemoryPasskeyStore:
    """In-memory stand-in for ``navigator_auth.passkey.PasskeyStore``.

    Same methods and semantics, backed by two dicts instead of the
    ``user_credentials`` and ``user_passkey_handles`` tables. ``conn`` arguments
    are accepted and ignored (there is no transaction to join).
    """

    def __init__(self) -> None:
        self._credentials: dict[bytes, StoredCredential] = {}
        self._handles: dict[tuple[int, str], bytes] = {}

    async def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]:
        """Return one credential by id, or ``None``."""
        return self._credentials.get(bytes(credential_id))

    async def list_credentials(
        self, user_id: int, rp_id: Optional[str] = None
    ) -> list[StoredCredential]:
        """All credentials of a user, optionally limited to one RP, oldest first."""
        return [
            c
            for c in self._credentials.values()
            if c.user_id == user_id and rp_id in (None, c.rp_id)
        ]

    async def save_credential(
        self, credential: StoredCredential, *, conn: Any = None
    ) -> None:
        """Store a newly registered credential."""
        created = credential.model_copy(
            update={"created_at": datetime.now(timezone.utc)}
        )
        self._credentials[credential.credential_id] = created

    async def update_usage(
        self, credential_id: bytes, *, sign_count: int, backed_up: bool
    ) -> None:
        """Raise ``sign_count`` (never lower it), set ``backed_up`` and ``last_used_at``."""
        cred = self._credentials.get(credential_id)
        if cred is not None:
            cred.sign_count = max(cred.sign_count, sign_count)
            cred.backed_up = backed_up
            cred.last_used_at = datetime.now(timezone.utc)

    async def rename_credential(
        self, user_id: int, credential_id: bytes, label: str
    ) -> bool:
        """Rename a credential owned by ``user_id``; True when it exists."""
        cred = self._credentials.get(credential_id)
        if cred is None or cred.user_id != user_id:
            return False
        cred.label = label
        return True

    async def delete_credential(
        self,
        user_id: int,
        credential_id: bytes,
        *,
        keep_last: bool = False,
        conn: Any = None,
    ) -> bool:
        """Delete a credential owned by ``user_id``; with ``keep_last`` never the only one."""
        cred = self._credentials.get(credential_id)
        if cred is None or cred.user_id != user_id:
            return False
        if keep_last and await self.count_credentials(user_id) <= 1:
            return False
        del self._credentials[credential_id]
        return True

    async def count_credentials(self, user_id: int) -> int:
        """Number of credentials of a user across all RPs."""
        return sum(1 for c in self._credentials.values() if c.user_id == user_id)

    async def get_handle(self, user_id: int, rp_id: str) -> Optional[bytes]:
        """The user's WebAuthn user handle for ``rp_id``, or ``None``."""
        return self._handles.get((user_id, rp_id))

    async def get_or_create_handle(self, user_id: int, rp_id: str) -> bytes:
        """Return the user's handle for ``rp_id``, creating a random 32-byte one if absent."""
        return self._handles.setdefault((user_id, rp_id), secrets.token_bytes(32))


@asynccontextmanager
async def _memory_transition(
    app: Any, user_id: int, event: str, **kwargs: Any
) -> AsyncIterator[None]:
    """Stand-in for ``security_transition``: no ``authdb`` transaction to open.

    The real one takes a per-user advisory lock and commits the credential
    change together with the MFA bookkeeping.
    """
    logging.info("Passkey example: %s for user %s", event, user_id)
    yield None


async def _passkey_startup_without_authdb(backend: Any, app: web.Application) -> None:
    """``PasskeyAuth.on_startup`` minus the PostgreSQL store and table check.

    Args:
        backend: The ``PasskeyAuth`` instance being started.
        app: The aiohttp application.

    Raises:
        ConfigError: When the ``passkey`` extra (py_webauthn) is not installed.
    """
    await BasicAuth.on_startup(backend, app)
    try:
        import webauthn  # pylint: disable=C0415
    except ImportError as err:
        raise ConfigError(
            "PasskeyAuth requires the optional extra: pip install navigator-auth[passkey]"
        ) from err
    backend._webauthn = webauthn
    backend._pool = aioredis.ConnectionPool.from_url(
        nav_conf.REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
    )
    backend._store = MemoryPasskeyStore()


# ---------------------------------------------------------------------------
# Application handlers
# ---------------------------------------------------------------------------


async def index(request: web.Request) -> web.StreamResponse:
    """Serve the one-page client."""
    return web.FileResponse(STATIC_DIR / "passkey_app.html")


@is_authenticated()
@user_session()
async def me(
    request: web.Request, *, session: Any = None, user: Any = None
) -> web.StreamResponse:
    """Protected resource: who is signed in, and how they signed in.

    ``auth_method``, ``mfa`` and ``amr`` come from the access token claims; a
    password login reports ``basic``, a passkey login ``passkey``.
    """
    claims = request.get("userdata") or {}
    return web.json_response(
        {
            "message": f"Hello {getattr(user, 'username', 'anonymous')}!",
            "user_id": getattr(user, "user_id", None) or getattr(user, "id", None),
            "username": getattr(user, "username", None),
            "auth_method": claims.get("auth_method"),
            "mfa": claims.get("mfa"),
            "amr": claims.get("amr"),
        }
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def make_app() -> web.Application:
    """Build the example application (BasicAuth + PasskeyAuth, no PostgreSQL)."""
    app = web.Application()

    _warn_on_short_secret()

    # PasskeyAuth.configure() reads the relying parties from navigator_auth.conf.
    nav_conf.PASSKEY_RELYING_PARTIES = RELYING_PARTIES

    # ``authz_backends=[]``: an inherited ``allow_hosts`` (ALLOWED_HOSTS defaults to
    # ``localhost*``) would let every browser request through without a session.
    # ``secure_cookies=False``: the page authenticates with the bearer token from the
    # login response, so the flow does not depend on a Secure cookie over plain http.
    auth = AuthHandler(
        backends=_BACKENDS, authz_backends=[], enable_authdb=False, secure_cookies=False
    )

    demo_idp = DemoIdentityProvider(DEMO_USERS)
    auth._idp = demo_idp
    for backend in auth.backends.values():
        backend._idp = demo_idp
        # A local settings module may register AUTH_SUCCESSFUL_CALLBACKS that query the
        # auth database on every login; the demo users do not live there.
        backend._success_callbacks = None

    # Example-only: run PasskeyAuth without ``app["authdb"]`` (see the module docstring).
    passkey = auth.backends["PasskeyAuth"]
    passkey.on_startup = functools.partial(_passkey_startup_without_authdb, passkey)
    passkey_backend.security_transition = _memory_transition

    auth.setup(app)

    app.router.add_get("/", index, name="index")
    app.router.add_get("/api/v1/me", me, name="me")
    app[AUTH_EXCLUDE_LIST_KEY].append("/")

    app.on_startup.append(_print_banner)
    return app


async def _print_banner(app: web.Application) -> None:
    """Tell the operator where to go once the server is up."""
    print(
        f"\n  Open {BASE_URL}/ (use this exact host: passkeys are bound to the origin)."
    )
    print("  Demo credentials: demo / demo123\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(make_app(), host=HOST, port=PORT)
