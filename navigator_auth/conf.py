"""
Navigator Auth Configuration.
"""
# Import Config Class
import base64
import orjson
from cryptography import fernet
from navconfig import config
from navconfig.logging import logging


############
#
### Authentication System
#
############

## Allowed Hosts
HOSTS = [e.strip() for e in list(config.get("HOSTS", fallback="localhost").split(","))]

## Default Domain
DOMAIN = config.get("DOMAIN", fallback="dev.local")

### DATABASE INFORMATION:
AUTH_DB_SCHEMA = config.get('AUTH_DB_SCHEMA', fallback="auth")
AUTH_USERS_TABLE = config.get("AUTH_USERS_TABLE", fallback="users")
AUTH_USERS_VIEW = config.get("AUTH_USERS_VIEW", fallback="vw_users")

#### Main Database
PG_USER = config.get("DBUSER")
PG_HOST = config.get("DBHOST", fallback="localhost")
PG_PWD = config.get("DBPWD")
PG_DATABASE = config.get("DBNAME", fallback="navigator")
PG_PORT = config.get("DBPORT", fallback=5432)

default_dsn = f"postgres://{PG_USER}:{PG_PWD}@{PG_HOST}:{PG_PORT}/{PG_DATABASE}"

### Exclude List:
excluded_default = [
    "/static/",
    "/api/v1/login",
    "/api/v1/logout",
    "/login",
    "/logout",
    "/signin",
    "/signout",
]
new_excluded = [e.strip() for e in list(config.get("ROUTES_EXCLUDED", fallback="").split(","))]
exclude_list = excluded_default + new_excluded

# if false, force credentials are not required for using this system.
AUTH_CREDENTIALS_REQUIRED = config.getboolean(
    "AUTH_CREDENTIALS_REQUIRED", fallback=True
)

# AsyncDB Model representing a User Record.
AUTH_USER_MODEL = config.get(
    "AUTH_USER_MODEL", fallback="navigator_auth.models.User"
)

# Group Record.
AUTH_GROUP_MODEL = config.get(
    "AUTH_GROUP_MODEL", fallback="navigator_auth.models.Group"
)

ALLOWED_HOSTS = [
    e.strip()
    for e in list(config.get("ALLOWED_HOSTS", section="auth", fallback="localhost*").split(","))
]

## Redirections:
AUTH_REDIRECT_URI = config.get('AUTH_REDIRECT_URI', section="auth")
AUTH_LOGIN_FAILED_URI = config.get('AUTH_REDIRECT_URI', section="auth")

AUTH_SUCCESSFUL_CALLBACKS = (
)

# Enable authentication backends
AUTHENTICATION_BACKENDS = (
)

AUTHORIZATION_BACKENDS = [
    e.strip()
    for e in list(
        config.get("AUTHORIZATION_BACKENDS", fallback="allow_hosts").split(",")
    )
]

## Basic Authorization Middlewares
AUTHORIZATION_MIDDLEWARES = (
)

DEFAULT_MAPPING = {
    "user_id": "user_id",
    "username": "username",
    "password": "password",
    "first_name": "first_name",
    "last_name": "last_name",
    "email": "email",
    "enabled": "is_active",
    "superuser": "is_superuser",
    "last_login": "last_login",
    "title": "title",
}

USER_MAPPING = DEFAULT_MAPPING
mapping = config.get('AUTH_USER_MAPPING')
if mapping is not None:
    try:
        USER_MAPPING = orjson.loads(mapping)
    except orjson.JSONDecodeError:
        logging.exception(
            'Auth: Invalid User Mapping on *AUTH_USER_MAPPING*'
        )

## Redis Session:
CACHE_HOST = config.get("CACHEHOST", fallback="localhost")
CACHE_PORT = config.get("CACHEPORT", fallback=6379)
CACHE_URL = f"redis://{CACHE_HOST}:{CACHE_PORT}"
REDIS_SESSION_DB = config.get("REDIS_SESSION_DB", fallback=0)

redis_url = f"redis://{CACHE_HOST}:{CACHE_PORT}/1"
REDIS_AUTH_URL = config.get('REDIS_AUTH_URL', fallback=redis_url)

### Session and Auth Backends:
CACHE_PREFIX = config.get('CACHE_PREFIX', fallback='navigator')
SESSION_PREFIX = f'{CACHE_PREFIX}_session'

# Basic Authentication
SECRET_KEY = config.get('AUTH_SECRET_KEY')
if not SECRET_KEY:
    fernet_key = fernet.Fernet.generate_key()
    SECRET_KEY = base64.urlsafe_b64decode(fernet_key)

AUTH_SESSION_OBJECT = config.get(
    "AUTH_SESSION_OBJECT", fallback="session"
)
AUTH_DEFAULT_ISSUER = "urn:Navigator"
AUTH_DEFAULT_SCHEME = 'Bearer'
AUTH_TOKEN_ISSUER = config.get('AUTH_TOKEN_ISSUER', fallback='Navigator')
AUTH_PWD_DIGEST = config.get("AUTH_PWD_DIGEST", fallback="sha256")
AUTH_PWD_ALGORITHM = config.get("AUTH_PWD_ALGORITHM", fallback="pbkdf2_sha256")
AUTH_PWD_LENGTH = config.get("AUTH_PWD_LENGTH", fallback=32)
AUTH_JWT_ALGORITHM = config.get("JWT_ALGORITHM", fallback="HS256")
AUTH_PWD_SALT_LENGTH = config.get("AUTH_PWD_SALT_LENGTH", fallback=6)
AUTH_USERNAME_ATTRIBUTE = config.get(
    'AUTH_USERNAME_ATTRIBUTE', fallback='username'
)

## Django Auth Backend:
DJANGO_SESSION_DB = config.get('DJANGO_SESSION_DB', fallback=REDIS_SESSION_DB)
DJANGO_SESSION_URL = f"redis://{CACHE_HOST}:{CACHE_PORT}/{DJANGO_SESSION_DB}"
DJANGO_SESSION_PREFIX = config.get('DJANGO_SESSION_PREFIX', fallback=f'{CACHE_PREFIX}_session')

DJANGO_USER_MAPPING = {
    "groups": "groups",
    "programs": "programs",
    "modules": "modules",
    "api_url": "api_url",
    "api_query": "api_query",
    "filtering_fixed": "filtering_fixed",
    "hierarchy": "hierarchy",
    "employee": "employee",
}

# used by tokenauth with RNC.
PARTNER_KEY = config.get("PARTNER_KEY")
CYPHER_TYPE = config.get("CYPHER_TYPE", fallback="RNC")

## Token:
AUTH_TOKEN_ISSUER = config.get("AUTH_TOKEN_ISSUER", fallback="Navigator")
AUTH_TOKEN_SECRET = config.get("AUTH_TOKEN_SECRET", fallback=PARTNER_KEY)

try:
    from settings.settings import * # pylint: disable=W0614,W0401
except ImportError as ex:
    print(ex)
