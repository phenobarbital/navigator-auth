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
ENVIRONMENT = config.get('ENVIRONMENT', fallback='development')

### DATABASE INFORMATION:
AUTH_DB_SCHEMA = config.get("AUTH_DB_SCHEMA", fallback="auth")
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
    "/login/callback"
]
new_excluded = [
    e.strip() for e in list(config.get("ROUTES_EXCLUDED", fallback="").split(","))
]
exclude_list = excluded_default + new_excluded

# if false, force credentials are not required for using this system.
AUTH_CREDENTIALS_REQUIRED = config.getboolean(
    "AUTH_CREDENTIALS_REQUIRED", fallback=True
)

# AsyncDB Model representing a User Record.
AUTH_USER_MODEL = config.get("AUTH_USER_MODEL", fallback="navigator_auth.models.User")
# User View can represent a more complex user View used for getting User Data.
AUTH_USER_VIEW = config.get("AUTH_USER_VIEW", fallback="navigator_auth.models.User")

# Group Record.
AUTH_GROUP_MODEL = config.get(
    "AUTH_GROUP_MODEL", fallback="navigator_auth.models.Group"
)

# User Group Record.
AUTH_USER_GROUP_MODEL = config.get(
    "AUTH_USER_GROUP_MODEL", fallback="navigator_auth.models.UserGroup"
)

### Other Models (clients, organizations and Programs):
AUTH_CLIENT_MODEL = config.get("AUTH_CLIENT_MODEL", fallback=None)

AUTH_PROGRAM_MODEL = config.get("AUTH_PROGRAM_MODEL", fallback=None)

AUTH_PROGRAM_CLIENT_MODEL = config.get("AUTH_PROGRAM_CLIENT_MODEL", fallback=None)

AUTH_PROGRAM_CATEGORY_MODEL = config.get("AUTH_PROGRAM_CATEGORY_MODEL", fallback=None)

AUTH_ORGANIZATION_MODEL = config.get("AUTH_ORGANIZATION_MODEL", fallback=None)

AUTH_USER_ORGANIZATION_MODEL = config.get("AUTH_USER_ORGANIZATION_MODEL", fallback=None)

AUTH_PERMISSION_MODEL = config.get("AUTH_PERMISSION_MODEL", fallback=None)

AUTH_USER_IDENTITY_MODEL = config.get("AUTH_USER_IDENTITY_MODEL", fallback=None)

ALLOWED_HOSTS = [
    e.strip()
    for e in list(
        config.get("ALLOWED_HOSTS", section="auth", fallback="localhost*").split(",")
    )
]

## Redirections:
AUTH_REDIRECT_URI = config.get("AUTH_REDIRECT_URI", section="auth")
AUTH_LOGIN_FAILED_URI = config.get("AUTH_LOGIN_FAILED_URI", section="auth")

AUTH_SUCCESSFUL_CALLBACKS = ()

# Enable authentication backends
AUTHENTICATION_BACKENDS = ()

AUTHORIZATION_BACKENDS = [
    e.strip()
    for e in list(
        config.get("AUTHORIZATION_BACKENDS", fallback="allow_hosts").split(",")
    )
]

## Basic Authorization Middlewares
AUTHORIZATION_MIDDLEWARES = ()

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
mapping = config.get("AUTH_USER_MAPPING")
if mapping is not None:
    try:
        USER_MAPPING = orjson.loads(mapping)
    except orjson.JSONDecodeError:
        logging.exception(
            "Auth: Invalid User Mapping on *AUTH_USER_MAPPING*"
        )

## Redis Session:
REDIS_HOST = config.get("REDIS_HOST", fallback="localhost")
REDIS_PORT = config.get("REDIS_PORT", fallback=6379)
REDIS_DB = config.get("REDIS_DB", fallback=1)
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
REDIS_AUTH_URL = config.get("REDIS_AUTH_URL", fallback=REDIS_URL)

### Session and Auth Backends:
REDIS_SESSION_DB = config.get("SESSION_DB", fallback=0)
CACHE_PREFIX = config.get("CACHE_PREFIX", fallback="navigator")
SESSION_PREFIX = f"{CACHE_PREFIX}_session"

# Basic Authentication
SECRET_KEY = config.get("AUTH_SECRET_KEY")
if not SECRET_KEY:
    fernet_key = fernet.Fernet.generate_key()
    SECRET_KEY = base64.urlsafe_b64decode(fernet_key)

AUTH_SESSION_OBJECT = config.get("AUTH_SESSION_OBJECT", fallback="session")
AUTH_DEFAULT_ISSUER = "urn:Navigator"
AUTH_DEFAULT_SCHEME = "Bearer"
AUTH_TOKEN_ISSUER = config.get("AUTH_TOKEN_ISSUER", fallback="Navigator")
AUTH_PWD_DIGEST = config.get("AUTH_PWD_DIGEST", fallback="sha256")
AUTH_PWD_ALGORITHM = config.get("AUTH_PWD_ALGORITHM", fallback="pbkdf2_sha256")
AUTH_PWD_LENGTH = config.get("AUTH_PWD_LENGTH", fallback=32)
AUTH_JWT_ALGORITHM = config.get("JWT_ALGORITHM", fallback="HS256")
AUTH_PWD_SALT_LENGTH = config.get("AUTH_PWD_SALT_LENGTH", fallback=6)
AUTH_USERNAME_ATTRIBUTE = config.get("AUTH_USERNAME_ATTRIBUTE", fallback="username")

## Django Auth Backend:
DJANGO_SESSION_DB = config.get("DJANGO_SESSION_DB", fallback=REDIS_SESSION_DB)
DJANGO_SESSION_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{DJANGO_SESSION_DB}"
DJANGO_SESSION_PREFIX = config.get(
    "DJANGO_SESSION_PREFIX", fallback=f"{CACHE_PREFIX}_session"
)

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


### Azure Authentication
# Microsoft Azure
AZURE_ADFS_CLIENT_ID = config.get("AZURE_ADFS_CLIENT_ID")
AZURE_ADFS_CLIENT_SECRET = config.get("AZURE_ADFS_CLIENT_SECRET")
AZURE_ADFS_TENANT_ID = config.get("AZURE_ADFS_TENANT_ID", fallback="common")
AZURE_ADFS_SECRET = config.get("AZURE_ADFS_SECRET")
AZURE_ADFS_DOMAIN = config.get("AZURE_ADFS_DOMAIN", fallback="contoso.onmicrosoft.com")

default_scopes = "User.Read,User.Read.All,User.ReadBasic.All,openid"
AZURE_ADFS_SCOPES = [
    e.strip() for e in list(config.get("AZURE_ADFS_SCOPES", fallback="").split(","))
]

PREFERRED_AUTH_SCHEME = config.get("PREFERRED_AUTH_SCHEME", fallback="https")
# ADFS SSO
ADFS_SERVER = config.get("ADFS_SERVER")
ADFS_CLIENT_ID = config.get("ADFS_CLIENT_ID")
ADFS_RELYING_PARTY_ID = config.get("ADFS_RELYING_PARTY_ID")
ADFS_RESOURCE = config.get("ADFS_RESOURCE")
ADFS_AUDIENCE = config.get("ADFS_AUDIENCE")
ADFS_ISSUER = config.get("ADFS_ISSUER")
ADFS_SCOPES = config.get("ADFS_SCOPES", fallback="https://graph.microsoft.com/.default")
ADFS_TENANT_ID = config.get("ADFS_TENANT_ID", fallback=None)
USERNAME_CLAIM = config.get("USERNAME_CLAIM")
GROUP_CLAIM = config.get("GROUP_CLAIM")
ADFS_LOGIN_REDIRECT_URL = config.get("ADFS_LOGIN_REDIRECT_URL")
ADFS_CALLBACK_REDIRECT_URL = config.get("ADFS_CALLBACK_REDIRECT_URL", fallback=None)

adfs_mapping = {
    "first_name": "given_name",
    "last_name": "family_name",
    "email": "email",
}
AZURE_AD_SERVER = config.get("AZURE_AD_SERVER", fallback="login.microsoftonline.com")
AZURE_SESSION_TIMEOUT = config.get("AZURE_SESSION_TIMEOUT", fallback=120)
ADFS_CLAIM_MAPPING = config.get("ADFS_CLAIM_MAPPING", fallback=adfs_mapping)

# Okta
OKTA_CLIENT_ID = config.get("OKTA_CLIENT_ID")
OKTA_CLIENT_SECRET = config.get("OKTA_CLIENT_SECRET")
OKTA_DOMAIN = config.get("OKTA_DOMAIN")
OKTA_APP_NAME = config.get("OKTA_APP_NAME")

# GOOGLE
GOOGLE_CLIENT_ID = config.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config.get("GOOGLE_CLIENT_SECRET")
GOOGLE_API_SCOPES = [
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "email",
]

## Github Support:
GITHUB_CLIENT_ID = config.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = config.get("GITHUB_CLIENT_SECRET")

## Audit Backend
# this is the backend for saving task executions
ENABLE_AUDIT_LOG = config.getboolean('ENABLE_AUDIT_LOG', fallback=True)
AUDIT_BACKEND = config.get('AUDIT_BACKEND', fallback='influx')
AUDIT_CREDENTIALS = {
    "host": config.get('INFLUX_HOST', fallback='localhost'),
    "port": config.get('INFLUX_PORT', fallback=8086),
    "bucket": config.get('INFLUX_DATABASE', fallback='navigator_audit'),
    "org": config.get('INFLUX_ORG', fallback='navigator'),
    "token": config.get('INFLUX_TOKEN')
}

try:
    from settings.settings import *  # pylint: disable=W0614,W0401
except ImportError as ex:
    print(ex)
