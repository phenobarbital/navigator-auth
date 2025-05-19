"""
Navigator Auth Configuration.
"""
# Import Config Class
import base64
import orjson
from cryptography import fernet
from navconfig import config, BASE_DIR
from navconfig.logging import logging

## Disable aiohttp Logging
logging.getLogger(name='aiohttp.access').setLevel(logging.WARNING)

############
#
### Authentication System
#
############

## Hosts
DOMAIN_HOST = config.get('API_HOST', fallback='localhost:5000')
HOSTS = [e.strip() for e in list(config.get("HOSTS", fallback="localhost").split(","))]

## Default Domain
DOMAIN = config.get("DOMAIN", fallback="dev.local")
ENVIRONMENT = config.get('ENVIRONMENT', fallback='development')

### DATABASE INFORMATION:
AUTH_DB_SCHEMA = config.get("AUTH_DB_SCHEMA", fallback="auth")
AUTH_USERS_TABLE = config.get("AUTH_USERS_TABLE", fallback="users")
AUTH_USERS_VIEW = config.get("AUTH_USERS_VIEW", fallback="vw_users")
AUTH_GROUPS_TABLE = config.get("AUTH_GROUPS_TABLE", fallback="groups")

#### Main Database
DBUSER = config.get("DBUSER")
DBHOST = config.get("DBHOST", fallback="localhost")
DBPWD = config.get("DBPWD")
DBNAME = config.get("DBNAME", fallback="navigator")
DBPORT = config.get("DBPORT", fallback=5432)

default_dsn = f"postgres://{DBUSER}:{DBPWD}@{DBHOST}:{DBPORT}/{DBNAME}"

### Exclude List:
excluded_default = [
    "/static/",
    "/api/v1/login",
    "/api/v1/logout",
    "/auth/login",
    "/auth/logout",
    "/auth/login/callback"
]
new_excluded = [
    e.strip() for e in list(config.get("ROUTES_EXCLUDED", fallback="").split(","))
]
exclude_list = excluded_default + new_excluded

# if false, force credentials are not required for using this system.
AUTH_CREDENTIALS_REQUIRED = config.getboolean(
    "AUTH_CREDENTIALS_REQUIRED", fallback=True
)

# Security Headers:
ENABLE_XFRAME_OPTIONS = config.getboolean('ENABLE_XFRAME_OPTIONS', fallback=True)
XFRAME_OPTIONS = config.get('XFRAME_OPTIONS', fallback='DENY')

# Security: Referer Policy
ENABLE_XREFERER_POLICY = config.getboolean('XREFERER_POLICY', fallback=True)
XREFERER_POLICY = config.get(
    'XREFERER_POLICY',
    fallback='strict-origin-when-cross-origin'
)

# Content Security Policy:
HSTS_MAX_AGE = config.getint('HSTS_MAX_AGE', fallback=31536000)
STRICT_INCLUDE_SUBDOMAINS = config.getboolean(
    'STRICT_INCLUDE_SUBDOMAINS',
    fallback=True
)
ENABLE_XSS_PROTECTION = config.getboolean('ENABLE_XSS_PROTECTION', fallback=True)
XSS_PROTECTION = config.get('XSS_PROTECTION', fallback='1; mode=block')
XCONTENT_TYPE_OPTIONS = config.get('XCONTENT_TYPE_OPTIONS', fallback='nosniff')

# what happen when a user doesn't exists?
# possible values are: create (user is created), raise (a UserDoesntExists raises)
# and ignore, session is created but user is missing.
AUTH_MISSING_ACCOUNT = config.get("AUTH_MISSING_ACCOUNT", fallback="create")
# List of function callbacks called (in order) when a user is

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

AUTH_PERMISSION_MODEL = config.get("AUTH_PERMISSION_MODEL", fallback=None)

AUTH_USER_IDENTITY_MODEL = config.get("AUTH_USER_IDENTITY_MODEL", fallback=None)

ALLOWED_HOSTS = [
    e.strip()
    for e in list(
        config.get("ALLOWED_HOSTS", section="auth", fallback="localhost*").split(",")
    )
]

## Redirections:
AUTH_REDIRECT_URI = config.get("AUTH_REDIRECT_URI", fallback="/")
AUTH_FAILED_REDIRECT_URI = config.get("AUTH_FAILED_REDIRECT_URI", fallback="/login")
AUTH_LOGIN_FAILED_URI = config.get("AUTH_LOGIN_FAILED_URI", fallback="/login")
AUTH_LOGOUT_REDIRECT_URI = config.get("AUTH_LOGOUT_REDIRECT_URI", fallback="/logout")
AUTH_SUCCESSFUL_CALLBACKS = ()

# Enable authentication backends
AUTHENTICATION_BACKENDS = ()

AUTHORIZATION_BACKENDS = [
    e.strip()
    for e in list(
        config.get("AUTHORIZATION_BACKENDS", fallback="allow_hosts").split(",")
    )
]

### Allowed User-Agents:
ALLOWED_UA = [
    e.strip()
    for e in list(config.get("ALLOWED_UA", fallback="*").split(","))
    if e.strip() != ""
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

### Custom User Attributes:
# FILTERS: functions called on "filter" process.
USER_ATTRIBUTES = [
    "navigator_auth.backends.attributes.DomainAttribute"
]


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


AUTH_CLIENT_ID = config.get('AUTH_CLIENT_ID', fallback='navigator_dev.client_id')
AUTH_SESSION_OBJECT = config.get("AUTH_SESSION_OBJECT", fallback="session")

## Basic Password Auth
AUTH_PWD_DIGEST = config.get("AUTH_PWD_DIGEST", fallback="sha256")
AUTH_PWD_ALGORITHM = config.get("AUTH_PWD_ALGORITHM", fallback="pbkdf2_sha256")
AUTH_PWD_LENGTH = config.get("AUTH_PWD_LENGTH", fallback=32)
AUTH_JWT_ALGORITHM = config.get("JWT_ALGORITHM", fallback="HS256")
AUTH_PWD_SALT_LENGTH = config.get("AUTH_PWD_SALT_LENGTH", fallback=6)
AUTH_USERID_ATTRIBUTE = config.get("AUTH_USERID_ATTRIBUTE", fallback="user_id")
AUTH_USERNAME_ATTRIBUTE = config.get("AUTH_USERNAME_ATTRIBUTE", fallback="username")
AUTH_PASSWORD_ATTRIBUTE = config.get("AUTH_PASSWORD_ATTRIBUTE", fallback="password")
AUTH_OAUTH2_REDIRECT_URL = config.get(
    "AUTH_OAUTH2_REDIRECT_URL",
    fallback=None
)

## Django Auth Backend:
DJANGO_SESSION_DB = config.get("DJANGO_SESSION_DB", fallback=REDIS_SESSION_DB)
DJANGO_SESSION_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{DJANGO_SESSION_DB}"
DJANGO_SESSION_PREFIX = config.get(
    "DJANGO_SESSION_PREFIX", fallback=f"{CACHE_PREFIX}_session"
)

BASIC_USER_MAPPING = {
    "user_id": "user_id",
    "name": "display_name",
    "email": "email",
    "upn": "email"
}

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
TROCTOKEN_REDIRECT_URI = config.get(
    'TROCTOKEN_REDIRECT_URI',
    fallback=AUTH_REDIRECT_URI
)
## Oauth2 authentication:
AUTH_TOKEN_ISSUER = config.get("AUTH_TOKEN_ISSUER", fallback="urn:Navigator")
AUTH_TOKEN_SECRET = config.get("AUTH_TOKEN_SECRET", fallback=PARTNER_KEY)
AUTH_CODE_EXPIRATION = config.getint("AUTH_CODE_EXPIRATION", fallback=600)
AUTH_DEFAULT_SCHEME = config.get('AUTH_DEFAULT_SCHEME', fallback="Bearer")
AUTH_DEFAULT_ISSUER = AUTH_TOKEN_ISSUER

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

azure_mapping = {
    "phone": "businessPhones",
    "display_name": "displayName",
    "first_name": "givenName",
    "given_name": "givenName",
    "last_name": "surname",
    "family_name": "surname",
    "userid": "id",
    "id": "id",
    "job_title": "jobTitle",
    "title": "jobTitle",
    "email": "mail",
    "mobile": "mobilePhone",
    "username": "userPrincipalName",
    "utid": "utid",
    "name": "displayName"
}
az_mapping = config.get("AZURE_MAPPING")

if az_mapping is not None:
    try:
        azure_mapping = orjson.loads(az_mapping)
    except orjson.JSONDecodeError:
        logging.exception(
            "Auth: Invalid Azure Mapping on *AZURE_MAPPING*"
        )
AZURE_MAPPING = azure_mapping

# ADFS SSO
ADFS_SERVER = config.get("ADFS_SERVER")
ADFS_CLIENT_ID = config.get("ADFS_CLIENT_ID")
ADFS_RELYING_PARTY_ID = config.get("ADFS_RELYING_PARTY_ID")
ADFS_RESOURCE = config.get("ADFS_RESOURCE")
ADFS_DEFAULT_RESOURCE = config.get(
    "ADFS_DEFAULT_RESOURCE",
    fallback="urn:microsoft:userinfo"
)
ADFS_AUDIENCE = config.get("ADFS_AUDIENCE")
ADFS_ISSUER = config.get("ADFS_ISSUER")
ADFS_SCOPES = config.get("ADFS_SCOPES", fallback="https://graph.microsoft.com/.default")
ADFS_TENANT_ID = config.get("ADFS_TENANT_ID", fallback=None)
USERNAME_CLAIM = config.get("USERNAME_CLAIM")
GROUP_CLAIM = config.get("GROUP_CLAIM")
ADFS_LOGIN_REDIRECT_URL = config.get("ADFS_LOGIN_REDIRECT_URL")
ADFS_CALLBACK_REDIRECT_URL = config.get("ADFS_CALLBACK_REDIRECT_URL", fallback=None)

ADFS_MAPPING = {
    "upn": "upn",
    "email": "email",
    "given_name": "given_name",
    "family_name": "family_name",
    "department": "Department",
    "name": "Display-Name",
    "display_name": "Display-Name"
}
ad_mapping = config.get("ADFS_CLAIM_MAPPING")
if ad_mapping is not None:
    try:
        ad_mapping = orjson.loads(ad_mapping)
    except orjson.JSONDecodeError:
        logging.exception(
            "Auth: Invalid Azure Mapping on *ADFS_MAPPING*"
        )
ADFS_CLAIM_MAPPING = ad_mapping

AZURE_AD_SERVER = config.get("AZURE_AD_SERVER", fallback="login.microsoftonline.com")
AZURE_SESSION_TIMEOUT = config.get("AZURE_SESSION_TIMEOUT", fallback=120)


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
# this is the backend for saving Authentication information
ENABLE_AUDIT_LOG = config.getboolean('ENABLE_AUDIT_LOG', fallback=True)
AUDIT_BACKEND = config.get('AUDIT_BACKEND', fallback='influx')
AUDIT_CREDENTIALS = {
    "host": config.get('INFLUX_HOST', fallback='localhost'),
    "port": config.get('INFLUX_PORT', fallback=8086),
    "bucket": config.get('INFLUX_DATABASE', fallback='navigator_audit'),
    "org": config.get('INFLUX_ORG', fallback='navigator'),
    "token": config.get('INFLUX_TOKEN')
}


## Oauth Provider:
OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS = config.getint(
    "OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS", fallback=4
)

try:
    from settings.settings import *  # pylint: disable=W0614,W0401 # noqa
except ImportError as ex:
    logging.error(
        f'There is no "*settings/settings.py" module in project. {ex}'
    )
    try:
        from settings import *  # pylint: disable=W0614,W0401 # noqa
    except ImportError as ex:
        logging.error(
            f'There is no "*settings/__init__.py" module in project. {ex}'
        )
