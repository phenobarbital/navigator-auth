"""
Navigator Auth Configuration.
"""
# Import Config Class
import base64
import orjson
import contextlib
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
AUTH_EXCLUDE_LIST_KEY = "auth_exclude_list"

### Request key set when a request is authorized by a *sessionless* authz
### backend (authz_allowed_ips, authz_hosts, authz_allow_hosts,
### authz_useragent). Downstream consumers (e.g. QuerySource PBAC) can read
### ``request[AUTHZ_BACKEND_KEY]`` to detect IP/host/User-Agent authorization
### and allow access even when there is no user session.
AUTHZ_BACKEND_KEY = "authz_backend"

### Boolean companion of ``AUTHZ_BACKEND_KEY``: ``request[AUTHORIZED_KEY]`` is
### True when the request was *authorized* (allowed to pass) without being
### *authenticated* (no user, no session). Mirrors ``request["authenticated"]``
### so downstream code can distinguish the two states explicitly.
AUTHORIZED_KEY = "authorized"

EXCLUDE_DEFAULTS: list[str] = [
    "/static/",
    "/api/v1/login",
    "/api/v1/logout",
    "/api/v1/forgot-password",
    "/api/v1/reset-password",
]
_extra_excluded = [
    e.strip() for e in config.get("ROUTES_EXCLUDED", fallback="").split(",")
]
# Combined defaults used to seed per-app exclude lists.
exclude_list = EXCLUDE_DEFAULTS + [e for e in _extra_excluded if e]

# AUTH_CREDENTIALS_REQUIRED has been removed (SOC2).
# Authentication is always enforced and cannot be disabled via environment.

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

# Version / Deployment Headers:
import platform  # noqa: E402
from .version import __version__ as _PKG_VERSION  # noqa: E402

ENABLE_VERSION_HEADERS = config.getboolean('ENABLE_VERSION_HEADERS', fallback=True)
APP_VERSION = config.get('APP_VERSION', fallback=_PKG_VERSION)
GIT_SHA = config.get('GIT_SHA', fallback='unknown')

# Server Info Headers (API_HOST, PYTHON_VERSION, QS_PBAC_ENABLED, ENVIRONMENT):
ENABLE_SERVER_HEADERS = config.getboolean('ENABLE_SERVER_HEADERS', fallback=True)
API_HOST = config.get('API_HOST', fallback=DOMAIN_HOST)
PYTHON_VERSION = platform.python_version()
QS_PBAC_ENABLED = config.getboolean('QS_PBAC_ENABLED', fallback=False)

# Security: enable/disable the "/api/v1/security/config" debug endpoint (ConfigHandler).
SECURITY_CONFIG_HANDLER = config.getboolean('SECURITY_CONFIG_HANDLER', fallback=False)

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
        config.get("ALLOWED_HOSTS", fallback="localhost*").split(",")
    )
]

## Redirections:
AUTH_REDIRECT_URI = config.get("AUTH_REDIRECT_URI", fallback="/")
AUTH_FAILED_REDIRECT_URI = config.get("AUTH_FAILED_REDIRECT_URI", fallback="/login")
AUTH_LOGIN_FAILED_URI = config.get("AUTH_LOGIN_FAILED_URI", fallback="/login")
AUTH_LOGOUT_REDIRECT_URI = config.get("AUTH_LOGOUT_REDIRECT_URI", fallback="/oauth2/logout/complete")
AUTH_SUCCESSFUL_CALLBACKS = ()

# Enable authentication backends
AUTHENTICATION_BACKENDS = ()

# No permissive fallback: if AUTHORIZATION_BACKENDS is unset/empty, no authz
# backend is active (requests must pass authentication, not a host allowlist).
AUTHORIZATION_BACKENDS = [
    e.strip()
    for e in config.get("AUTHORIZATION_BACKENDS", fallback="").split(",")
    if e.strip()
]

### Allowed IPs (individual IPs or CIDR ranges, comma-separated):
ALLOWED_IPS = [
    e.strip()
    for e in config.get(
        "ALLOWED_IPS", section="auth", fallback=""
    ).split(",")
    if e.strip()
]

### Trusted proxy IPs (for X-Forwarded-For resolution):
ALLOWED_IP_TRUSTED_PROXIES = [
    e.strip()
    for e in config.get(
        "ALLOWED_IP_TRUSTED_PROXIES", section="auth", fallback=""
    ).split(",")
    if e.strip()
]

### PowerBI IP authorization (authz_powerbi backend).
# Static PBI CIDRs to seed the backend (fallback when the live Azure
# Service-Tag fetch is unavailable, e.g. offline startup):
POWERBI_ALLOWED_IPS = [
    e.strip()
    for e in config.get(
        "POWERBI_ALLOWED_IPS", section="auth", fallback=""
    ).split(",")
    if e.strip()
]

# Azure Service Tag names loaded into the authz_powerbi backend at startup.
# The fetch only runs when the authz_powerbi backend is installed in
# AUTHORIZATION_BACKENDS (its presence is the opt-in switch):
POWERBI_SERVICE_TAGS = [
    e.strip()
    for e in config.get(
        "POWERBI_SERVICE_TAGS", section="auth", fallback="PowerBI,PowerQueryOnline"
    ).split(",")
    if e.strip()
]

### Allowed User-Agents:
ALLOWED_UA = [
    e.strip()
    for e in list(config.get("ALLOWED_UA", fallback="*").split(","))
    if e.strip() != ""
]

### User-Agent authorization hardening (geo-fence).
# When True, authz_useragent requires a matching User-Agent AND that the
# real client IP geolocates to one of USERAGENT_ALLOWED_COUNTRIES. This is a
# temporary measure for service clients (e.g. PowerBI) that cannot be pinned
# to a CIDR range while they migrate to API-key authentication.
USERAGENT_SECURITY = config.getboolean("USERAGENT_SECURITY", fallback=False)

### Explicit authorization debug logging (IP / Host / User-Agent based authz):
# When True, every IP/host/User-Agent authorization decision made by the
# authz backends (authz_allowed_ips, authz_hosts, authz_allow_hosts,
# authz_useragent) is logged explicitly with the requesting client's
# User-Agent and IP/host information. Default: False.
AUTHZ_DEBUG = config.getboolean("AUTHZ_DEBUG", fallback=False)

### ISO-3166 country codes allowed when USERAGENT_SECURITY is on:
USERAGENT_ALLOWED_COUNTRIES = [
    e.strip().upper()
    for e in config.get(
        "USERAGENT_ALLOWED_COUNTRIES", section="auth", fallback="US,CA"
    ).split(",")
    if e.strip()
]

### Path to the MaxMind GeoLite2-Country database (.mmdb) for geo-fencing:
GEOIP_DATABASE = config.get(
    "GEOIP_DATABASE",
    section="auth",
    fallback="/etc/navigator/GeoLite2-Country.mmdb",
)

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

# ADFS SAML Relay: When set, after OIDC login the user is redirected
# to ADFS IdP-initiated SSO for this Relying Party (display name as
# shown in ADFS Management), enabling SSO with a third-party SAML SP
# without re-authentication. Example: "Network Ninja Production Management"
ADFS_SAML_RELAY_RP = config.get("ADFS_SAML_RELAY_RP", fallback=None)


# SAML
SAML_PATH = config.get("SAML_PATH")
SAML_SETTINGS = config.get("SAML_SETTINGS")
if SAML_SETTINGS:
    try:
        SAML_SETTINGS = orjson.loads(SAML_SETTINGS)
    except orjson.JSONDecodeError:
        logging.exception(
            "Auth: Invalid SAML Settings on *SAML_SETTINGS*"
        )

SAML_MAPPING = {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "username": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
    "object_id": "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "tenant_id": "http://schemas.microsoft.com/identity/claims/tenantid",
}

saml_mapping = config.get("SAML_MAPPING")
if saml_mapping is not None:
    try:
        SAML_MAPPING = orjson.loads(saml_mapping)
    except orjson.JSONDecodeError:
        logging.exception(
            "Auth: Invalid SAML Mapping on *SAML_MAPPING*"
        )


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
# Supported values:
#   "log"    — Python logger only (no external dependency).
#   "influx" — InfluxDB (time-series point write).
#   "mongo"  — MongoDB (document insert).
#   any asyncdb SQL driver name — "pg", "postgres", "mysql", "mysqlclient",
#       "mariadb", "mssql", "sqlite", "duckdb", "oracle", ... (requires AUDIT_DSN).
AUDIT_BACKEND = config.get('AUDIT_BACKEND', fallback='influx')

# Driver-specific credentials.
# For "influx":
INFLUX_CREDENTIALS = {
    "host": config.get('INFLUX_HOST', fallback='localhost'),
    "port": config.get('INFLUX_PORT', fallback=8086),
    "bucket": config.get('INFLUX_DATABASE', fallback='navigator_audit'),
    "org": config.get('INFLUX_ORG', fallback='navigator'),
    "token": config.get('INFLUX_TOKEN'),
}
# For any asyncdb SQL/document driver (mongo, pg, mysql, mssql, oracle, ...):
AUDIT_DSN = config.get('AUDIT_DSN', fallback=None)
# Destination table (SQL) or collection (document/Mongo) name.
AUDIT_TABLE = config.get('AUDIT_TABLE', fallback='audit_log')
# SQL bind placeholder dialect for drivers not auto-detected in
# navigator_auth.abac.audit.SQL_PARAMSTYLES. One of:
#   "numeric" ($1, $2 — asyncpg/Postgres)
#   "format"  (%s     — MySQL/MariaDB)
#   "qmark"   (?      — SQLite/MSSQL/DuckDB)
#   "named"   (:1, :2 — Oracle)
AUDIT_PARAMSTYLE = config.get('AUDIT_PARAMSTYLE', fallback='format')

# Backwards-compatible alias
AUDIT_CREDENTIALS = INFLUX_CREDENTIALS


## ABAC / PBAC Configuration
# Business hours for time-based access control
BUSINESS_HOURS_START = config.get("BUSINESS_HOURS_START", fallback="08:00")
BUSINESS_HOURS_END = config.get("BUSINESS_HOURS_END", fallback="18:00")
BUSINESS_DAYS = config.get("BUSINESS_DAYS", fallback="1,2,3,4,5")

# Day segment boundaries (HH:MM-HH:MM)
DAY_SEGMENT_MORNING = config.get("DAY_SEGMENT_MORNING", fallback="06:00-12:00")
DAY_SEGMENT_AFTERNOON = config.get("DAY_SEGMENT_AFTERNOON", fallback="12:00-18:00")
DAY_SEGMENT_EVENING = config.get("DAY_SEGMENT_EVENING", fallback="18:00-22:00")

# YAML policy storage directory
POLICY_STORAGE_DIR = config.get(
    "POLICY_STORAGE_DIR",
    fallback=str(BASE_DIR / "env" / "policies") if hasattr(BASE_DIR, '__truediv__') else None
)

# Default effect when no policies match a request ("deny" or "allow").
ABAC_DEFAULT_EFFECT = config.get("ABAC_DEFAULT_EFFECT", fallback="deny")

# ABAC Hot-Reload Interval (seconds). Default: 0 (disabled).
ABAC_RELOAD_INTERVAL = config.getint("ABAC_RELOAD_INTERVAL", fallback=0)

# Explicit debug logging of every authorization decision, including the
# requesting client's User-Agent and IP/host information (remote IP,
# X-Forwarded-For, Host header). Useful for tracing *who* asked for what.
# Default: False (keep the audit noise down in production).
ABAC_DEBUG_AUTHORIZATION = config.getboolean(
    "ABAC_DEBUG_AUTHORIZATION", fallback=False
)

# ---------------------------------------------------------------------------
# Per-tenant policy scoping (FEAT-092)
# ---------------------------------------------------------------------------

# Allow X-Org-Id / X-Client-Id request headers to set the request tenant.
# SECURITY: enable ONLY when headers are stripped and re-injected by a trusted
# edge (reverse proxy / API gateway).  Default: False.
ABAC_TENANT_TRUST_HEADERS = config.getboolean(
    "ABAC_TENANT_TRUST_HEADERS", fallback=False
)

# Header names for tenant resolution (overridable per deployment).
ABAC_TENANT_HEADER_ORG = config.get("ABAC_TENANT_HEADER_ORG", fallback="X-Org-Id")
ABAC_TENANT_HEADER_CLIENT = config.get("ABAC_TENANT_HEADER_CLIENT", fallback="X-Client-Id")

# (Phase 2) SQL-side prefetch + per-tenant evaluator instances.
# Default: False (Phase-1 in-engine filtering is the backstop).
ABAC_TENANT_SQL_FILTERING = config.getboolean(
    "ABAC_TENANT_SQL_FILTERING", fallback=False
)

## Oauth Provider:
OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS = config.getint(
    "OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS", fallback=4
)

# Access token TTL in seconds (default: 1 hour).
OAUTH_ACCESS_TOKEN_TTL = config.getint("OAUTH_ACCESS_TOKEN_TTL", fallback=3600)

# Authorization code TTL in seconds (default: 10 minutes).
OAUTH_CODE_TTL = config.getint("OAUTH_CODE_TTL", fallback=600)

# Refresh token sliding TTL in seconds (default: 30 days).
OAUTH_REFRESH_TOKEN_TTL = config.getint("OAUTH_REFRESH_TOKEN_TTL", fallback=2592000)

# Refresh token absolute maximum lifetime in seconds (default: 90 days).
OAUTH_REFRESH_ABSOLUTE_TTL = config.getint("OAUTH_REFRESH_ABSOLUTE_TTL", fallback=7776000)

# Enable refresh token rotation on every use (default: True).
OAUTH_REFRESH_ROTATION = config.getboolean("OAUTH_REFRESH_ROTATION", fallback=True)

# Require PKCE for public clients (default: True per FEAT-093 spec).
OAUTH_REQUIRE_PKCE_PUBLIC = config.getboolean("OAUTH_REQUIRE_PKCE_PUBLIC", fallback=True)

# Revocation cache TTL in seconds (default: 30 s).
# Controls how long a jti revocation marker survives independently of the token's remaining TTL.
OAUTH_REVOCATION_CACHE_TTL = config.getint("OAUTH_REVOCATION_CACHE_TTL", fallback=30)

# ---------------------------------------------------------------------------
# OAuth2 Scope registry (FEAT-093 TASK-030)
# ---------------------------------------------------------------------------
# Comma-separated list of valid scope identifiers (reject unknown at authorize per D5).
# Override via environment: OAUTH_SCOPES="default,profile,email,offline_access,read,write"
_oauth_scopes_raw = config.get(
    "OAUTH_SCOPES",
    fallback="default,profile,email,offline_access,read,write,admin",
)
OAUTH_SCOPES: list[str] = [s.strip() for s in _oauth_scopes_raw.split(",") if s.strip()]

# Action → required scope(s) mapping.
# Format: "action_name:scope1+scope2,...".  Multiple scopes per action are AND-ed.
# Override via environment: OAUTH_SCOPE_ACTIONS="tool:execute:default,kb:query:default+read"
_oauth_scope_actions_raw = config.get("OAUTH_SCOPE_ACTIONS", fallback="")
OAUTH_SCOPE_ACTIONS: dict[str, list[str]] = {}
if _oauth_scope_actions_raw.strip():
    for _entry in _oauth_scope_actions_raw.split(","):
        _entry = _entry.strip()
        if ":" in _entry:
            # Last colon separates action from scope list; earlier colons are part of action.
            _parts = _entry.rsplit(":", 1)
            _action_key = _parts[0].strip()
            _scope_list = [s.strip() for s in _parts[1].split("+") if s.strip()]
            if _action_key and _scope_list:
                OAUTH_SCOPE_ACTIONS[_action_key] = _scope_list


# ---------------------------------------------------------------------------
# OAuth2 Token Introspection (RFC 7662) — FEAT-094 TASK-033
# ---------------------------------------------------------------------------

# When True, include FEAT-093 effective ABAC scopes in introspection responses.
# Resolved D5: default False (strict RFC 7662 claims only).
OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES = config.getboolean(
    "OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES", fallback=False
)

# ---------------------------------------------------------------------------
# OAuth2 Device Authorization Grant (RFC 8628) — FEAT-094 TASK-034
# ---------------------------------------------------------------------------

# Lifetime of a device_code in seconds (RFC 8628 §3.2 default 600 s).
OAUTH_DEVICE_CODE_TTL = config.getint("OAUTH_DEVICE_CODE_TTL", fallback=600)

# Initial poll interval returned to the device client in seconds.
OAUTH_DEVICE_POLL_INTERVAL = config.getint("OAUTH_DEVICE_POLL_INTERVAL", fallback=5)

# Seconds added to the interval on a slow_down response (RFC 8628 §3.5).
OAUTH_DEVICE_SLOW_DOWN_INCREMENT = config.getint(
    "OAUTH_DEVICE_SLOW_DOWN_INCREMENT", fallback=5
)

# Length of the user_code (excluding any formatting hyphens).
OAUTH_DEVICE_USER_CODE_LENGTH = config.getint(
    "OAUTH_DEVICE_USER_CODE_LENGTH", fallback=8
)

# Unambiguous alphabet for user_code generation.
OAUTH_DEVICE_USER_CODE_ALPHABET = config.get(
    "OAUTH_DEVICE_USER_CODE_ALPHABET", fallback="BCDFGHJKLMNPQRSTVWXZ"
)

# Verification URI for the device flow.  When empty, derived from request host.
OAUTH_DEVICE_VERIFICATION_URI = config.get(
    "OAUTH_DEVICE_VERIFICATION_URI", fallback=""
)

# Max bad user_code attempts before the client IP is locked out.
OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS = config.getint(
    "OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS", fallback=5
)

# Lockout duration in seconds after too many bad attempts.
OAUTH_DEVICE_LOCKOUT_TTL = config.getint("OAUTH_DEVICE_LOCKOUT_TTL", fallback=300)


with contextlib.suppress(ImportError):
    from settings.settings import *  # pylint: disable=W0614,W0401 # noqa
with contextlib.suppress(ImportError):
    from settings import *  # pylint: disable=W0614,W0401 # noqa
