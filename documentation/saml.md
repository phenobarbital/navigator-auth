# SAML 2.0 Authentication

Navigator Auth ships an abstract SAML 2.0 layer on
[`pysaml2`](https://pysaml2.readthedocs.io/), replacing the previous
single, concrete `python3-saml`-based backend (FEAT-097). Two roles are
available, sharing one engine (`SAMLCore`):

- **Service Provider (SP)** — `AbstractSAMLBackend` / the generic
  `SAMLAuth` reference subclass. Delegates login to an external IdP
  (Okta, Microsoft Entra ID, a partner IdP). This is what most
  deployments need.
- **Identity Provider (IdP)** — `AbstractSAMLIdentityProvider` / the
  generic `SAMLIdentityProvider` reference subclass. Issues signed
  assertions for the *current* Navigator session to external SAML
  Service Providers (e.g. Verizon Connect) that Navigator needs to "SSO
  into". It never authenticates anyone itself; it hides from
  `/api/v1/auth/methods` and defines no auth middleware.

Both roles support Redirect and POST bindings, Single Logout, and a
documented set of hooks for subclassing.

## Prerequisites

`pysaml2` shells out to the `xmlsec1` system binary for every signing and
signature-verification operation — it is not a Python package and must be
installed separately.

```bash
# Debian/Ubuntu
sudo apt-get install xmlsec1

# RHEL/Fedora/Alma
sudo dnf install xmlsec1

# Alpine
apk add xmlsec
```

Startup fails fast with a message naming the binary and the
`SAML_XMLSEC_BINARY` setting when `xmlsec1` cannot be found on `PATH`.

```toml
[project.dependencies]
pysaml2 = ">=7.5,<8"
```

## Service Provider (SP) Role

### 1. Enable the Backend

```python
AUTHENTICATION_BACKENDS = (
    'navigator_auth.backends.SAMLAuth',
)
```

### 2. Point at the IdP's Metadata

```python
# A URL pysaml2 fetches at startup...
SAML_METADATA = "https://idp.example.com/federationmetadata/2007-06/federationmetadata.xml"
# ...or a local file path.
SAML_METADATA = "/etc/navigator/saml/idp-metadata.xml"
```

### 3. Attribute Mapping

Unchanged shape from the legacy backend — maps SAML attribute URIs to
user fields:

```python
SAML_MAPPING = {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "username": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
    "object_id": "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "tenant_id": "http://schemas.microsoft.com/identity/claims/tenantid",
}
```

A mapping value may also be `{"name": "<attr uri>", "multi": True}` to
keep every value (as a list) instead of just the first one.

### 4. Optional SP Key Pair, Binding, Signature Flags

```python
SAML_SP_KEY_FILE = "/etc/navigator/saml/sp.key"    # AuthnRequest signing / assertion decryption
SAML_SP_CERT_FILE = "/etc/navigator/saml/sp.crt"
SAML_BINDING = "redirect"                          # or "post"
SAML_ALLOW_UNSOLICITED = True                      # accept IdP-initiated logins
SAML_WANT_ASSERTIONS_SIGNED = True
SAML_WANT_RESPONSE_SIGNED = False
```

See :doc:`../docs/settings` for the full key reference, including the
shared keys (`SAML_XMLSEC_BINARY`, `SAML_CLOCK_SKEW`, `SAML_FLOW_TTL`,
`SAML_EXECUTOR_WORKERS`, `SAML_METADATA_RELOAD`).

### Subclassing `AbstractSAMLBackend`

A minimal subclass only needs to implement three hooks:

| Hook | Required | Description |
|---|---|---|
| `get_idp_metadata()` | yes | Path/URL to IdP metadata, or an inline `pysaml2` metadata dict. |
| `get_attribute_mapping()` | yes | `user_field -> SAML attribute name` (`SAML_MAPPING` shape). |
| `resolve_user_identifier(result)` | yes | Login identifier used for `validate_user_info` (usually a mapped `username`, falling back to `email` or the raw `NameID`). |
| `authorize(request, result, identifier)` | no | Post-validation access decision. Default: allow. `False` -> `SAML_FORBIDDEN`. |
| `on_assertion(request, result, user)` | no | Called after the session is created. Default: no-op. |
| `get_settings()` | no | Optional `pysaml2` config overrides (default: `<prefix>_SETTINGS` JSON). |

```python
from navigator_auth.backends.saml import AbstractSAMLBackend

class OktaSAMLBackend(AbstractSAMLBackend):
    config_prefix = "OKTA_SAML"          # every key above resolves under OKTA_SAML_* first

    def get_idp_metadata(self):
        return "/etc/navigator/saml/okta-metadata.xml"

    def get_attribute_mapping(self):
        return {"email": "email", "username": "login"}

    async def resolve_user_identifier(self, result):
        return result.attributes.get("username") or result.attributes.get("email")
```

## Identity Provider (IdP) Role

### 1. Enable the Backend

```python
AUTHENTICATION_BACKENDS = (
    'navigator_auth.backends.SAMLIdentityProvider',
    # ... your login backend(s), e.g. BasicAuth or an OIDC backend, so
    # there's an actual session for the IdP role to issue assertions for.
)
```

The IdP role is loaded for lifecycle only (`configure`/`on_startup`/
`on_cleanup`); it defines no `auth_middleware`, never sets
`request.user`/`request["authenticated"]`, and never appears in
`/api/v1/auth/methods` (`hidden = True`).

### 2. Signing Key Pair (required)

```python
SAML_IDP_KEY_FILE = "/etc/navigator/saml/idp.key"
SAML_IDP_CERT_FILE = "/etc/navigator/saml/idp.crt"
SAML_IDP_KEY_PASSPHRASE = None  # optional
```

### 3. Register Service Providers

```python
SAML_IDP_SERVICE_PROVIDERS = '''[
    {
        "sp_id": "verizon-connect",
        "entity_id": "https://sp.verizonconnect.example/saml/metadata",
        "acs_url": "https://sp.verizonconnect.example/saml/acs",
        "acs_binding": "HTTP-POST",
        "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "attribute_map": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email"},
        "sign_assertion": true,
        "sign_response": false,
        "assertion_ttl": 300,
        "allowed_relay_hosts": ["sp.verizonconnect.example"]
    }
]'''
```

Parsed and validated at startup (`ServiceProviderConfig.from_dict`);
a duplicate `sp_id` or a config missing `sp_id`/`entity_id`/`acs_url`
fails startup.

### 4. Subclassing `AbstractSAMLIdentityProvider`

| Hook | Required | Description |
|---|---|---|
| `get_service_providers()` | yes | `{sp_id: ServiceProviderConfig}` registry. |
| `build_attributes(user, sp)` | yes | SAML attribute statement for `user`, scoped to `sp`. |
| `get_nameid(user, sp)` | no | Default: `user.email` for the `emailAddress` format, else `user.username`. |
| `authorize_sp_access(request, user, sp)` | no | Default: allow. `False` -> `SAML_SP_FORBIDDEN`, nothing rendered, audited as `saml.sp.forbidden`. |
| `get_keypair()` | no | Default: `<prefix>_KEY_FILE`/`_CERT_FILE`/`_KEY_PASSPHRASE`. |
| `get_settings()` | no | Optional `pysaml2` config overrides. |

```python
from navigator_auth.backends.saml import AbstractSAMLIdentityProvider, ServiceProviderConfig

class MyIdentityProvider(AbstractSAMLIdentityProvider):
    def get_service_providers(self):
        return {
            "verizon-connect": ServiceProviderConfig(
                sp_id="verizon-connect",
                entity_id="https://sp.verizonconnect.example/saml/metadata",
                acs_url="https://sp.verizonconnect.example/saml/acs",
            ),
        }

    async def build_attributes(self, user, sp):
        return {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [user.email]}
```

### Flows

- **IdP-initiated SSO**: a logged-in user visits
  `/auth/saml-idp/initiate/{sp_id}`; the IdP issues a signed assertion and
  auto-POSTs it to the SP's ACS URL.
- **SP-initiated SSO**: the SP redirects to `/auth/saml-idp/sso` with an
  `AuthnRequest`. With no Navigator session, the request is parked
  (single-use, TTL `SAML_FLOW_TTL`) and the browser is sent to the login
  page; after login it resumes `/auth/saml-idp/sso?flow=<id>` once.
- **SLO**: `/auth/saml-idp/slo` accepts an inbound `LogoutRequest` from a
  registered SP, clears the matching session, and replies with a signed
  `LogoutResponse`.

## Routes

| Role | Method | Path | Excluded from auth |
|---|---|---|---|
| SP | `*` | `/api/v1/auth/<svc>/` | yes |
| SP | `GET` | `/auth/<svc>/login` | yes |
| SP | `POST` | `/auth/<svc>/callback/` | yes |
| SP | `GET` | `/auth/<svc>/metadata` | yes |
| SP | `GET` | `/api/v1/auth/<svc>/logout` | no |
| SP | `GET`, `POST` | `/auth/<svc>/logout` | yes |
| IdP | `GET` | `/auth/<svc>/initiate/{sp_id}` | no (session required) |
| IdP | `GET`, `POST` | `/auth/<svc>/sso` | yes (checks the session itself) |
| IdP | `GET`, `POST` | `/auth/<svc>/slo` | yes |
| IdP | `GET` | `/auth/<svc>/metadata` | yes |

`<svc>` is `saml` for `SAMLAuth` and `saml-idp` for `SAMLIdentityProvider`
by default (or `config_prefix` lower-cased, hyphenated, for a subclass).

## Stable Error Codes

Surfaced on `error=` (SP failed-redirect) and in every audit record:

`SAML_INVALID_RESPONSE`, `SAML_INVALID_SIGNATURE`, `SAML_EXPIRED`,
`SAML_REPLAY`, `SAML_STALE_REQUEST`, `SAML_AUDIENCE_MISMATCH`,
`SAML_DECRYPT_FAILED`, `SAML_NOT_AUTHENTICATED`, `SAML_USER_NOT_FOUND`,
`SAML_FORBIDDEN`, `SAML_UNKNOWN_SP`, `SAML_SP_FORBIDDEN`,
`SAML_INVALID_AUTHN_REQUEST`, `SAML_SLO_FAILED`.

## Migration from `python3-saml`

FEAT-097 replaces `python3-saml`/`xmlsec` with `pysaml2`; the settings
surface changed accordingly. `SAMLAuth`'s public import path, routes, and
`SAML_MAPPING` semantics are unchanged — but the `SAML_SETTINGS` JSON blob
(if you use one) is now translated by
`navigator_auth.backends.saml.legacy.translate_legacy_settings`, which
only understands the keys below. **Any other key fails startup**, naming
every offending key (no best-effort/warn-only mode).

| Legacy key | Translated to |
|---|---|
| `strict` | Acknowledged, no direct `pysaml2` equivalent (no-op). |
| `sp.entityId` | SP `entityid` override. |
| `sp.assertionConsumerService.url` | SP ACS endpoint (`HTTP-POST`). |
| `sp.singleLogoutService.url` | SP SLO endpoint (`HTTP-Redirect`). |
| `sp.x509cert` / `sp.privateKey` | Raw PEM *content* (not a path) — spilled to a temp file and used as `cert_file`/`key_file`. |
| `idp.entityId` + `idp.singleSignOnService.url` (+ optional `idp.x509cert`, `idp.singleLogoutService.url`) | A minimal, unsigned inline IdP metadata document trusted by the SP. |
| `security.wantAssertionsSigned` | SP `want_assertions_signed`. |
| `security.wantMessagesSigned` | SP `want_response_signed`. |
| `security.authnRequestsSigned` | SP `authn_requests_signed`. |
| `security.nameIdEncrypted` | **Rejected** when truthy — encrypted `NameID` issuance from the IdP role is out of scope. |

Any other key — including the commonly-used `sp.assertionConsumerService.binding`,
`idp.singleSignOnService.binding`, or `sp.NameIDFormat` from the old
`settings.json` examples — is **not** translated and will fail startup.
Migrate those to the native `SAML_*` keys above (`SAML_BINDING`,
`SAML_ALLOW_UNSOLICITED`, etc.) instead of a `SAML_SETTINGS` blob where
possible.

`SAML_PATH` still works as a fallback for `SAMLAuth.get_idp_metadata()`:
when `SAML_METADATA` is unset, it looks for
`<SAML_PATH>/idp-metadata.xml`, then `<SAML_PATH>/certs/idp.crt` combined
with a legacy `SAML_SETTINGS` `idp` block.

## Troubleshooting

### "xmlsec1 binary not found"
Install the `xmlsec1` system package (see Prerequisites), or set
`SAML_XMLSEC_BINARY` to its full path.

### "Metadata not found"
Ensure `SAML_METADATA` (or the `SAML_PATH` fallback chain) points at a
readable file/URL.

### "SAML Response not valid" / `SAML_INVALID_SIGNATURE`
Verify the IdP's signing certificate matches what's in its metadata, and
that system clocks are synchronized (`SAML_CLOCK_SKEW` tolerates drift,
default 60s).

### `SAML_REPLAY`
An unsolicited (IdP-initiated) response was already consumed once; each
assertion ID is checked against a replay cache until its `NotOnOrAfter`.

### Redirect Loop / `RelayState` Dropped
Every redirect target derived from `RelayState` or `redirect_uri` is
host-validated against `ALLOWED_HOSTS` (SP role) or the SP's own ACS host
plus `allowed_relay_hosts` (IdP role); an off-host value is silently
dropped in favor of the default home redirect.
