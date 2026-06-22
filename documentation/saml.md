# SAML Authentication

Navigator Auth supports SAML 2.0 authentication using `python3-saml`. This allows integration with Identity Providers (IdP) such as Microsoft Entra ID (Azure AD), Okta, OneLogin, and others.

## Prerequisites

You must install the `python3-saml` library and its system dependencies.

**System Dependencies (Debian/Ubuntu):**
```bash
sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
```

**Python Dependency:**
```toml
[project.dependencies]
python3-saml = ">=1.16.0"
```

## Configuration

To enable SAML authentication, update your `navigator_auth` configuration (e.g., in `conf.py` or your application settings).

### 1. Enable the Backend

Add `navigator_auth.backends.SAMLAuth` to your `AUTHENTICATION_BACKENDS`.

```python
AUTHENTICATION_BACKENDS = (
    'navigator_auth.backends.SAMLAuth',
)
```

### 2. Configure Settings path

You need to tell `navigator-auth` where to find the SAML configuration files (`settings.json`, certificates).

```python
SAML_PATH = "/path/to/saml/directory"
```

The directory specified in `SAML_PATH` should contain:
- `settings.json`: The main configuration file.
- `advanced_settings.json`: (Optional) Advanced configuration.
- `certs/`: Directory containing your SP certificates.
    - `sp.key`: Your Private Key.
    - `sp.crt`: Your Public Certificate.
    - `idp.crt`: (Optional) The IdP Public Certificate if not embedded in `settings.json`.

Alternatively, you can provide settings directly as a JSON string (not recommended for secrets but useful for dynamic config):

```python
SAML_SETTINGS = '{"strict": true, "sp": { ... }, "idp": { ... }}'
```

### 3. Attribute Mapping

Map the SAML attributes returned by the IdP to Navigator Auth user attributes.

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

## `settings.json` Configuration

The `settings.json` file is where you configure the Service Provider (SP) - your app - and the Identity Provider (IdP).

### Example for Microsoft Entra ID

```json
{
    "strict": true,
    "debug": true,
    "sp": {
        "entityId": "https://<YOUR_DOMAIN>/api/v1/auth/saml/metadata",
        "assertionConsumerService": {
            "url": "https://<YOUR_DOMAIN>/auth/saml/callback/",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": "https://<YOUR_DOMAIN>/api/v1/auth/saml/logout",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": "<CONTENT_OF_YOUR_SP_CERTIFICATE_PEM>",
        "privateKey": "<CONTENT_OF_YOUR_SP_PRIVATE_KEY_PEM>"
    },
    "idp": {
        "entityId": "https://sts.windows.net/<TENANT_ID>/",
        "singleSignOnService": {
            "url": "https://login.microsoftonline.com/<TENANT_ID>/saml2",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "https://login.microsoftonline.com/<TENANT_ID>/saml2",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "<CONTENT_OF_IDP_CERTIFICATE_PROVIDED_BY_MICROSOFT>"
    }
}
```

### Key Settings

- **strict**: If `true`, checks if the response is valid, signature is correct, etc. ALWAYS set to `true` in production.
- **sp.entityId**: The unique identifier of your application.
- **sp.assertionConsumerService.url**: The URL where the IdP sends the SAML Response (Login Callback).
    - Default: `https://<YOUR_DOMAIN>/auth/saml/callback/`
- **idp.entityId**: Unique identifier of the IdP (from Entra ID Overview).
- **idp.x509cert**: The certificate used by Entra ID to sign the tokens.

## Troubleshooting

### "Metadata not found"
Ensure your `SAML_PATH` is correct and readable by the application process.

### "SAML Response not valid"
- Check if `strict` is true.
- Verify that your system clocks are synchronized.
- Ensure `idp.x509cert` matches exactly what is in Entra ID.

### Redirect Loop
Check if the `RelayState` is pointing recursively to the login page.
