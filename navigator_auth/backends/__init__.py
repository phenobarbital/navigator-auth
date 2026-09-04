"""Navigator.

Authentication Backends.
"""
from navconfig.logging import logging
from .noauth import NoAuth
from .basic import BasicAuth
from .django import DjangoAuth
from .troc import TrocToken
from .token import TokenAuth
from .api import APIKeyAuth
from .google import GoogleAuth
from .okta import OktaAuth
from .adfs import ADFSAuth
from .azure import AzureAuth
from .github import GithubAuth
from .odoo import OdooAuth
from .oauth2 import Oauth2Provider
from .exchange import TokenExchangeAuth

# TODO(FEAT-097/TASK-060): `saml.py` (python3-saml/onelogin) is being replaced
# by the `saml/` package (pysaml2). `python3-saml` was removed from
# pyproject.toml in TASK-054, so this legacy module cannot import until the
# `saml/` package lands and `saml.py` is deleted (TASK-060). Guarded so the
# rest of the package keeps importing meanwhile.
try:
    from .saml import SAMLAuth
except ImportError as exc:
    logging.getLogger("Auth.Backends").warning(
        f"Legacy SAMLAuth (python3-saml) is unavailable, pending FEAT-097 migration: {exc}"
    )
    SAMLAuth = None


__all__ = (
    "NoAuth",
    "BasicAuth",
    "DjangoAuth",
    "TrocToken",
    "TokenAuth",
    "APIKeyAuth",
    "GoogleAuth",
    "OktaAuth",
    "ADFSAuth",
    "AzureAuth",
    "GithubAuth",
    "OdooAuth",
    "Oauth2Provider",
    "SAMLAuth",
    "TokenExchangeAuth",
)
