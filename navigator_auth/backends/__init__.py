"""Navigator.

Authentication Backends.
"""
from .noauth import NoAuth
from .basic import BasicAuth
from .django import DjangoAuth
from .troc import TrocToken
from .token import TokenAuth
from .api import APIKeyAuth
# from .google import GoogleAuth
# from .okta import OktaAuth
# from .adfs import ADFSAuth
# from .azure import AzureAuth
# from .github import GithubAuth

__all__ = [
    "NoAuth",
    "BasicAuth",
    "DjangoAuth",
    "TrocToken",
    "TokenAuth",
    "APIKeyAuth",
    # "GoogleAuth",
    # "OktaAuth",
    # "ADFSAuth",
    # "AzureAuth",
    # 'GithubAuth'
]
