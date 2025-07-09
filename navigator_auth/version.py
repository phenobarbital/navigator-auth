# -*- coding: utf-8 -*-
"""Navigator Auth Meta information.
Navigator-Auth add an authentication/authorization layer over an aiohttp application.
"""

__title__ = "navigator_auth"
__description__ = (
    "Navigator Auth is an Authentication/Authorization Toolkit for aiohttp."
)
__version__ = "0.15.8"  # pragma: no cover
__author__ = "Jesus Lara"
__author_email__ = "jesuslarag@gmail.com"
__copyright__ = "Copyright (c) 2019-2025 Jesus Lara"
__license__ = "Apache 2.0 License"


def get_version() -> tuple:    # pragma: no cover
    """
    Get nav-auth version as tuple.
    """
    return tuple(__version__.split("."))
