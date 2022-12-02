# -*- coding: utf-8 -*-
"""Navigator Auth Meta information.
   Navigator Auth allows us to authenticate/authorize users over an aiohttp application.
"""

__title__ = 'navigator_auth'
__description__ = ('Navigator Auth is an Authentication/Authorization '
                   'Toolkit for aiohttp.')
__version__ = '0.3.32'  # pragma: no cover
__author__ = 'Jesus Lara'
__author_email__ = 'jesuslarag@gmail.com'
__license__ = 'Apache 2.0 license'


def get_version() -> tuple: # pragma: no cover
   """
   Get nav-auth version as tuple.
   """
   return tuple(x for x in __version__.split('.')) # pragma: no cover
