"""
  Navigator Auth.

  Basic Toolkit for authentication/Authorization for aiohttp, using AsyncDB for Storage access.
"""
from .version import __author__, __description__, __title__, __version__, get_version

from .auth import AuthHandler


__all__ = ('AuthHandler', )
