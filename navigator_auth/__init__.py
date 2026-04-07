"""
  Navigator Auth.

  Basic Toolkit for authentication/Authorization for aiohttp,
  using AsyncDB for Storage access.
"""
from .version import __author__, __description__, __title__, __version__, get_version

from .auth import AuthHandler
from .uv import install_uvloop

# Try to import the Rust extension (navigator_auth_pep)
try:
    import navigator_auth_pep
except ImportError:
    navigator_auth_pep = None

install_uvloop()

__all__ = ("AuthHandler", "navigator_auth_pep")
