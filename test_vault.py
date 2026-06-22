import asyncio
from aiohttp import web
from navigator_auth.handlers.vault import VaultView

print("VaultView.get:", VaultView.get)
print("VaultView.get.__name__:", VaultView.get.__name__)
print("VaultView.post:", VaultView.post)
print("VaultView.post.__name__:", VaultView.post.__name__)

v = VaultView(None)
print("v.get:", v.get)

# Let's inspect what happens to the methods
print("VaultView.get.__wrapped__:", getattr(VaultView.get, "__wrapped__", None))
print("VaultView.post.__wrapped__:", getattr(VaultView.post, "__wrapped__", None))
