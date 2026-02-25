import asyncio
from aiohttp import web
from navigator_auth.handlers.vault import VaultView

async def main():
    app = web.Application()
    
    # Mocking necessary components
    app["authdb"] = "db_pool"
    app["redis"] = "redis"
    
    # Mock get_session and vault
    async def mock_get_session(request, new=False):
        return {"user": {}}
    
    import navigator_auth.handlers.vault as vault_module
    vault_module.get_session = mock_get_session
    
    class MockVault:
        async def keys(self):
            return ["key1", "key2"]
            
        async def exists(self, key):
            return True
            
        async def get(self, key):
            return "value"
            
    async def mock_get_vault(self, session):
        return MockVault()
        
    VaultView._get_vault = mock_get_vault
    
    app.router.add_view("/api/v1/user/vault", VaultView)
    app.router.add_view("/api/v1/user/vault/{key}", VaultView)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()

    print("Server ready")
    await asyncio.sleep(60)

if __name__ == '__main__':
    asyncio.run(main())
