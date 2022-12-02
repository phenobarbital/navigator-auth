import logging
from aiohttp import web
from .abstract import AuthStorage



class RedisStorage(AuthStorage):
    driver: str = 'redis'
    name: str = 'redis'
    pool_based: bool = False
    timeout: int = 60

    def __init__(
        self,
        driver: str = "redis",
        dsn: str = "",
        params: dict = None,
        **kwargs
    ):
        super(RedisStorage, self).__init__(
            driver=driver,
            dsn=dsn,
            params=params,
            **kwargs
        )

    async def shutdown(self, app: web.Application):
        pass

    async def cleanup(self, app: web.Application):
        """Called when application ends.
        """
        logging.debug(" === Closing Auth Redis Connections === ")
        try:
            if self.conn:
                await self.conn.close()
        finally:
            app['redis'] = None
