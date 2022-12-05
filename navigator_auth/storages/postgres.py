import logging
from aiohttp import web
from .abstract import AuthStorage



class PostgresStorage(AuthStorage):
    driver: str = "pg"
    name: str = 'authdb'
    pool_based: bool = True
    timeout: int = 3600

    def __init__(
        self,
        driver: str = "pg",
        dsn: str = "",
        params: dict = None,
        **kwargs
    ):
        kwargs = {
            "min_size": 2,
            "max_size": 100,
            "server_settings": {
                "application_name": 'NAV-AUTH',
                "client_min_messages": "notice",
                "max_parallel_workers": "48",
                "jit": "off",
                "statement_timeout": "36000",
                "idle_in_transaction_session_timeout": '5min',
                "effective_cache_size": "2147483647"
            },
        }
        super(PostgresStorage, self).__init__(
            driver=driver,
            dsn=dsn,
            params=params,
            **kwargs
        )

    async def shutdown(self, app: web.Application):
        logging.debug(" === Closing Auth Postgres Connections === ")
        try:
            if self.conn:
                await self.conn.wait_close(gracefully=True, timeout=2)
        finally:
            app['authdb'] = None
            logging.debug("Exiting ...")

    async def cleanup(self, app: web.Application):
        """Called when application ends.
        """
