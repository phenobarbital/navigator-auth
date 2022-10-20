from typing import Optional
from abc import ABC, abstractmethod
from collections.abc import Callable
import logging
from aiohttp import web
from asyncdb import AsyncDB, AsyncPool
from asyncdb.exceptions import ProviderError, DriverError


class AuthStorage(ABC):
    pool_based: bool = True
    timeout: int = 60

    _startup_: Optional[Callable] = None
    _shutdown_: Optional[Callable] = None

    def __init__(
        self,
        driver: str = "pg",
        dsn: str = "",
        params: dict = None,
        **kwargs
    ):
        self.driver = driver
        self.params = params
        self.kwargs = kwargs
        self._dsn = dsn
        # Empty Connection:
        self.conn: Callable = None

    def connection(self):
        return self.conn

    def configure(self, app: web.Application) -> None:
        """configure.
        Configure Connection Handler to connect on App initialization.
        """
        app.on_startup.append(
            self.startup
        )
        app.on_shutdown.append(
            self.shutdown
        )
        app.on_cleanup.append(
            self.cleanup
        )

    def is_connected(self) -> bool:
        return bool(self.conn.is_connected())

    @abstractmethod
    async def cleanup(self, app: web.Application):
        """Called when application ends.
        """

    async def startup(self, app: web.Application) -> None:
        try:
            if self.pool_based:
                self.conn = AsyncPool(
                    self.driver,
                    dsn=self._dsn,
                    params=self.params,
                    timeout=self.timeout,
                    **self.kwargs
                )
                await self.conn.connect()
            else:
                self.conn = AsyncDB(
                    self.driver,
                    dsn=self._dsn,
                    params=self.params,
                    timeout=self.timeout,
                    **self.kwargs
                )
                await self.conn.connection()
            logging.debug(f'Starting Auth DB driver={self.driver} On: {app}')
            app['authdb'] = self.conn
        except (ProviderError, DriverError) as ex:
            raise RuntimeError(
                f"Error creating DB {self.driver}: {ex}"
            ) from ex

    async def shutdown(self, app: web.Application) -> None:
        logging.debug(f'Closing Auth DB on App: {app!r}')
        try:
            await self.conn.close()
        finally:
            app['authdb'] = None
