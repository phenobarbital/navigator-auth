"""DB (asyncdb) Extension.
DB connection for any Application.
"""
from collections.abc import Callable
from navconfig.logging import logging
from asyncdb import AsyncDB
from asyncdb.exceptions import ProviderError, DriverError
from navigator_auth.exceptions import AuthException, ConfigError
from .abstract import AbstractStorage


class DBStorage(AbstractStorage):
    """DBStorage.

    Description: Abstract Storage for any asyncdb-based DB connection for loading policies.

    Args:
        dsn (str): default DSN (if none, use default.)
        params (dict): optional connection parameters (if DSN is none)

    Raises:
        RuntimeError: Some exception raised.
        web.InternalServerError: Database connector is not installed.

    Returns:
        A collection of Policies loaded from Storage.
    """
    name: str = 'asyncdb'
    driver: str = 'pg'
    timeout: int = 10

    def __init__(
            self,
            driver: str = 'pg',
            dsn: str = None,
            **kwargs
        ) -> None:
        self.driver = driver
        try:
            self.timeout = kwargs['timeout']
            del kwargs['timeout']
        except KeyError:
            pass
        try:
            self.params = kwargs['params']
            del kwargs['params']
        except KeyError:
            self.params = {}
        super(DBStorage, self).__init__(
            **kwargs
        )
        self.conn: Callable = None
        self._dsn: str = dsn
        if not self._dsn and not self.params:
            raise ConfigError(
                "DB: No DSN or Parameters for DB connection."
            )

    def connection(self):
        try:
            self.conn = AsyncDB(
                self.driver,
                dsn=self._dsn,
                params=self.params,
                timeout=self.timeout
            )
            self.conn.output_format('iterable')
            return self.conn
        except (ProviderError, DriverError) as err:
            logging.exception(
                f"Error on Startup {self.name} Backend: {err!s}"
            )
            raise AuthException(
                f"Error on Startup {self.name} Backend: {err!s}"
            ) from err


    async def close(self):
        try:
            await self.conn.close()
        except AttributeError:
            pass
        except ProviderError as err:
            raise AuthException(
                f"Error on Closing Connection {self.name}: {err!s}"
            ) from err

    async def load_policies(self):
        """load_policies.

        Load all Policies from Storage.
        """
