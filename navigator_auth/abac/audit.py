import asyncio
from datetime import datetime
import socket
from navconfig.logging import logger
from asyncdb import AsyncDB
from asyncdb.exceptions import DriverError
from navigator_auth.exceptions import ConfigError
from navigator_auth.conf import (
    ENVIRONMENT,
    DOMAIN,
    AUDIT_BACKEND,
    AUDIT_CREDENTIALS,
    ENABLE_AUDIT_LOG
)


class AuditLog:
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        if ENABLE_AUDIT_LOG is True:
            try:
                self.logger = AsyncDB(
                    AUDIT_BACKEND,
                    params=AUDIT_CREDENTIALS,
                    loop=self.loop
                )
                self.host = socket.gethostbyname(socket.gethostname())
            except DriverError as ex:
                raise ConfigError(
                    f"Unable to start Audit Backend: {ex}"
                ) from ex
        else:
            self.logger = logger

    async def log(self, answer, status, user):
        start_time = datetime.utcnow()
        if ENABLE_AUDIT_LOG is True:
            async with await self.logger.connection() as conn:
                try:
                    data = {
                        "measurement": 'audit',
                        "location": ENVIRONMENT,
                        "domain": DOMAIN,
                        "timestamp": start_time,
                        "fields": {
                            "status": status
                        },
                        "tags": {
                            "host": self.host,
                            "region": ENVIRONMENT,
                            "message": answer.response,
                            "answer": answer,
                            "username": user.username,
                            "user": user.id
                        }
                    }
                    await conn.write(data, bucket=AUDIT_CREDENTIALS['bucket'])
                except (TypeError, AttributeError, ValueError, DriverError) as ex:
                    logger.error(
                        f'Error saving Audit Log: {ex}'
                    )
        else:
            message = f'Access {status} by: {answer.response} to user {user.username}'
            self.logger.info(message)
