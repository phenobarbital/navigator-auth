import time
import jwt
import redis
from ...conf import (
    REDIS_URL,
    AUTH_CODE_EXPIRATION,
    AUTH_TOKEN_ISSUER,
    SECRET_KEY,
    AUTH_JWT_ALGORITHM
)

class CodeManagement:

    _codes: dict = {}

    def __init__(self):
        self.redis = redis.Redis(REDIS_URL)

    def create_code(self, payload: dict):
        expiration_date = time.time() + AUTH_CODE_EXPIRATION
        payload['exp'] = expiration_date
        payload['iss'] = AUTH_TOKEN_ISSUER
        authzcode = jwt.encode(
            payload,
            SECRET_KEY,
            algorithm=AUTH_JWT_ALGORITHM
        )
        self._codes[authzcode] = {
            **payload
        }

    def __getitem__(self, key):
        value = self.redis.get(key)
        if value is None:
            raise KeyError(key)
        return value.decode('utf-8')

    def __setitem__(self, key, value):
        self.redis.set(key, value)

    def __delitem__(self, key):
        self.redis.delete(key)

    def __contains__(self, key):
        return self.redis.exists(key)

    def __len__(self):
        return self.redis.dbsize()

    def keys(self):
        return [key.decode('utf-8') for key in self.redis.keys()]

    def values(self):
        return [value.decode('utf-8') for value in self.redis.mget(self.redis.keys())]

    def items(self):
        return [
            (key.decode('utf-8'), value.decode('utf-8'))
            for key, value in self.redis.items()
        ]
