from typing import Any
from collections.abc import MutableMapping, Iterator
import time
from datetime import datetime
from aiohttp import web
from datamodel import BaseModel

class EvalContext(dict, MutableMapping):
    """EvalContext.

    Build The Evaluation Context from Request and User Data.
    """
    def __init__(self, request: web.Request, user: Any, userinfo: Any, session: Any, *args, **kwargs):
        ## initialize the mutable mapping:
        self.store = dict()
        self.store['ip_addr'] = request.remote
        self.store['method'] = request.method
        self.store['referer'] = request.headers.get('referer', None)
        self.store['time'] = time.time()
        dow = datetime.today().weekday()
        self.store['dow'] = dow
        self.store['day_of_week'] = dow
        self.store['path_qs'] = request.path_qs
        self.store['path'] = request.path
        self.store['headers'] = request.headers
        self.store['url'] = request.rel_url
        self.store['user'] = user
        if isinstance(user, BaseModel):
            self.store['user_keys'] = user.get_fields()
        else:
            self.store['user_keys'] = user.__dict__.keys()
        self.store['userinfo'] = userinfo
        if isinstance(userinfo, dict):
            self.store['userinfo_keys'] = list(userinfo.keys())
        else:
            self.store['userinfo_keys'] = userinfo.__dict__.keys()
        self.store['session'] = session
        self.update(*args, **kwargs)
        self._columns = list(self.store.keys())

    def __missing__(self, key):
        return False

    def items(self) -> zip:  # type: ignore
        return zip(self._columns, self.store)

    def keys(self) -> list:
        return self._columns

    def set(self, key, value) -> None:
        self.store[key] = value
        if not key in self._columns:
            self._columns.append(key)

    ### Section: Simple magic methods
    def __len__(self) -> int:
        return len(self.store)

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.store})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.store})>"

    def __contains__(self, key: str) -> bool:
        return key in self._columns

    def __iter__(self) -> Iterator:
        for value in self.store:
            yield value

    def __delitem__(self, key) -> None:
        value = self.store[key]
        del self.store[key]
        self._columns.pop(value, None)

    def __setitem__(self, key, value):
        self.store[key] = value
        if not key in self._columns:
            self._columns.append(key)

    def __getattr__(self, key):
        try:
            return super().__getattribute__('store')[key]
        except KeyError as ex:
            raise AttributeError(key) from ex

    def __setattr__(self, key, value):
        if key == 'store':
            super().__setattr__(key, value)
        else:
            self.store[key] = value

    def __delattr__(self, key):
        try:
            del self.store[key]
        except KeyError as ex:
            raise AttributeError(key) from ex
