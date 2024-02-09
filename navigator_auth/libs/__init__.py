"""
JSON Encoders.
"""
from .json import JSONContent

class DefaultEncoder:
    """
    Encoder replacement for json.dumps using orjson
    """
    def __init__(self, *args, **kwargs):
        encoder = JSONContent(*args, **kwargs)
        self.encode = encoder.__call__
