"""
Resource.

Evaluates a Resource Object.
"""
from typing import List
import re

class Resource:
    def __init__(self, value):
        self._negative = False
        self.namespace: str = None
        self.resource_subtype: str = None
        self.resource_parts: List[str] = []
        try:
            self.resource_type, self.raw_value = value.split(':', 1)
        except (ValueError, TypeError):
            self.resource_type = 'uri'
            self.raw_value = value

        if self.resource_type == 'urn':
            self.resource_type, self.namespace, *self.resource_parts = re.split('[:|::]', self.raw_value)

        if self.resource_type == 'uri':
            self.raw_value = self.namespace
            self.resource_subtype = 'uri'
            if self.raw_value.startswith('!'):
                self._negative = True
                self.raw_value = self.raw_value[1:]

        self.is_regex = False
        try:
            self.value = re.compile(f'^{self.raw_value}$')
            self.is_regex = True
        except re.error:
            logging.warning(f'Resource {value} is not a Regular Expression.')
            self.value = self.raw_value

    def __str__(self) -> str:
        return self.raw_value

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.resource_type}: {self.value!r})>"

    def is_negative(self):
        return self._negative

    def match_uri(self, value):
        if self.is_regex:
            return self.value.match(value)
        elif self.raw_value == '*':
            return True
        else:
            return self.raw_value == value

    def match(self, value):
        if self.resource_type == 'uri':
            return self.match_uri(value)
        elif self.resource_type == 'urn':
            if self.resource_subtype == 'uri':
                return self.match_uri(value)
            else:
                raise ValueError(
                    f"Unsupported resource subtype: {self.resource_subtype}"
                )
        return False
