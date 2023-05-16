"""
Resource.

Evaluates a Resource Object.
"""
from typing import List
import logging
import re
from navigator_auth.libs.parser import is_parseable


class RequestResource:
    def __init__(self, value):
        self._negative = False
        self.namespace: str = None
        self.resource_subtype: str = None
        self.resource_parts: List[str] = []
        self.is_regex: bool = False
        try:
            self.resource_type, self.raw_value = value.split(':', 1)
        except (ValueError, TypeError):
            self.resource_type = 'uri'
            self.raw_value = value

        if self.resource_type == 'urn':
            if self.raw_value.startswith('uri:'):
                self.resource_type, self.namespace, *self.resource_parts = re.split('[:|::]', self.raw_value)
            else:
                self.namespace, self.resource_type, *self.resource_parts = re.split('[:|::]', self.raw_value)

        if self.resource_type == 'uri':
            if self.namespace is not None:
                self.raw_value = self.namespace
            self.resource_subtype = 'uri'
            self.value = self.raw_value
        else:
            ## converting "resource_parts" to objects
            elements = []
            for el in self.resource_parts:
                if el:
                    if (obj := is_parseable(el)):
                        try:
                            value = obj(el)
                        except ValueError:
                            value = el
                        elements += value
                    else:
                        if el == '*':
                            elements = el
                        else:
                            elements.append(el)
            self.value = elements

    def __str__(self) -> str:
        if self.raw_value is None:
            return ''
        return self.raw_value

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.resource_type}: {self.value!r})>"

class Resource:
    def __init__(self, value):
        self._negative = False
        self.namespace: str = None
        self.resource_subtype: str = None
        self.resource_parts: List[str] = []
        self.is_regex: bool = False
        try:
            self.resource_type, self.raw_value = value.split(':', 1)
        except (ValueError, TypeError):
            self.resource_type = 'uri'
            self.raw_value = value

        if self.resource_type == 'urn':
            if self.raw_value.startswith('uri:'):
                self.resource_type, self.namespace, *self.resource_parts = re.split('[:|::]', self.raw_value)
            else:
                self.namespace, self.resource_type, *self.resource_parts = re.split('[:|::]', self.raw_value)

        if self.resource_type == 'uri':
            if self.namespace is not None:
                self.raw_value = self.namespace
            self.resource_subtype = 'uri'
            if self.raw_value.startswith('!'):
                self._negative = True
                self.raw_value = self.raw_value[1:]
        else:
            ## converting "resource_parts" to objects
            elements = []
            # print(' EVAL ', self.resource_type, self.namespace, self.resource_parts)
            for el in self.resource_parts:
                # print('EL > ', el)
                if el:
                    if (obj := is_parseable(el)):
                        try:
                            value = obj(el)
                        except ValueError:
                            value = el
                        elements += value
                    else:
                        try:
                            val = re.compile(f'^{el}$')
                            self.is_regex = True
                            elements.append(val)
                        except re.error:
                            if el == '*':
                                elements = el
                            else:
                                elements.append(el)
            self.resource_parts = elements
            if elements:
                ## disable using raw value
                self.raw_value = None
                self.value = None
        try:
            if self.raw_value is not None:
                self.value = re.compile(f'^{self.raw_value}$')
                self.is_regex = True
        except re.error:
            logging.warning(f'Resource {value} is not a Regular Expression.')
            self.value = self.raw_value
        ##
        if not self.resource_parts:
            self.resource_parts = []

    def __str__(self) -> str:
        if self.raw_value is None:
            return ''
        return self.raw_value

    def __repr__(self) -> str:
        if self.resource_parts:
            return f"<{type(self).__name__}({self.resource_type}: {self.resource_parts!r})>"
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

    def match_generic(self, ctx):
        try:
            value = ctx.get(self.resource_type)
        except AttributeError:
            value = ctx
        except KeyError:
            ### this resource doesn't match with any objects
            return False
        if isinstance(value, list):
            # Check if there are any elements in 'value' that are not in
            # the negated elements of resource_parts and are
            # not in the non-negated elements of resource_parts
            non_negated_elements = []
            negated_elements = []

            for elem in self.resource_parts:
                if isinstance(elem, re.Pattern):
                    non_negated_elements.append(elem)
                elif elem.startswith('!'):
                    negated_elements.append(elem.lstrip('!'))
                else:
                    non_negated_elements.append(elem)

            # non_negated_elements = [elem for elem in self.resource_parts if not elem.startswith('!')]
            # negated_elements = [elem.lstrip('!') for elem in self.resource_parts if elem.startswith('!')]
            if any(elem not in negated_elements and elem in non_negated_elements for elem in value):
                return True
            elif self.resource_parts == '*':
                return True
            else:
                return False
        if isinstance(self.resource_parts, list) and value in self.resource_parts:
            return True

        # Check if value matches any regex in self.resource_parts
        for resource_part in self.resource_parts:
            val = value
            if value is None:
                val = ''
            if isinstance(resource_part, re.Pattern) and resource_part.match(val):
                return True
        # If value is not in self.resource_parts and doesn't match any regex
        return False

    def match(self, value):
        if self.resource_type == 'uri':
            return self.match_uri(value)
        else:
            return self.match_generic(value)
        return False
