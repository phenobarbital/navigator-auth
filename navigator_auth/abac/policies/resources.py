"""
Resource.

Evaluates a Resource Object.
"""
from typing import List, Optional, Set, Pattern, Dict, Any
import logging
import re
import fnmatch
from enum import Enum
from dataclasses import dataclass, field
from navigator_auth.libs.parser import is_parseable


class ResourceType(Enum):
    """Types of resources in System."""
    TOOL = "tool"
    KB = "kb"
    VECTOR = "vector"
    AGENT = "agent"
    MCP = "mcp"
    URI = "uri"


class ActionType(Enum):
    """Standard actions for AI-Parrot resources."""
    # Tool actions
    TOOL_EXECUTE = "tool:execute"
    TOOL_LIST = "tool:list"
    TOOL_CONFIGURE = "tool:configure"

    # KB actions
    KB_QUERY = "kb:query"
    KB_WRITE = "kb:write"
    KB_ADMIN = "kb:admin"

    # Vector actions
    VECTOR_SEARCH = "vector:search"
    VECTOR_INSERT = "vector:insert"
    VECTOR_DELETE = "vector:delete"

    # Agent actions
    AGENT_CHAT = "agent:chat"
    AGENT_QUERY = "agent:query"
    AGENT_CONFIGURE = "agent:configure"


@dataclass(frozen=True, slots=True)
class ResourcePattern:
    """
    Immutable, hashable resource pattern for efficient matching.

    Supports:
    - Exact match: "tool:jira_create"
    - Wildcard: "tool:jira_*"
    - All: "tool:*"
    """
    resource_type: ResourceType
    pattern: str
    _regex: Pattern = field(default=None, compare=False, hash=False)

    def __post_init__(self):
        # Convert glob pattern to regex for efficient matching
        if '*' in self.pattern or '?' in self.pattern:
            regex_pattern = fnmatch.translate(self.pattern)
            object.__setattr__(self, '_regex', re.compile(regex_pattern))

    @classmethod
    def from_string(cls, resource_str: str) -> 'ResourcePattern':
        """Parse 'type:pattern' string into ResourcePattern."""
        try:
            type_str, pattern = resource_str.split(':', 1)
            try:
                resource_type = ResourceType(type_str)
            except ValueError:
                # Fallback for custom types or if defined as string
                resource_type = type_str
            return cls(resource_type=resource_type, pattern=pattern)
        except (ValueError, KeyError) as e:
            raise ValueError(f"Invalid resource pattern: {resource_str}") from e

    def matches(self, resource_name: str) -> bool:
        """Check if resource_name matches this pattern."""
        if self.pattern == '*':
            return True
        if self._regex:
            return bool(self._regex.match(resource_name))
        return self.pattern == resource_name

    def __hash__(self):
        return hash((self.resource_type, self.pattern))


@dataclass
class SubjectSpec:
    """Specification for policy subjects (who the policy applies to)."""
    groups: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)
    exclude_groups: Set[str] = field(default_factory=set)
    exclude_users: Set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, data: dict) -> 'SubjectSpec':
        """Create SubjectSpec from YAML dict."""
        return cls(
            groups=set(data.get('groups', [])),
            users=set(data.get('users', [])),
            roles=set(data.get('roles', [])),
            exclude_groups=set(data.get('exclude_groups', [])),
            exclude_users=set(data.get('exclude_users', []))
        )

    def matches_user(self, username: str, user_groups: Set[str], user_roles: Set[str] = None) -> bool:
        """Check if user matches this subject specification."""
        user_roles = user_roles or set()

        # Check exclusions first (deny takes precedence)
        if username in self.exclude_users:
            return False
        if self.exclude_groups & user_groups:
            return False

        # Check inclusions
        # Wildcard group means any authenticated user
        if '*' in self.groups:
            return True
        if username in self.users:
            return True
        if self.groups & user_groups:
            return True
        if self.roles & user_roles:
            return True

        # No explicit allow
        return False


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
