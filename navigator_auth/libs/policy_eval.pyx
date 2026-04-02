# cython: language_level=3, boundscheck=False, wraparound=False
"""
Cython-accelerated policy evaluation for navigator-auth PBAC.

Provides fast pattern matching and condition evaluation for resource
filtering. Falls back to pure Python when Cython is not compiled.
"""
import re
from fnmatch import translate as fnmatch_translate


cdef class PatternMatcher:
    """Fast pattern matcher with compiled regex caching."""
    cdef dict _cache
    cdef int _cache_size

    def __cinit__(self, int cache_size=4096):
        self._cache = {}
        self._cache_size = cache_size

    cpdef bint match_pattern(self, str pattern, str resource):
        """Match a resource name against a glob pattern.

        Supports:
        - Exact match: "jira_create"
        - Wildcard: "jira_*"
        - All: "*"

        Args:
            pattern: Glob pattern string.
            resource: Resource name to match.

        Returns:
            True if the resource matches the pattern.
        """
        if pattern == '*':
            return True
        if '*' not in pattern and '?' not in pattern:
            return pattern == resource

        # Use cached compiled regex
        cdef object compiled
        compiled = self._cache.get(pattern)
        if compiled is None:
            regex_str = fnmatch_translate(pattern)
            compiled = re.compile(regex_str)
            if len(self._cache) < self._cache_size:
                self._cache[pattern] = compiled
        return compiled.match(resource) is not None


cdef PatternMatcher _default_matcher = PatternMatcher()


def match_pattern(str pattern, str resource) -> bool:
    """Fast glob pattern matching for resource names.

    Module-level convenience function using a shared PatternMatcher.

    Args:
        pattern: Glob pattern (e.g., "jira_*").
        resource: Resource name to check (e.g., "jira_create").

    Returns:
        True if the resource matches the pattern.
    """
    return _default_matcher.match_pattern(pattern, resource)


def evaluate_conditions(dict env_dict, dict conditions) -> bool:
    """Evaluate environment conditions against current environment.

    Args:
        env_dict: Current environment as dict (hour, dow, is_business_hours, etc.).
        conditions: Required conditions as dict.

    Returns:
        True if all conditions are satisfied.
    """
    cdef str key
    cdef object expected, actual

    for key, expected in conditions.items():
        actual = env_dict.get(key)
        if actual is None:
            continue

        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, dict):
            # Range check: {"min": 8, "max": 18}
            if 'min' in expected and actual < expected['min']:
                return False
            if 'max' in expected and actual > expected['max']:
                return False
        else:
            if actual != expected:
                return False

    return True


def filter_resources_batch(
    list policies,
    list resources,
    dict user,
    dict env,
) -> dict:
    """Batch filter resources against policies.

    Cython-accelerated version of resource filtering. Each policy is a dict
    with keys: name, effect, resources (list of "type:pattern"), actions,
    subjects (dict with groups/users/roles), conditions (dict), priority, enforcing.

    Args:
        policies: List of policy dicts.
        resources: List of resource strings (e.g., ["tool:jira_create"]).
        user: Dict with username, groups, roles.
        env: Dict with hour, dow, is_business_hours, etc.

    Returns:
        Dict with "allowed" and "denied" lists.
    """
    cdef list allowed = []
    cdef list denied = []
    cdef str resource
    cdef dict policy
    cdef str action

    action = user.get('action', '')
    user_groups = set(user.get('groups', []))
    user_roles = set(user.get('roles', []))
    username = user.get('username', '')

    for resource in resources:
        if _evaluate_single(
            policies, resource, action,
            username, user_groups, user_roles, env
        ):
            allowed.append(resource)
        else:
            denied.append(resource)

    return {'allowed': allowed, 'denied': denied}


cdef bint _evaluate_single(
    list policies,
    str resource,
    str action,
    str username,
    set user_groups,
    set user_roles,
    dict env,
):
    """Evaluate a single resource against all policies."""
    cdef int best_allow_priority = -1
    cdef int best_deny_priority = -1
    cdef bint has_allow = False
    cdef bint has_deny = False
    cdef dict policy
    cdef int priority

    for policy in policies:
        # Check resource coverage
        if not _policy_covers_resource(policy, resource):
            continue

        # Check action coverage
        policy_actions = policy.get('actions', [])
        if policy_actions and action not in policy_actions:
            continue

        # Check subject match
        if not _matches_subject(policy, username, user_groups, user_roles):
            continue

        # Check environment conditions
        conditions = policy.get('conditions', {})
        env_conditions = conditions.get('environment', {}) if isinstance(conditions, dict) else {}
        if env_conditions and not evaluate_conditions(env, env_conditions):
            continue

        # Policy matches
        effect = policy.get('effect', 'deny').lower()
        priority = policy.get('priority', 0)
        is_allow = effect == 'allow'

        # Enforcing policy — immediate return
        if policy.get('enforcing', False):
            return is_allow

        if is_allow:
            has_allow = True
            if priority > best_allow_priority:
                best_allow_priority = priority
        else:
            has_deny = True
            if priority > best_deny_priority:
                best_deny_priority = priority

    # Deny takes precedence at equal priority
    if has_deny and has_allow:
        return best_allow_priority > best_deny_priority
    if has_allow:
        return True
    return False


cdef bint _policy_covers_resource(dict policy, str resource):
    """Check if a policy covers the given resource."""
    cdef list res_patterns = policy.get('resources', [])
    if not res_patterns:
        return True  # No restriction

    cdef str pattern, ptype, pname, rtype, rname

    # Split resource into type:name
    parts = resource.split(':', 1)
    if len(parts) != 2:
        return False
    rtype = parts[0]
    rname = parts[1]

    for pattern in res_patterns:
        pparts = pattern.split(':', 1)
        if len(pparts) != 2:
            continue
        ptype = pparts[0]
        pname = pparts[1]
        if ptype == rtype and _default_matcher.match_pattern(pname, rname):
            return True

    return False


cdef bint _matches_subject(
    dict policy, str username, set user_groups, set user_roles
):
    """Check if user matches policy subjects."""
    cdef dict subjects = policy.get('subjects', {})
    if not subjects:
        return True  # No subject restriction

    # Check exclusions
    exclude_users = subjects.get('exclude_users', [])
    if username in exclude_users:
        return False
    exclude_groups = set(subjects.get('exclude_groups', []))
    if exclude_groups & user_groups:
        return False

    # Check inclusions
    groups = subjects.get('groups', [])
    users = subjects.get('users', [])
    roles = subjects.get('roles', [])

    if '*' in groups:
        return True
    if username in users:
        return True
    if set(groups) & user_groups:
        return True
    if set(roles) & user_roles:
        return True

    # No subjects specified at all = match everyone
    return not groups and not users and not roles
