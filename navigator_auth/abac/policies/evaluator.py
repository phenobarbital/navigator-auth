"""
Efficient Policy Evaluator for AI-Parrot.

Features:
- YAML policy loading with validation
- Indexed lookups by resource type
- LRU caching for repeated evaluations
- Async-compatible design
"""
from __future__ import annotations
from typing import Optional, List, Dict, Set, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
from functools import lru_cache
from collections import defaultdict
import hashlib
import time
import yaml
import logging

from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies.resource_policy import ResourcePolicy

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    """Result of policy evaluation with metadata."""
    allowed: bool
    effect: PolicyEffect
    matched_policy: Optional[str] = None
    reason: str = ""
    evaluation_time_ms: float = 0.0
    cached: bool = False

    def __bool__(self):
        return self.allowed


@dataclass
class FilteredResources:
    """Result of filtering resources by permissions."""
    allowed: List[str] = field(default_factory=list)
    denied: List[str] = field(default_factory=list)
    policies_applied: List[str] = field(default_factory=list)


class PolicyIndex:
    """
    Indexed policy storage for O(1) lookups by resource type.

    Maintains sorted order by priority within each resource type.
    """

    def __init__(self):
        self._by_type: Dict[ResourceType, List[ResourcePolicy]] = defaultdict(list)
        self._by_name: Dict[str, ResourcePolicy] = {}
        self._enforcing: List[ResourcePolicy] = []
        self._all_policies: List[ResourcePolicy] = []

    def add(self, policy: ResourcePolicy) -> None:
        """Add policy to index."""
        self._by_name[policy.name] = policy
        self._all_policies.append(policy)

        # Index by resource type
        for resource_type in policy._patterns_by_type.keys():
            self._by_type[resource_type].append(policy)

        # Track enforcing policies
        if policy.enforcing:
            self._enforcing.append(policy)

        # Re-sort by priority (higher priority = evaluated first)
        for policies in self._by_type.values():
            policies.sort(key=lambda p: -p.priority)
        self._enforcing.sort(key=lambda p: -p.priority)
        self._all_policies.sort(key=lambda p: -p.priority)

    def get_for_resource_type(self, resource_type: ResourceType) -> List[ResourcePolicy]:
        """Get policies that might apply to this resource type."""
        return self._by_type.get(resource_type, [])

    def get_enforcing(self) -> List[ResourcePolicy]:
        """Get enforcing policies (evaluated first, stop on match)."""
        return self._enforcing

    def get_by_name(self, name: str) -> Optional[ResourcePolicy]:
        """Get policy by name."""
        return self._by_name.get(name)

    def all(self) -> List[ResourcePolicy]:
        """Get all policies sorted by priority."""
        return self._all_policies


class PolicyLoader:
    """
    Load and validate policies from YAML files.
    """

    @staticmethod
    def load_from_file(path: Path) -> List[ResourcePolicy]:
        """Load policies from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return PolicyLoader.load_from_dict(data)

    @staticmethod
    def load_from_dict(data: dict) -> List[ResourcePolicy]:
        """Load policies from parsed YAML dict."""
        policies = []
        default_effect = data.get('defaults', {}).get('effect', 'deny')

        for policy_data in data.get('policies', []):
            try:
                # Parse effect
                effect_str = policy_data.get('effect', default_effect)
                effect = PolicyEffect.ALLOW if effect_str == 'allow' else PolicyEffect.DENY

                # Parse subjects
                subjects_data = policy_data.get('subjects', {})

                policy = ResourcePolicy(
                    name=policy_data['name'],
                    description=policy_data.get('description'),
                    effect=effect,
                    resources=policy_data.get('resources', []),
                    actions=policy_data.get('actions', []),
                    subjects=subjects_data,
                    conditions=policy_data.get('conditions', {}).get('context', {}),
                    environment=policy_data.get('conditions', {}).get('environment', {}),
                    priority=policy_data.get('priority', 0),
                    enforcing=policy_data.get('enforcing', False)
                )
                policies.append(policy)
                logger.debug(f"Loaded policy: {policy.name}")

            except Exception as e:
                logger.error(f"Failed to load policy {policy_data.get('name', 'unknown')}: {e}")
                # We log but continue loading other policies
                pass

        return policies

    @staticmethod
    def load_from_directory(directory: Path) -> List[ResourcePolicy]:
        """Load all policy files from directory."""
        policies = []
        for path in directory.glob('*.yaml'):
            policies.extend(PolicyLoader.load_from_file(path))
        for path in directory.glob('*.yml'):
            policies.extend(PolicyLoader.load_from_file(path))
        return policies


class PolicyEvaluator:
    """
    High-performance policy evaluator with caching.

    Features:
    - LRU cache for repeated evaluations
    - Short-circuit on enforcing policies
    - Deny-by-default security model

    Example:
        evaluator = PolicyEvaluator()
        evaluator.load_policies_from_file("policies.yaml")

        result = evaluator.check_access(
            ctx=eval_context,
            resource_type=ResourceType.TOOL,
            resource_name="jira_create",
            action="tool:execute"
        )

        if result.allowed:
            # Execute tool
    """

    def __init__(
        self,
        default_effect: PolicyEffect = PolicyEffect.DENY,
        cache_size: int = 1024,
        cache_ttl_seconds: int = 300
    ):
        self._index = PolicyIndex()
        self._default_effect = default_effect
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, Tuple[EvaluationResult, float]] = {}
        self._stats = {
            'evaluations': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

    def load_policies(self, policies: List[ResourcePolicy]) -> None:
        """Load policies into evaluator."""
        for policy in policies:
            self._index.add(policy)
        logger.info(f"Loaded {len(policies)} policies")

    def load_from_file(self, path: Path) -> None:
        """Load policies from YAML file."""
        policies = PolicyLoader.load_from_file(path)
        self.load_policies(policies)

    def load_from_directory(self, directory: Path) -> None:
        """Load all policies from directory."""
        policies = PolicyLoader.load_from_directory(directory)
        self.load_policies(policies)

    def _make_cache_key(
        self,
        user_id: str,
        user_groups: Set[str],
        resource_type: ResourceType,
        resource_name: str,
        action: str
    ) -> str:
        """Generate cache key for evaluation."""
        groups_str = ','.join(sorted(user_groups))
        key_data = f"{user_id}|{groups_str}|{resource_type.value}|{resource_name}|{action}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _check_cache(self, cache_key: str) -> Optional[EvaluationResult]:
        """Check cache for previous evaluation result."""
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                self._stats['cache_hits'] += 1
                result.cached = True
                return result
            else:
                # Expired
                del self._cache[cache_key]
        self._stats['cache_misses'] += 1
        return None

    def _update_cache(self, cache_key: str, result: EvaluationResult) -> None:
        """Update cache with evaluation result."""
        # Simple LRU: remove oldest if at capacity
        if len(self._cache) >= self._cache_size:
            try:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]
            except ValueError:
                pass # Cache is empty
        self._cache[cache_key] = (result, time.time())

    def invalidate_cache(self, user_id: str = None) -> None:
        """Invalidate cache entries, optionally for specific user."""
        if user_id:
            # Remove entries for specific user
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(user_id)]
            for k in keys_to_remove:
                del self._cache[k]
        else:
            self._cache.clear()

    def check_access(
        self,
        ctx: EvalContext,
        resource_type: ResourceType,
        resource_name: str,
        action: str,
        env: Environment = None
    ) -> EvaluationResult:
        """
        Check if access is allowed for the given resource and action.

        This is the main entry point for permission checks.

        Args:
            ctx: Evaluation context with user info
            resource_type: Type of resource (TOOL, KB, VECTOR, etc.)
            resource_name: Specific resource name
            action: Action being attempted
            env: Optional environment (defaults to current time)

        Returns:
            EvaluationResult with allowed status and metadata
        """
        start_time = time.perf_counter()
        self._stats['evaluations'] += 1

        # Get user info for cache key
        try:
            user_id = ctx.userinfo.get('username', ctx.userinfo.get('user_id', 'anonymous'))
            user_groups = set(ctx.userinfo.get('groups', []))
        except (AttributeError, TypeError):
            user_id = 'anonymous'
            user_groups = set()

        # Check cache
        cache_key = self._make_cache_key(user_id, user_groups, resource_type, resource_name, action)
        cached_result = self._check_cache(cache_key)
        if cached_result:
            return cached_result

        # Create environment if not provided
        if env is None:
            env = Environment()

        # Evaluate policies
        result = self._evaluate_policies(ctx, env, resource_type, resource_name, action)

        # Record timing
        result.evaluation_time_ms = (time.perf_counter() - start_time) * 1000

        # Cache result
        self._update_cache(cache_key, result)

        return result

    def _evaluate_policies(
        self,
        ctx: EvalContext,
        env: Environment,
        resource_type: ResourceType,
        resource_name: str,
        action: str
    ) -> EvaluationResult:
        """
        Internal policy evaluation logic.

        Order of evaluation:
        1. Enforcing DENY policies (immediate deny if matched)
        2. Enforcing ALLOW policies (immediate allow if matched)
        3. Regular policies by priority
        4. Default effect if no policy matched
        """
        # 1. Check enforcing policies first
        for policy in self._index.get_enforcing():
            if not policy.covers_resource(resource_type, resource_name):
                continue
            if not policy.covers_action(action):
                continue

            response = policy.is_allowed(
                ctx, env,
                resource_type=resource_type,
                resource_name=resource_name,
                action=action
            )

            if response.effect == PolicyEffect.DENY and policy.effect == PolicyEffect.DENY:
                # Enforcing DENY matched
                return EvaluationResult(
                    allowed=False,
                    effect=PolicyEffect.DENY,
                    matched_policy=policy.name,
                    reason=response.response
                )
            elif response.effect == PolicyEffect.ALLOW and policy.effect == PolicyEffect.ALLOW:
                # Enforcing ALLOW matched
                return EvaluationResult(
                    allowed=True,
                    effect=PolicyEffect.ALLOW,
                    matched_policy=policy.name,
                    reason=response.response
                )

        # 2. Evaluate regular policies for this resource type
        allow_matched = None
        deny_matched = None

        for policy in self._index.get_for_resource_type(resource_type):
            if policy.enforcing:
                continue  # Already evaluated
            if not policy.covers_resource(resource_type, resource_name):
                continue
            if not policy.covers_action(action):
                continue

            response = policy.is_allowed(
                ctx, env,
                resource_type=resource_type,
                resource_name=resource_name,
                action=action
            )

            # Track matches
            if response.effect == PolicyEffect.ALLOW and policy.effect == PolicyEffect.ALLOW:
                if allow_matched is None or policy.priority > allow_matched[1]:
                    allow_matched = (policy, policy.priority, response)
            elif response.effect == PolicyEffect.DENY and policy.effect == PolicyEffect.DENY:
                if deny_matched is None or policy.priority > deny_matched[1]:
                    deny_matched = (policy, policy.priority, response)

        # 3. Determine final result
        # DENY takes precedence at equal priority
        if deny_matched and allow_matched:
            if deny_matched[1] >= allow_matched[1]:
                policy, _, response = deny_matched
                return EvaluationResult(
                    allowed=False,
                    effect=PolicyEffect.DENY,
                    matched_policy=policy.name,
                    reason=response.response
                )

        if allow_matched:
            policy, _, response = allow_matched
            return EvaluationResult(
                allowed=True,
                effect=PolicyEffect.ALLOW,
                matched_policy=policy.name,
                reason=response.response
            )

        if deny_matched:
            policy, _, response = deny_matched
            return EvaluationResult(
                allowed=False,
                effect=PolicyEffect.DENY,
                matched_policy=policy.name,
                reason=response.response
            )

        # 4. Default effect (no policy matched)
        return EvaluationResult(
            allowed=(self._default_effect == PolicyEffect.ALLOW),
            effect=self._default_effect,
            matched_policy=None,
            reason=f"No matching policy, default: {self._default_effect.name}"
        )

    def filter_resources(
        self,
        ctx: EvalContext,
        resource_type: ResourceType,
        resource_names: List[str],
        action: str,
        env: Environment = None
    ) -> FilteredResources:
        """
        Filter a list of resources by user permissions.

        Efficient batch evaluation for filtering tools, KBs, etc.

        Args:
            ctx: Evaluation context
            resource_type: Type of all resources
            resource_names: List of resource names to filter
            action: Action being attempted
            env: Optional environment

        Returns:
            FilteredResources with allowed/denied lists
        """
        result = FilteredResources()
        policies_used = set()

        for name in resource_names:
            eval_result = self.check_access(ctx, resource_type, name, action, env)
            if eval_result.allowed:
                result.allowed.append(name)
            else:
                result.denied.append(name)
            if eval_result.matched_policy:
                policies_used.add(eval_result.matched_policy)

        result.policies_applied = list(policies_used)
        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get evaluation statistics."""
        return {
            **self._stats,
            'cache_size': len(self._cache),
            'policy_count': len(self._index.all()),
            'cache_hit_rate': (
                self._stats['cache_hits'] / max(1, self._stats['cache_hits'] + self._stats['cache_misses'])
            )
        }
