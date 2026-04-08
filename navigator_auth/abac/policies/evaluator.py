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
import json
import yaml
import logging
try:
    from navigator_auth.rs_pep import evaluate_single, filter_resources_batch
    _RS_PEP_AVAILABLE = True
except ImportError:
    evaluate_single = None
    filter_resources_batch = None
    _RS_PEP_AVAILABLE = False

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
        """Add policy to index (call finalize() after batch loading)."""
        self._by_name[policy.name] = policy
        self._all_policies.append(policy)

        # Index by resource type
        for resource_type in policy._patterns_by_type.keys():
            self._by_type[resource_type].append(policy)

        # Track enforcing policies
        if policy.enforcing:
            self._enforcing.append(policy)

    def finalize(self) -> None:
        """Sort all policy lists by priority (call once after all adds)."""
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
                logger.debug("Loaded policy: %s", policy.name)

            except Exception as e:
                logger.error("Failed to load policy %s: %s", policy_data.get('name', 'unknown'), e)
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
        if not _RS_PEP_AVAILABLE:
            raise RuntimeError(
                "The 'rs_pep' Rust extension is required but not installed. "
                "Install it with: maturin develop --release (from the rs_pep directory)"
            )
        self._index = PolicyIndex()
        self._default_effect = default_effect
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, Tuple[EvaluationResult, float]] = {}
        self._policies_json: str = "[]"
        self._stats = {
            'evaluations': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

    def load_policies(self, policies: List[ResourcePolicy]) -> None:
        """Load policies into evaluator."""
        for policy in policies:
            self._index.add(policy)
        self._index.finalize()
        self._rebuild_json_cache()
        logger.info("Loaded %d policies", len(policies))

    def _rebuild_json_cache(self) -> None:
        """Serialize all policies to JSON for Rust engine."""
        self._policies_json = self._serialize_policies_from_index(self._index)

    def _serialize_policies_from_index(self, index: PolicyIndex) -> str:
        """Serialize all policies in an index to JSON for Rust engine."""
        policies_data = []
        for policy in index.all():
            policies_data.append({
                "name": policy.name,
                "effect": "allow" if policy.effect == PolicyEffect.ALLOW else "deny",
                "resources": [f"{p.resource_type.value if hasattr(p.resource_type, 'value') else p.resource_type}:{p.pattern}"
                              for p in policy._resource_patterns],
                "actions": list(policy._actions),
                "subjects": {
                    "groups": list(policy._subjects.groups),
                    "users": list(policy._subjects.users),
                    "roles": list(policy._subjects.roles),
                    "exclude_groups": list(policy._subjects.exclude_groups),
                    "exclude_users": list(policy._subjects.exclude_users),
                },
                "conditions": {
                    "environment": policy._env_conditions,
                    "is_manager": bool(policy.conditions.get("is_manager", False) or policy._env_conditions.get("is_manager", False))
                },
                "priority": policy.priority,
                "enforcing": policy.enforcing,
            })
        return json.dumps(policies_data)

    def swap_index(self, new_index: PolicyIndex, new_json: str = None) -> None:
        """Atomically swap policy index and clear cache.

        Args:
            new_index: The new PolicyIndex to replace the current one.
            new_json: Pre-serialized JSON for Rust engine.
                If None, serialization is done automatically.
        """
        if new_json is None:
            new_json = self._serialize_policies_from_index(new_index)
        self._index = new_index
        self._policies_json = new_json
        self._cache.clear()
        self._stats['cache_hits'] = 0
        self._stats['cache_misses'] = 0
        logger.info("Policy index swapped successfully (%d policies)", len(new_index.all()))

    def _build_user_context(self, ctx: EvalContext) -> dict:
        username = "anonymous"
        if ctx.userinfo:
            username = ctx.userinfo.get("username", ctx.userinfo.get("user_id", "anonymous"))
        elif ctx.user and hasattr(ctx.user, 'username'):
            username = ctx.user.username

        return {
            "username": username,
            "groups": list(ctx.userinfo.get("groups", [])) if ctx.userinfo else [],
            "roles": list(ctx.userinfo.get("roles", [])) if ctx.userinfo else [],
        }

    def _build_env_dict(self, env: Environment) -> dict:
        return {
            "hour": env.hour,
            "dow": env.dow,
            "is_business_hours": env.is_business_hours,
            "is_weekend": env.is_weekend,
            "day_segment": env.day_segment.value if hasattr(env.day_segment, 'value') else str(env.day_segment),
        }

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
        action: str,
        env_dict: dict = None
    ) -> str:
        """Generate cache key for evaluation."""
        groups_str = ','.join(sorted(user_groups))
        rtype_val = resource_type.value if hasattr(resource_type, 'value') else resource_type
        env_str = json.dumps(env_dict, sort_keys=True) if env_dict else ""
        key_data = f"{user_id}|{groups_str}|{rtype_val}|{resource_name}|{action}|{env_str}"
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
        """Invalidate cache entries, optionally for specific user.

        Note: user-specific invalidation rebuilds the cache key for each
        entry to check the user_id component, since keys are MD5 hashes.
        For full invalidation, simply clears the entire cache.
        """
        if user_id:
            # Cache keys are MD5 hashes, so we cannot filter by prefix.
            # For user-specific invalidation, clear the entire cache to be safe.
            # A more efficient approach would require a secondary index.
            self._cache.clear()
            logger.debug("Cache cleared for user %s (full invalidation)", user_id)
        else:
            self._cache.clear()

    def check_access(
        self,
        ctx: EvalContext,
        resource_type: ResourceType,
        resource_name: str,
        action: str,
        env: Environment = None,
        owner_reports_to: str = None
    ) -> EvaluationResult:
        """
        Check if access is allowed for the given resource and action.

        This is the main entry point for permission checks.
        """
        start_time = time.perf_counter()
        self._stats['evaluations'] += 1

        # Create environment if not provided
        if env is None:
            env = Environment()
        env_dict = self._build_env_dict(env)

        # Get user info for cache key
        try:
            user_id = ctx.userinfo.get('username', ctx.userinfo.get('user_id', 'anonymous')) if ctx.userinfo else 'anonymous'
            user_groups = set(ctx.userinfo.get('groups', [])) if ctx.userinfo else set()
        except (AttributeError, TypeError):
            user_id = 'anonymous'
            user_groups = set()

        # Check cache (Hierarchy checks are NOT cached easily if owner_reports_to varies)
        cache_key = None
        if not owner_reports_to:
            cache_key = self._make_cache_key(user_id, user_groups, resource_type, resource_name, action, env_dict=env_dict)
            cached_result = self._check_cache(cache_key)
            if cached_result:
                return cached_result

        # Build context for Rust
        user_ctx = self._build_user_context(ctx)
        user_ctx["action"] = action

        # Evaluate via Rust engine (mandatory — no Python fallback per spec)
        try:
            result_dict = evaluate_single(
                self._policies_json,
                f"{resource_type.value if hasattr(resource_type, 'value') else resource_type}:{resource_name}",
                action,
                user_ctx,
                env_dict,
                owner_reports_to=owner_reports_to
            )

            result = EvaluationResult(
                allowed=result_dict["allowed"],
                effect=PolicyEffect.ALLOW if result_dict["allowed"] else PolicyEffect.DENY,
                matched_policy=result_dict.get("matched_policy"),
                reason=result_dict.get("reason", ""),
            )
        except Exception as e:
            # Fail closed: deny access on Rust engine errors (no silent fallback)
            logger.error(
                "Rust evaluation failed for resource %s:%s — denying access: %s",
                resource_type, resource_name, e
            )
            result = EvaluationResult(
                allowed=False,
                effect=PolicyEffect.DENY,
                matched_policy=None,
                reason=f"Evaluation engine error: {e}",
            )

        # Record timing
        result.evaluation_time_ms = (time.perf_counter() - start_time) * 1000

        # Cache result if it's a standard check
        if cache_key:
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

        Efficient batch evaluation via Rust.
        """
        if env is None:
            env = Environment()

        # Build context for Rust
        user_ctx = self._build_user_context(ctx)
        user_ctx["action"] = action
        env_dict = self._build_env_dict(env)

        # Format resources for Rust: "type:name"
        rtype_prefix = f"{resource_type.value if hasattr(resource_type, 'value') else resource_type}:"
        rust_resources = [f"{rtype_prefix}{name}" for name in resource_names]

        try:
            res_dict = filter_resources_batch(
                self._policies_json,
                rust_resources,
                user_ctx,
                env_dict
            )

            # Strip type prefix from results
            prefix_len = len(rtype_prefix)
            allowed = [r[prefix_len:] for r in res_dict.get('allowed', [])]
            denied = [r[prefix_len:] for r in res_dict.get('denied', [])]

            return FilteredResources(
                allowed=allowed,
                denied=denied
            )
        except Exception as e:
            # Fail closed: deny all resources on Rust engine errors
            logger.error(
                "Rust batch filter failed — denying all resources: %s", e
            )
            return FilteredResources(
                allowed=[],
                denied=list(resource_names)
            )

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
