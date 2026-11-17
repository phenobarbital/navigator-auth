from typing import List, Optional, Union, Dict, Set, Tuple
from navigator_auth.abac.policies.abstract import AbstractPolicy, PolicyEffect, PolicyResponse
from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.policies.resources import ResourcePattern, ResourceType, SubjectSpec

class ResourcePolicy(AbstractPolicy):
    """
    PBAC Policy Based Access Control for Resources.

    Extends AbstractPolicy with:
    - Efficient pattern matching for tools/KBs/vectors or other resources
    - Subject specifications with allow/deny lists
    - Resource-type-specific conditions

    Example:
        policy = ResourcePolicy(
            name="engineering_jira",
            effect=PolicyEffect.ALLOW,
            resources=["tool:jira_*", "tool:github_*"],
            actions=["tool:execute", "tool:list"],
            subjects={"groups": ["engineering"]},
            priority=10
        )
    """

    def __init__(
        self,
        name: str,
        effect: PolicyEffect = PolicyEffect.ALLOW,
        description: str = None,
        resources: List[str] = None,
        actions: List[str] = None,
        subjects: Union[dict, SubjectSpec] = None,
        conditions: dict = None,
        environment: dict = None,
        priority: int = 0,
        enforcing: bool = False,
        org_id: int = 1,
        client_id: int = 1,
        **kwargs
    ):
        # Tenant scope — 1 is the global/inheritable sentinel
        self.org_id = org_id
        self.client_id = client_id

        # Parse resources into ResourcePattern objects
        self._resource_patterns: List[ResourcePattern] = []
        if resources:
            self._resource_patterns = [
                ResourcePattern.from_string(r) for r in resources
            ]

        # Index patterns by type for O(1) lookup
        self._patterns_by_type: Dict[ResourceType, List[ResourcePattern]] = {}
        for pattern in self._resource_patterns:
            if pattern.resource_type not in self._patterns_by_type:
                self._patterns_by_type[pattern.resource_type] = []
            self._patterns_by_type[pattern.resource_type].append(pattern)

        # Parse subjects
        if isinstance(subjects, dict):
            self._subjects = SubjectSpec.from_dict(subjects)
        elif isinstance(subjects, SubjectSpec):
            self._subjects = subjects
        else:
            self._subjects = SubjectSpec()

        # Parse actions
        self._actions: Set[str] = set(actions) if actions else set()

        # Environment conditions (optional)
        self._env_conditions = environment or {}

        # Call parent constructor
        super().__init__(
            name=name,
            description=description,
            effect=effect,
            conditions=conditions or {},
            priority=priority,
            enforcing=enforcing,
            **kwargs
        )

    def covers_resource(self, resource_type: ResourceType, resource_name: str) -> bool:
        """
        Check if this policy covers the given resource.

        O(n) where n = number of patterns for this resource type (usually small).
        """
        # Handle string resource types
        if isinstance(resource_type, str):
            try:
                resource_type = ResourceType(resource_type)
            except ValueError:
                # Custom resource type support
                pass

        patterns = self._patterns_by_type.get(resource_type, [])
        return any(p.matches(resource_name) for p in patterns)

    def covers_action(self, action: str) -> bool:
        """Check if this policy covers the given action."""
        if not self._actions:
            return True  # No action restriction
        return action in self._actions

    def matches_subject(self, ctx: EvalContext) -> bool:
        """Check if the context's user matches the policy subjects."""
        try:
            username = ctx.userinfo.get('username', '')
            user_groups = set(ctx.userinfo.get('groups', []))
            user_roles = set(ctx.userinfo.get('roles', []))
            return self._subjects.matches_user(username, user_groups, user_roles)
        except (KeyError, TypeError, AttributeError):
            return False

    def evaluate_conditions(self, ctx: EvalContext, environ: Environment) -> bool:
        """Evaluate additional conditions."""
        # Environment conditions (time-based, etc.)
        if self._env_conditions:
            for key, allowed_values in self._env_conditions.items():
                current_value = getattr(environ, key, None)
                if current_value is None:
                    continue
                if isinstance(allowed_values, list):
                    if current_value not in allowed_values:
                        return False
                elif isinstance(allowed_values, dict):
                    # Range check: {"min": 8, "max": 18}
                    if 'min' in allowed_values and current_value < allowed_values['min']:
                        return False
                    if 'max' in allowed_values and current_value > allowed_values['max']:
                        return False
                else:
                    if current_value != allowed_values:
                        return False

        # Custom conditions from self.conditions
        for key, expected in self.conditions.items():
            actual = getattr(ctx, key, None)
            if actual is None:
                continue
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        return True

    def _out_of_scope(
        self,
        resource_type: ResourceType = None,
        resource_name: str = None,
        action: str = None,
    ) -> Optional[PolicyResponse]:
        """Return the DENY for a resource or action this policy does not cover.

        Args:
            resource_type: Type of the resource, checked with ``resource_name``.
            resource_name: Name of the resource.
            action: Action being requested.

        Returns:
            The "not covered" response, or ``None`` when both are covered.
        """
        if resource_type and resource_name and not self.covers_resource(resource_type, resource_name):
            return PolicyResponse(
                effect=PolicyEffect.DENY,
                response=f"Resource not covered by {self.name}",
                rule=self.name,
                actions=[]
            )
        if action and not self.covers_action(action):
            return PolicyResponse(
                effect=PolicyEffect.DENY,
                response=f"Action not covered by {self.name}",
                rule=self.name,
                actions=[]
            )
        return None

    def _match(self, ctx: EvalContext, environ: Environment) -> Tuple[bool, PolicyResponse]:
        """Check subject and conditions.

        Returns:
            ``(applies, response)``; ``response`` carries ``self.effect`` when
            ``applies`` is True, a "not matched" DENY otherwise.
        """
        # Check subject
        if not self.matches_subject(ctx):
            return False, PolicyResponse(
                effect=PolicyEffect.DENY,
                response=f"Subject not matched by {self.name}",
                rule=self.name,
                actions=list(self._actions)
            )

        # Check conditions
        if not self.evaluate_conditions(ctx, environ):
            return False, PolicyResponse(
                effect=PolicyEffect.DENY,
                response=f"Conditions not met for {self.name}",
                rule=self.name,
                actions=list(self._actions)
            )

        # All checks passed
        return True, PolicyResponse(
            effect=self.effect,
            response=f"Access {self.effect.name} by {self.name}",
            rule=self.name,
            actions=list(self._actions)
        )

    def decide(
        self,
        ctx: EvalContext,
        env: Environment,
        resource_type: ResourceType = None,
        resource_name: str = None,
        action: str = None,
    ) -> Tuple[bool, PolicyResponse]:
        """Evaluate the policy once and tell whether it applied.

        Same checks as :meth:`is_allowed`. A policy that does not apply answers
        DENY, the effect a DENY policy answers when it applies; the flag tells
        the two apart. A subclass that overrides :meth:`evaluate` or
        :meth:`is_allowed` is not reflected here.

        Args:
            ctx: Evaluation context with user info.
            env: Environment (time, etc.).
            resource_type: Type of the resource, checked with ``resource_name``.
            resource_name: Name of the resource.
            action: Action being requested.

        Returns:
            ``(applies, response)``: ``applies`` is True when resource, action,
            subject and conditions all match, and ``response`` then carries
            ``self.effect``; otherwise it is a "not covered / not matched" DENY.
        """
        refused = self._out_of_scope(resource_type, resource_name, action)
        if refused is not None:
            return False, refused
        return self._match(ctx, env)

    def evaluate(self, ctx: EvalContext, environ: Environment) -> PolicyResponse:
        """
        Evaluate policy against context and environment.

        Returns PolicyResponse with effect if all conditions match.
        """
        return self._match(ctx, environ)[1]

    def applies_to(
        self,
        ctx: EvalContext,
        env: Environment,
        resource_type: ResourceType = None,
        resource_name: str = None,
        action: str = None,
    ) -> bool:
        """Tell whether this policy decides the request with its own effect.

        Args:
            ctx: Evaluation context with user info.
            env: Environment (time, etc.).
            resource_type: Type of the resource, checked with ``resource_name``.
            resource_name: Name of the resource.
            action: Action being requested.

        Returns:
            True when resource, action, subject and conditions all match.
        """
        return self.decide(ctx, env, resource_type, resource_name, action)[0]

    def is_allowed(
        self,
        ctx: EvalContext,
        env: Environment,
        resource_type: ResourceType = None,
        resource_name: str = None,
        action: str = None,
        **kwargs
    ) -> PolicyResponse:
        """
        Check if access is allowed for specific resource and action.

        Args:
            ctx: Evaluation context with user info
            env: Environment (time, etc.)
            resource_type: Type of resource (TOOL, KB, VECTOR, AGENT)
            resource_name: Name of the specific resource
            action: Action being requested

        Returns:
            PolicyResponse with effect and details
        """
        refused = self._out_of_scope(resource_type, resource_name, action)
        if refused is not None:
            return refused
        # Evaluate full policy (a subclass may override evaluate)
        return self.evaluate(ctx, env)
