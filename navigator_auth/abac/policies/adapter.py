import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Union, Any, Set
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.abstract import PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType, SubjectSpec

@dataclass
class AdapterResult:
    policy: Optional[ResourcePolicy] = None
    warnings: List[str] = field(default_factory=list)
    additional_policies: List[ResourcePolicy] = field(default_factory=list)
    skipped: bool = False
    reason: str = ""

class PolicyAdapter:
    """Converts classic policy dicts to ResourcePolicy at load time."""

    # HTTP method -> action mapping
    METHOD_ACTION_MAP = {
        "GET": "uri:read",
        "HEAD": "uri:read",
        "POST": "uri:write",
        "PUT": "uri:write",
        "PATCH": "uri:write",
        "DELETE": "uri:delete",
    }

    # Regex metacharacters for detection
    RE_METAS = r'[\^\$\(\)\+\{\}\[\]\|\?\\]'

    @staticmethod
    def _convert_urn(urn_str: str) -> Tuple[str, bool]:
        """Convert URN to type:pattern format. Returns (converted, is_negated)."""
        negated = urn_str.startswith("!")
        if negated:
            urn_str = urn_str[1:]

        if urn_str.startswith("urn:uri:"):
            # urn:uri:/api/v1/... -> uri:/api/v1/...
            return f"uri:{urn_str[8:]}", negated
        elif urn_str.startswith("urn:"):
            # urn:namespace:type::parts -> type:parts
            parts = urn_str[4:].split("::", 1)
            prefix_parts = parts[0].split(":")
            # Last part of prefix is the type
            rtype = prefix_parts[-1]
            rname = parts[1] if len(parts) > 1 else "*"
            return f"{rtype}:{rname}", negated
        elif ":" in urn_str:
            # Already in type:pattern format
            return urn_str, negated
        else:
            # Bare resource name -> uri: type
            return f"uri:{urn_str}", negated

    @staticmethod
    def _validate_resource(resource: str) -> Optional[str]:
        """Validate resource pattern. Returns warning if invalid."""
        try:
            type_str, pattern = resource.split(':', 1)
            # If it's a regex (detected by metacharacters), try to compile it
            if re.search(PolicyAdapter.RE_METAS, pattern):
                try:
                    re.compile(pattern)
                except re.error as e:
                    return f"Invalid regex pattern '{pattern}': {e}"
            return None
        except ValueError:
            return f"Invalid resource format (missing colon): {resource}"

    @staticmethod
    def adapt(policy_dict: dict) -> AdapterResult:
        """Convert a single policy dict to ResourcePolicy."""
        try:
            policy_type = policy_dict.get("policy_type", "policy")
            if policy_type == "resource":
                return PolicyAdapter._adapt_resource(policy_dict)
            elif policy_type == "file":
                return PolicyAdapter._adapt_file(policy_dict)
            elif policy_type == "object":
                return PolicyAdapter._adapt_object(policy_dict)
            else:
                return PolicyAdapter._adapt_classic(policy_dict)
        except Exception as e:
            return AdapterResult(skipped=True, reason=f"Unexpected error during adaptation: {e}")

    @staticmethod
    def _adapt_resource(policy_dict: dict) -> AdapterResult:
        """Pass-through for already correct ResourcePolicy format."""
        # Ensure effect is enum
        effect = policy_dict.get('effect', PolicyEffect.ALLOW)
        if isinstance(effect, str):
            effect = PolicyEffect.ALLOW if effect.upper() == 'ALLOW' else PolicyEffect.DENY

        try:
            # Re-initialize to ensure it's a valid ResourcePolicy
            p = ResourcePolicy(
                name=policy_dict['name'],
                effect=effect,
                description=policy_dict.get('description'),
                resources=policy_dict.get('resources'),
                actions=policy_dict.get('actions'),
                subjects=policy_dict.get('subjects'),
                conditions=policy_dict.get('conditions'),
                environment=policy_dict.get('environment'),
                priority=policy_dict.get('priority', 0),
                enforcing=policy_dict.get('enforcing', False)
            )
            return AdapterResult(policy=p)
        except Exception as e:
            return AdapterResult(skipped=True, reason=f"Error parsing resource policy: {e}")

    @staticmethod
    def _adapt_classic(policy_dict: dict) -> AdapterResult:
        """Convert classic Policy dict."""
        warnings = []
        name = policy_dict.get('name', 'unnamed')

        # 1. Effect
        effect_str = str(policy_dict.get('effect', 'ALLOW')).upper()
        effect = PolicyEffect.ALLOW if effect_str == 'ALLOW' else PolicyEffect.DENY

        # 2. Resources & Negated
        raw_resources = policy_dict.get('resource') or policy_dict.get('resources') or []
        if isinstance(raw_resources, str):
            raw_resources = [raw_resources]

        final_resources = []
        negated_resources = []
        for r in raw_resources:
            conv, is_negated = PolicyAdapter._convert_urn(r)
            warning = PolicyAdapter._validate_resource(conv)
            if warning:
                warnings.append(warning)
                continue # Skip invalid patterns

            if is_negated:
                negated_resources.append(conv)
            else:
                final_resources.append(conv)

        # 3. Actions
        raw_actions = policy_dict.get('actions') or []
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]
        final_actions = []
        for a in raw_actions:
            if ':' in a:
                final_actions.append(a)
            else:
                # Map method to uri: action if possible
                mapped = PolicyAdapter.METHOD_ACTION_MAP.get(a.upper())
                if mapped:
                    final_actions.append(mapped)
                else:
                    final_actions.append(f"uri:{a.lower()}")

        # 4. Subjects
        subjects_data = {
            'groups': set(policy_dict.get('groups') or []),
            'users': set(policy_dict.get('subject') or [])
        }
        subjects = SubjectSpec.from_dict(subjects_data)

        # 5. Conditions (context attributes)
        conditions = {}
        python_conditions = {}
        raw_context = policy_dict.get('context') or {}
        for k, v in raw_context.items():
            # For now, we only support direct matches that can be evaluated in Rust
            # More complex session/user attribute access will need Python post-filter (TBD)
            python_conditions[k] = v

        # 6. Create Policy
        try:
            p = ResourcePolicy(
                name=name,
                effect=effect,
                description=policy_dict.get('description'),
                resources=final_resources,
                actions=final_actions,
                subjects=subjects,
                conditions=conditions,
                environment=policy_dict.get('environment'),
                priority=policy_dict.get('priority', 0),
                enforcing=policy_dict.get('enforcing', False)
            )
            # Attach python conditions for later use
            if python_conditions:
                p.python_conditions = python_conditions

            # 7. Handle Negated Resources (create separate DENY policies)
            if negated_resources:
                deny_policy = ResourcePolicy(
                    name=f"{name}_negated",
                    effect=PolicyEffect.DENY,
                    description=f"Deny policy for negated resources of {name}",
                    resources=negated_resources,
                    actions=final_actions,
                    subjects=subjects,
                    conditions=conditions,
                    environment=policy_dict.get('environment'),
                    priority=policy_dict.get('priority', 0) + 1, # Higher priority
                    enforcing=True # Enforce the deny
                )
                return AdapterResult(policy=p, warnings=warnings, additional_policies=[deny_policy])

            return AdapterResult(policy=p, warnings=warnings)
        except Exception as e:
            return AdapterResult(skipped=True, reason=f"Error creating ResourcePolicy: {e}", warnings=warnings)

    @staticmethod
    def _adapt_file(policy_dict: dict) -> AdapterResult:
        """Convert FilePolicy dict."""
        # FilePolicy already handles resources correctly in _adapt_classic
        # but we might want to ensure they are interpreted as uri:
        return PolicyAdapter._adapt_classic(policy_dict)

    @staticmethod
    def _adapt_object(policy_dict: dict) -> AdapterResult:
        """Convert ObjectPolicy dict."""
        policy_dict = policy_dict.copy()
        obj_type = policy_dict.get('type', 'object')
        objects = policy_dict.get('objects') or []
        if isinstance(objects, str):
            objects = [objects]

        # Convert objects to type:pattern
        new_resources = []
        for obj in objects:
            if ':' not in obj and not obj.startswith('urn:'):
                new_resources.append(f"{obj_type}:{obj}")
            else:
                new_resources.append(obj)
        policy_dict['resources'] = new_resources
        return PolicyAdapter._adapt_classic(policy_dict)

    @staticmethod
    def adapt_batch(policy_dicts: List[dict]) -> Tuple[List[ResourcePolicy], List[str]]:
        """Convert a batch of policy dicts."""
        all_policies = []
        all_warnings = []
        for d in policy_dicts:
            result = PolicyAdapter.adapt(d)
            if result.skipped:
                all_warnings.append(f"Skipped policy '{d.get('name')}': {result.reason}")
                continue

            if result.policy:
                all_policies.append(result.policy)
            if result.additional_policies:
                all_policies.extend(result.additional_policies)

            for w in result.warnings:
                all_warnings.append(f"Policy '{d.get('name')}': {w}")

        return all_policies, all_warnings
