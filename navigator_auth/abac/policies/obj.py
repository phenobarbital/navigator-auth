from typing import Union
from .abstract import PolicyEffect, PolicyResponse, AbstractPolicy
from ..context import EvalContext
from .environment import Environment


class ObjectPolicy(AbstractPolicy):
    """ObjectPolicy.

    Generic Policy Applied to Objects (resource systems).
    """
    def _fits_policy(self, ctx: EvalContext) -> bool:
        """Internal Method for checking if Policy fits the Context."""
        fit_result = False
        for resource in self.resources:
            objects = getattr(ctx, 'objects', [])
            for f in objects:
                object_type = getattr(ctx, 'objectype', None)
                if object_type and object_type != resource.resource_type:
                    # are not matching, return
                    break
                if resource.match(f'{f!s}') is not None:
                    fit_result = True
                    # if only one file is covered by this policy, exits
                    break
        return fit_result

    def evaluate(self, ctx: EvalContext, environ: Environment) -> bool:
        """
        Evaluates the policy against the provided context and environment.

        :param ctx: The evaluation context, containing user, userinfo, and session
           information.
        :param environ: The environment information, such as the current time and date.
        :return: A PolicyResponse instance, indicating whether access is allowed or
           denied.
        """
        # Check if the user belongs to any of the allowed groups
        groups_condition = False
        if self.groups:
            try:
                if bool(not set(ctx.userinfo["groups"]).isdisjoint(self.groups)):
                    # User is in at least one allowed group
                    groups_condition = True
            except (KeyError, TypeError, ValueError):
                pass
        else:
            # No groups specified in the policy, so this condition is true by default
            groups_condition = True

        # Check if the user is listed in the allowed subjects
        subject_condition = False
        if self.subject:
            if ctx.userinfo['username'] in self.subject:
                subject_condition = True
        else:
            # No subjects specified in the policy, so this condition is true by default
            subject_condition = True

        # Check if the current environment matches the policy's environment requirements
        environment_condition = False
        if self.environment:
            if self.evaluate_environment(environ):
                environment_condition = True
        else:
            # No environment requirements in the policy, so this condition is true.
            environment_condition = True

        # Check if the other contexts match the policy's attribute requirements
        context_condition = False
        if self.context:
            if self.context_attrs:
                for a in self.context_attrs:
                    att = self.context[a]
                    # Check user object attributes
                    try:
                        if att == getattr(ctx.user, a, None):
                            context_condition = True
                    except TypeError:
                        pass

                    # Check userinfo attributes
                    val = getattr(ctx.userinfo, a, ctx.userinfo.get(a, None))
                    if att == val:
                        context_condition = True

                    # Check session attributes
                    try:
                        val = getattr(ctx.session, a, None)
                        if isinstance(att, list):
                            if val in att:
                                context_condition = True
                        else:
                            if att == val:
                                context_condition = True
                    except (KeyError, TypeError):
                        pass
        else:
            # No context requirements in the policy, so this condition true by default
            context_condition = True

        # If all conditions are true, set is_allowed to True
        if (groups_condition and environment_condition
            and context_condition and subject_condition):
            return PolicyResponse(
                effect=PolicyEffect.ALLOW,
                response=f"Access {self.effect} by {self.name}",
                rule=self.name
            )
        # Default return: access denied
        return PolicyResponse(
            effect=PolicyEffect.DENY,
            response=f"Unauthorized by Policy {self.name}",
            rule=self.name
        )

    def is_allowed(
            self,
            ctx: EvalContext,
            env: Environment,
            actions: Union[str, list[str]],
            resource: list[dict],
            **kwargs
    ) -> PolicyResponse:
        """
        Determines if requested action is allowed by FilePolicy for the given resource.

        :param ctx: The evaluation context, containing user, userinfo, and session.
        :param env: The environment information, such as the current time and date.
        :param action: The requested action(s) to check against the policy's actions.
                       Can be a single action string or a list of action strings.
        :param resource: The requested resource to check against the policy's resources.
        :return: A PolicyResponse indicating if the action(s) is/are allowed or denied.
        """
        # First, check if the policy applies to the user using the evaluate method
                # Evaluate the policy with the given context and environment
        response = self.evaluate(ctx, env)

        # Convert action to a list if it's a single string
        if isinstance(actions, str):
            actions = [actions]

        # Check if the policy's actions cover the requested actions
        if self.actions and not set(actions).isdisjoint(self.actions):
            # Actions are covered by policy
            # Check if the requested directory matches any of the policy's resources
            for obj in ctx.objects:
                # Check for positive matches
                positive_match = any(
                    res.match(f"{obj!s}") for res in self.resources
                    if not res.is_negative()
                )

                # Check for negative matches
                negative_match = any(
                    res.match(f"{obj!s}") for res in self.resources if res.is_negative()
                )
                if positive_match and not negative_match:
                    # Requested directory is covered by policy
                    # # Check if the user belongs to a group that has permission
                    # if self.groups:
                    #     user_groups = ctx.userinfo.get('groups', [])
                    #     if set(user_groups).intersection(self.groups):
                    #         # User belongs to a group with permission, return a
                    # PolicyResponse with the same effect as policy_response
                    return PolicyResponse(
                        effect=response.effect,
                        response=f"{response.effect} by FilePolicy {self.name}",
                        actions=actions,
                        rule=self.name
                    )

        # Actions are not covered by policy, return a PolicyResponse with effect DENY
        return PolicyResponse(
            effect=PolicyEffect.DENY,
            response=f"Action Denied by Policy {self.name}",
            rule=self.name
        )

    def _filter(
            self,
            objects: Union[str, list[str]],
            _type: str,
            ctx: EvalContext,
            env: Environment
    ) -> PolicyResponse:
        """
        Evaluates the policy against the provided context and environment.

        :param objects: list of objects to be evaluated against Policy.
        :param _type: kind of object to be evaluated (file, dir, etc)
        :param ctx: The evaluation context, containing user, userinfo, and session
           information.
        :param env: The environment information, such as the current time and date.
        :return: A PolicyResponse instance, indicating whether access is allowed or
           denied.
        """
        # First, check if the policy applies to the user using the evaluate method
        policy_response = self.evaluate(ctx, env)
        allowed_objects = []
        if policy_response.effect == PolicyEffect.DENY:
            # Remove objects covered by police:
            for f in objects:
                if any(
                    res.match(f) for res in self.resources if res.resource_type == _type
                ):
                    if self.effect == PolicyEffect.ALLOW:
                        continue
                allowed_objects.append(f)
        else:
            # If the policy applies, filter the list based on the policy's context
            # allowed_files = files
            for f in objects:
                if any(
                    res.match(f) for res in self.resources if res.resource_type == _type
                ):
                    if self.effect == PolicyEffect.DENY:
                        ## remove the file(s) from list:
                        continue
                allowed_objects.append(f)
        return PolicyResponse(
            effect=self.effect,
            response=allowed_objects,
            rule=self.name
        )
