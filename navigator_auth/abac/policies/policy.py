from typing import Union
from .abstract import ActionKey, PolicyEffect, PolicyResponse, AbstractPolicy
from ..context import EvalContext
from .environment import Environment


class Policy(AbstractPolicy):
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
            if groups_condition is True:
                ## conditions in groups are over in context:
                context_condition = True
            elif self.context_attrs:
                for a in self.context_attrs:
                    att = self.context[a]
                    ### check Context Object itself:
                    try:
                        if att == getattr(ctx, a, None):
                            context_condition = True
                    except TypeError:
                        pass

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
        # print('EVALUATION > ')
        # print(groups_condition, environment_condition, context_condition, subject_condition)
        if (groups_condition and environment_condition
            and context_condition and subject_condition):
            return PolicyResponse(
                effect=self.effect,
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
            action: Union[str, ActionKey],
            resource: list[dict] = None,
            **kwargs
    ) -> PolicyResponse:
        """
        Determines if the requested action(s) is/are allowed by the policy.

        :param ctx: The evaluation context, containing user, userinfo, and session.
        :param env: The environment information, such as the current time and date.
        :param action: The requested action(s) to check against the policy's actions.
                       Can be a single action string or a list of action strings.
        :return: A PolicyResponse indicating if the action(s) is/are allowed or denied.
        """
        # Evaluate the policy with the given context and environment
        policy_response = self.evaluate(ctx, env)

        # Convert action to a list if it's a single string
        if isinstance(action, str):
            action = ActionKey(action)

        # Check if the policy's actions cover the requested actions
        _allowed = False
        for act in self.actions:
            if act == action:
                _allowed = True
                break
        if _allowed:
            # Actions are covered by policy, return a PolicyResponse with the same
            # effect as policy_response
            return PolicyResponse(
                effect=policy_response.effect,
                response=f"Access {policy_response.effect} by Policy {self.name}",
                actions=action,
                rule=self.name
            )
        # Actions are not covered by policy, return a PolicyResponse with effect DENY
        return PolicyResponse(
            effect=PolicyEffect.DENY,
            response=f"Action Denied by Policy {self.name}",
            rule=self.name
        )
