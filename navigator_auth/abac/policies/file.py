from typing import Union
from .abstract import PolicyEffect, PolicyResponse
from ..context import EvalContext
from .environment import Environment
from .obj import ObjectPolicy


class FilePolicy(ObjectPolicy):
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
        if isinstance(action, str):
            action = ActionKey(action)

        # Check if the policy's actions cover the requested actions
        _allowed = False
        for act in self.actions:
            if act == action:
                _allowed = True
                break
        if _allowed:
            # Actions are covered by policy
            # Check if the requested directory matches any of the policy's resources
            for obj in ctx.objects:
                if any(res.match(f"{obj!s}") for res in self.resources):
                    # Requested directory is covered by policy

                    # Check if the user belongs to a group that has permission
                    user_groups = ctx.userinfo.get('groups', [])
                    if set(user_groups).intersection(self.groups):
                        # User belongs to a group with permission, return a
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


    def filter_files(self, ctx: EvalContext, env: Environment) -> list[str]:
        """filter_files.
        Filters a list of files, returning only the files the user has access
          to according to the policy.

        :param files: A list of file names in the directory.
        :param ctx: The evaluation context, containing user, userinfo, and session.
        :param environ: The environment information, such as the current time and date.
        :return: A filtered list of file names the user has access to.
        """
        # First, check if the policy applies to the user using the evaluate method
        # If not, return an empty list
        files = ctx.objects
        policy_response = self.evaluate(ctx, env)
        allowed_files = []
        if policy_response.effect == PolicyEffect.DENY:
            # Remove the files covered by police:
            for f in files:
                if any(res.match(f) for res in self.resources):
                    if self.effect == PolicyEffect.ALLOW:
                        continue
                allowed_files.append(f)
        else:
            # If the policy applies, filter the list based on the policy's context
            # allowed_files = files
            for f in files:
                if any(res.match(f) for res in self.resources):
                    if self.effect == PolicyEffect.DENY:
                        ## remove the file(s) from list:
                        continue
                allowed_files.append(f)
        return allowed_files
