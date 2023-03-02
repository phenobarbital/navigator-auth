from typing import List, Optional
from .policy import Policy

class PDP:
    """ABAC Policy Decision Point implementation.
    """
    def __init__(self, policies: Optional[List[Policy]] = None):
        self._policies: list = []
        if policies:
            self._policies = policies

    def add_policy(self, policy: Policy):
        self._policies.append(policy)
        self.sorted_policies()

    def sorted_policies(self):
        self._policies.sort(key=lambda policy: policy.priority)
