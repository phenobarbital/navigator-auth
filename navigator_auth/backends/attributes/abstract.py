from typing import Any, Tuple
import logging
from collections.abc import Iterable
from abc import ABCMeta, abstractmethod

class UserAttribute(metaclass=ABCMeta):
    """UserAttribute.

        Interface for Set Custom User Attributes.
    """
    name: str

    def __call__(self, user: Iterable, userdata: dict, **kwargs) -> Tuple[str, Any]:
        try:
            return (self.name, self.get_value(user, userdata, **kwargs))
        except Exception as exc:
            logging.warning(
                f'Error getting user attribute {self.name}: {exc}'
            )
            return self.name, None

    @abstractmethod
    def get_value(self, user: Iterable, userdata: dict, **kwargs):
        """Get value for given user attribute and set into user data.
        Args:
            user (Iterable): User.
            userdata (dict): User data.
            **kwargs: Additional arguments.

        Returns:
            str: Attribute Value.
        """
        pass
