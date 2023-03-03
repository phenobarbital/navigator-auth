from abc import ABCMeta, abstractmethod


class AbstractStorage(metaclass=ABCMeta):
    """AbstractStorage.

    Base class for Any Policy Storage.

    Raises:
        RuntimeError: Some exception raised.
        web.InternalServerError: Database connector is not installed.

    Returns:
        A collection of Policies loaded from Storage.
    """

    @abstractmethod
    async def load_policies(self):
        """load_policies.

        Load all Policies from Storage.
        """
