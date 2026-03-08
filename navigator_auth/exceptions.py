"""Navigator Auth Exceptions."""

class AuthException(Exception):
    """Base class for other exceptions"""

    status: int = 400

    def __init__(self, message: str, status: int = 400, **kwargs):
        super().__init__(message)
        self.stacktrace = None
        if 'stacktrace' in kwargs:
            self.stacktrace = kwargs['stacktrace']
        self.message = message
        self.status = int(status)

    def __repr__(self):
        return f"{self.message}"

    def __str__(self):
        return f"{self.message}"

    def get(self):
        return self.message

#### Exceptions:
class ConfigError(AuthException):

    def __init__(self, message: str = None, status=500):
        super().__init__(message or "Auth Configuration Error.", status=status)

#### Authentication / Authorization
class UserNotFound(AuthException):

    def __init__(self, message: str = None, status=404):
        super().__init__(message or "User doesn't exists.", status=status)

class Unauthorized(AuthException):

    def __init__(self, message: str = None, status=401):
        super().__init__(message or "Unauthorized", status=status)

class InvalidAuth(AuthException):

    def __init__(self, message: str = None, status=401):
        super().__init__(message or "Invalid Authentication", status=status)

class FailedAuth(AuthException):

    def __init__(self, message: str = None, status=403):
        super().__init__(message or "Failed Authorization", status=status)

class Forbidden(AuthException):

    def __init__(self, message: str = None, status=403):
        super().__init__(message or "Forbidden", status=status)

class AuthExpired(AuthException):

    def __init__(self, message: str = None, status=410):
        super().__init__(message or "Gone: Authentication Expired.", status=status)
