"""Navigator Auth Exceptions."""


class AuthException(Exception):
    """Base class for other exceptions"""

    status: int = 400

    def __init__(self, message: str, status: int = 400, **kwargs):
        super().__init__(message)
        self.stacktrace = None
        if "stacktrace" in kwargs:
            self.stacktrace = kwargs["stacktrace"]
        self.message = message
        self.status = status

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


#### Second factor (FEAT-106)
class MfaSignal(AuthException):
    """Terminal outcome of the BasicAuth second-factor hook (FEAT-106, D1)."""

    def payload(self) -> dict:
        """Return the JSON body of the HTTP response without session material."""
        raise NotImplementedError


class MFARequired(MfaSignal):
    """Credentials are valid, but a second factor is owed."""

    def __init__(
        self,
        challenge: str,
        providers: list[str],
        preferred: str,
        expires_in: int,
        status: int = 401,
    ):
        super().__init__("Second factor required", status=status)
        self._challenge = challenge
        self.providers = list(providers)
        self.preferred = preferred
        self.expires_in = int(expires_in)

    def payload(self) -> dict:
        """Return the required-second-factor challenge envelope."""
        return {
            "mfa_required": True,
            "challenge": self._challenge,
            "providers": list(self.providers),
            "preferred": self.preferred,
            "expires_in": self.expires_in,
        }


class MFARefused(MfaSignal):
    """The MFA layer refused the login and therefore fails closed."""

    STRONG_FACTOR_REQUIRED = "strong_factor_required"
    NO_FACTOR_AVAILABLE = "no_factor_available"
    MFA_UNAVAILABLE = "mfa_unavailable"

    def __init__(self, code: str, message: str = None, status: int = 403):
        super().__init__(message or code, status=status)
        self.code = code

    def payload(self) -> dict:
        """Return the safe refusal response body."""
        return {"error": self.code, "message": self.message}
