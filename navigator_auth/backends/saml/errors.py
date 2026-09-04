"""SAML error hierarchy and the `pysaml2` exception translator.

FEAT-097 §2 "Stable error codes". `SAMLError` subclasses map 1:1 to the
stable codes surfaced on `error=` (failed-redirect) and in audit records.
Callers should never echo raw XML or IdP-supplied text; `map_pysaml2_error`
keeps the safe, stable code while the original exception is only logged.
"""
from ...exceptions import AuthException


class SAMLError(AuthException):
    """Base for all FEAT-097 SAML errors. `code` is the stable error code."""

    code: str = "SAML_INVALID_RESPONSE"

    def __init__(self, message: str = None, status: int = 400, code: str = None):
        super().__init__(message or self.code, status=status)
        if code:
            self.code = code


class SAMLInvalidResponse(SAMLError):
    code = "SAML_INVALID_RESPONSE"


class SAMLInvalidSignature(SAMLError):
    code = "SAML_INVALID_SIGNATURE"


class SAMLExpired(SAMLError):
    code = "SAML_EXPIRED"


class SAMLReplay(SAMLError):
    code = "SAML_REPLAY"


class SAMLStaleRequest(SAMLError):
    code = "SAML_STALE_REQUEST"


class SAMLAudienceMismatch(SAMLError):
    code = "SAML_AUDIENCE_MISMATCH"


class SAMLDecryptFailed(SAMLError):
    code = "SAML_DECRYPT_FAILED"


class SAMLNotAuthenticated(SAMLError):
    code = "SAML_NOT_AUTHENTICATED"
    status = 401


class SAMLUserNotFound(SAMLError):
    code = "SAML_USER_NOT_FOUND"
    status = 404


class SAMLForbidden(SAMLError):
    code = "SAML_FORBIDDEN"
    status = 403


class SAMLUnknownSP(SAMLError):
    code = "SAML_UNKNOWN_SP"
    status = 404


class SAMLSPForbidden(SAMLError):
    code = "SAML_SP_FORBIDDEN"
    status = 403


class SAMLInvalidAuthnRequest(SAMLError):
    code = "SAML_INVALID_AUTHN_REQUEST"


class SAMLSLOFailed(SAMLError):
    code = "SAML_SLO_FAILED"


#: code -> exception class, used by callers building an error from a stable code.
ERROR_CODES = {
    cls.code: cls
    for cls in (
        SAMLInvalidResponse,
        SAMLInvalidSignature,
        SAMLExpired,
        SAMLReplay,
        SAMLStaleRequest,
        SAMLAudienceMismatch,
        SAMLDecryptFailed,
        SAMLNotAuthenticated,
        SAMLUserNotFound,
        SAMLForbidden,
        SAMLUnknownSP,
        SAMLSPForbidden,
        SAMLInvalidAuthnRequest,
        SAMLSLOFailed,
    )
}


def map_pysaml2_error(exc: BaseException) -> SAMLError:
    """Translate a `pysaml2` exception into a stable `SAMLError`.

    Never includes the original exception's text verbatim in the returned
    message (callers log `exc` themselves, at most, at warning level); the
    message here is a safe, generic description of the failure class.
    """
    # Import lazily: keeps `errors.py` importable without pysaml2 installed
    # (e.g. for tooling that only needs the stable codes).
    try:
        from saml2.validate import ResponseLifetimeExceed, ToEarly, NotValid
    except ImportError:  # pragma: no cover - pysaml2 always present at runtime
        ResponseLifetimeExceed = ToEarly = NotValid = ()
    try:
        from saml2.sigver import (
            SignatureError,
            CertificateError,
            DecryptError as SigverDecryptError,
            XmlsecError,
        )
    except ImportError:  # pragma: no cover
        SignatureError = CertificateError = SigverDecryptError = XmlsecError = ()
    try:
        from saml2.response import StatusError, DecryptError as ResponseDecryptError
    except ImportError:  # pragma: no cover
        StatusError = ResponseDecryptError = ()
    try:
        from saml2.s_utils import UnknownPrincipal, UnravelError
    except ImportError:  # pragma: no cover
        UnknownPrincipal = UnravelError = ()

    if isinstance(exc, (ResponseLifetimeExceed, ToEarly)):
        return SAMLExpired("SAML assertion is outside its validity window.")
    if isinstance(exc, (SignatureError, CertificateError)):
        return SAMLInvalidSignature("SAML response/assertion signature validation failed.")
    if isinstance(exc, (SigverDecryptError, ResponseDecryptError, XmlsecError)):
        return SAMLDecryptFailed("Unable to decrypt the SAML assertion.")
    if isinstance(exc, (UnknownPrincipal, UnravelError, StatusError, NotValid)):
        return SAMLInvalidResponse("SAML response failed validation.")
    return SAMLInvalidResponse("SAML response could not be processed.")
