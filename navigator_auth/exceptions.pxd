# cython: language_level=3, embedsignature=True, boundscheck=False, wraparound=True, initializedcheck=False
# Copyright (C) 2018-present Jesus Lara
#
"""Navigator Auth Exceptions."""
cdef class AuthException(Exception):
    """Base class for other exceptions"""
    pass

#### Exceptions:
cdef class ConfigError(AuthException):
    pass

#### Authentication / Authorization
cdef class UserNotFound(AuthException):
    pass

cdef class Unauthorized(AuthException):
    pass

cdef class InvalidAuth(AuthException):
    pass

cdef class FailedAuth(AuthException):
    pass

cdef class Forbidden(AuthException):
    pass

cdef class AuthExpired(AuthException):
    pass
