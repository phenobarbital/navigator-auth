Config
========

SAML 2.0 (FEAT-097)
---------------------

``navigator_auth.backends.saml`` layers two abstract roles on ``pysaml2``:
``AbstractSAMLBackend`` (Service Provider) and
``AbstractSAMLIdentityProvider`` (Identity Provider), sharing one
``SAMLCore`` engine wrapper. The generic reference subclasses ``SAMLAuth``
and ``SAMLIdentityProvider`` read the ``SAML_*``/``SAML_IDP_*`` keys — see
:doc:`settings` for the full key table and
:doc:`../documentation/saml` for configuration examples, the subclassing
hook tables, routes, error codes, and the ``python3-saml`` migration guide.

Requires the ``xmlsec1`` system binary (``pysaml2`` shells out to it for
every signature operation); see :doc:`../documentation/saml` for
per-distribution install instructions.
