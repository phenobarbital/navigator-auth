api
========

``Authorizations``
-------------

.. autofunction:: navigator_auth.authorizations.abstract.AuthorizationPolicy
.. autofunction:: navigator_auth.authorizations.allow_hosts.authz_allow_hosts
.. autofunction:: navigator_auth.authorizations.hosts.authz_hosts


``Backends``
----------------

.. autofunction:: navigator_auth.backends.adfs.ADFSAuth 
.. autofunction:: navigator_auth.backends.azure.AzureAuth
.. autofunction:: navigator_auth.backends.base.BaseAuthBackend 
.. autofunction:: navigator_auth.backends.basic.BasicAuth 
.. autofunction:: navigator_auth.backends.django.DjangoAuth 
.. autofunction:: navigator_auth.backends.external.ExternalAuth 
.. autofunction:: navigator_auth.backends.github.GithubAuth 
.. autofunction:: navigator_auth.backends.google.GoogleAuth 
.. autofunction:: navigator_auth.backends.noauth.NoAuthAuth 
.. autofunction:: navigator_auth.backends.oauth.OauthAuth 
.. autofunction:: navigator_auth.backends.okta.OktaAuth 
.. autofunction:: navigator_auth.backends.token.TokenAuth 
.. autofunction:: navigator_auth.backends.troc.TrocTokenAuth 
 

``Handlers``
--------------

.. autofunction:: navigator_auth.handlers.base.UserHandler
.. autofunction:: navigator_auth.handlers.base.BaseView
.. autofunction:: navigator_auth.handlers.handler.UserHandler
.. autofunction:: navigator_auth.handlers.info.UserInfo


``Middlewares``
--------------

.. autofunction:: navigator_auth.middlewares.abstract.base_middleware
.. autofunction:: navigator_auth.middlewares.apikey.apikey_middleware
.. autofunction:: navigator_auth.middlewares.django.django_middleware
.. autofunction:: navigator_auth.middlewares.jwt.jwt_middleware
.. autofunction:: navigator_auth.middlewares.token.token_middleware



``Storages``
--------------

.. autofunction:: navigator_auth.storages.abstract.AuthStorage

``Token expiry fields`` (FEAT-103, client-visible change)
-----------------------------------------------------------

Login, refresh, ephemeral-token and external-callback responses publish:

``expires_in``
   Integer **seconds remaining** (RFC 6749 section 4.2.2), never below ``0``.
   Previously these responses carried an absolute epoch under this key, which
   no client could consume correctly. This extends the existing ``B1`` decision
   ("expires_in is seconds", ``navigator_auth/backends/oauth2/backend.py``) to
   the legacy login publishers; the OAuth2 provider backend already behaved
   this way.

``expires_at``
   New. Integer absolute epoch of the expiry.

The dynamic user attribute follows the same change: ``request.user.expires_in``
is now seconds remaining and ``request.user.expires_at`` carries the epoch. That
attribute is undeclared on ``Identity``, so there is no schema version to bump —
any consumer that read ``request.user.expires_in`` as a timestamp must switch to
``expires_at``. See the ``CHANGELOG.md`` entry for the same note.
