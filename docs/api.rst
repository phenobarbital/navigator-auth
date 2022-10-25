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