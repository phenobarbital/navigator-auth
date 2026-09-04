# Navigator Auth #

Navigator Auth is an Authentication/Authorization toolkit for aiohttp or Navigator, based on Asyncio.

[![pypi](https://img.shields.io/pypi/v/asyncdb?style=plastic)](https://pypi.org/project/asyncdb/)
[![versions](https://img.shields.io/pypi/pyversions/blacksheep.svg?style=plastic)](https://github.com/phenobarbital/navigator-auth)
[![Apache 2.0 licensed](https://img.shields.io/github/license/phenobarbital/navigator-auth?style=plastic)](https://raw.githubusercontent.com/phenobarbital/navigator-auth/master/LICENSE)


---

## Introduction

* Quick summary
* Version
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)

### Getting Started ###

* Installation
* Configuration
* Dependencies
* Database configuration
* How to run tests
* Deployment instructions

### Requirements ###

* Python >= 3.9
* asyncio (https://pypi.python.org/pypi/asyncio/)
* aiohttp >= 3.8
* Navigator-API >= 2.1

### Authentication Methods ###

Selected via the `X-Auth-Method` header on `POST /api/v1/login` (value =
the backend's class name):

| `X-Auth-Method` | Backend | Notes |
|---|---|---|
| `BasicAuth` | Username/password | |
| `TokenExchangeAuth` | External Token Exchange | Exchange an already-issued Azure/Google/GitHub bearer token for a session without a browser redirect. See the "Token Exchange" documentation page. |
| `AzureAuth` | Microsoft Azure AD / ADFS | |
| `GoogleAuth` | Google | |
| `GithubAuth` | GitHub OAuth2 | |
| `ADFSAuth` | Microsoft ADFS (OIDC) | |
| `OktaAuth` | Okta | |
| `SAMLAuth` | SAML 2.0 Service Provider | Delegates login to an external IdP (Okta, Entra ID, a partner IdP). See the "SAML Authentication" documentation page. |
| `SAMLIdentityProvider` | SAML 2.0 Identity Provider | Issues signed assertions for the current session to registered external SPs (e.g. Verizon Connect); never appears in `X-Auth-Method`/`/api/v1/auth/methods` (`hidden = True`) since it never authenticates a login itself. |
| `Oauth2Provider` | Navigator-as-OAuth2-Authorization-Server | For MCP/AI-agent and 3rd-party client flows. |

### License ###

Navigator_Auth is copyright of Jesus Lara (https://phenobarbital.info) and is under Apache 2 license. I am providing code in this repository under an open source license, remember, this is my personal repository; the license that you receive is from me and not from my employeer.
