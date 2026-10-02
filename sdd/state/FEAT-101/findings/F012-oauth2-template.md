# F012 — OAuth2 login template location
- citations: backends/oauth2/backend.py:1712 `self._parser.view(filename="oauth/login.html", params=data)`; file templates/oauth/login.html at repo root (no navigator_auth/templates dir).
- digest: Resolves "not verified" item; impact table path `navigator_auth/templates/` is wrong — template is `templates/oauth/login.html`.
- confidence: high
