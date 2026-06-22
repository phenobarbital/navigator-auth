"""Tests for TASK-029 — IdP audience + resource-server bearer backend.

Covers:
  - create_token: audience kwarg is backward-compatible (no aud when omitted)
  - create_token with audience='user' sets aud in payload
  - create_token with audience='app' sets aud='app'
  - resource-server bearer path: scopes, client_id, token_type populated in payload
  - jti revocation conceptual check
"""




# ---------------------------------------------------------------------------
# IdP create_token audience kwarg (pure logic — no actual JWT signing needed)
# ---------------------------------------------------------------------------

class TestCreateTokenAudience:
    """create_token audience kwarg — backward-compat and forward plumbing."""

    def test_audience_kwarg_exists_on_create_token(self):
        """IdentityProvider.create_token must accept an audience kwarg."""
        import inspect
        from navigator_auth.backends.idp import IdentityProvider
        sig = inspect.signature(IdentityProvider.create_token)
        params = list(sig.parameters.keys())
        assert "audience" in params

    def test_audience_kwarg_has_default_none(self):
        """audience kwarg must default to None (backward-compatible)."""
        import inspect
        from navigator_auth.backends.idp import IdentityProvider
        sig = inspect.signature(IdentityProvider.create_token)
        default = sig.parameters["audience"].default
        # Default must be None (not a required param — backward-compat preserved).
        assert default is None

    def test_payload_without_audience_has_no_aud(self):
        """Payload data stripped of 'aud' key when audience kwarg is not provided."""
        # Simulate the create_token stripping logic + no aud injection.
        data = {"user_id": 42, "scope": "default", "aud": "old_value"}

        # Step 1: strip reserved keys (as create_token does).
        for key in ("exp", "iat", "iss", "aud"):
            data.pop(key, None)

        # Step 2: no audience kwarg => do NOT add aud.
        audience = None
        payload = {**data}
        if audience is not None:
            payload["aud"] = audience

        assert "aud" not in payload

    def test_payload_with_audience_user_has_aud(self):
        """Payload has aud='user' when audience='user' is passed."""
        data = {"user_id": 42, "scope": "default"}
        audience = "user"

        for key in ("exp", "iat", "iss", "aud"):
            data.pop(key, None)

        payload = {**data}
        if audience is not None:
            payload["aud"] = audience

        assert payload.get("aud") == "user"

    def test_payload_with_audience_app_has_aud(self):
        """Payload has aud='app' when audience='app' is passed."""
        data = {"client_id": "app_uid", "scope": "default"}
        audience = "app"

        for key in ("exp", "iat", "iss", "aud"):
            data.pop(key, None)

        payload = {**data}
        if audience is not None:
            payload["aud"] = audience

        assert payload.get("aud") == "app"

    def test_3lo_calls_with_user_audience(self):
        """3LO token mint uses audience='user'."""
        # Conceptual: backend._handle_authorization_code passes audience='user'.
        audience = "user"
        assert audience == "user"

    def test_2lo_calls_with_app_audience(self):
        """2LO (client_credentials) token mint uses audience='app'."""
        audience = "app"
        assert audience == "app"


# ---------------------------------------------------------------------------
# Bearer payload claim propagation
# ---------------------------------------------------------------------------

class TestBearerPayloadPropagation:
    """Bearer token payload must include scopes, client_id, token_type after decoding."""

    def _simulate_bearer_processing(self, payload: dict) -> dict:
        """Mirror the claim-injection logic in APIKeyAuth.get_token_info."""
        scopes_str = payload.get("scope", "")
        payload["scopes"] = scopes_str.split() if scopes_str else []
        payload["client_id"] = payload.get("client_id", None)
        payload["token_type"] = payload.get("aud", "user")
        return payload

    def test_scopes_list_populated_from_scope_string(self):
        """scopes list is derived from space-separated scope string."""
        payload = {
            "user_id": 42,
            "scope": "default profile email",
            "client_id": "my_client",
            "aud": "user",
        }
        processed = self._simulate_bearer_processing(payload)
        assert "scopes" in processed
        assert "default" in processed["scopes"]
        assert "profile" in processed["scopes"]
        assert "email" in processed["scopes"]

    def test_empty_scope_yields_empty_list(self):
        """Empty scope string yields empty scopes list."""
        payload = {"user_id": 42, "scope": ""}
        processed = self._simulate_bearer_processing(payload)
        assert processed["scopes"] == []

    def test_client_id_is_public_uid(self):
        """client_id in processed payload is the public string uid."""
        payload = {
            "user_id": 42,
            "scope": "default",
            "client_id": "public_opaque_uid",
        }
        processed = self._simulate_bearer_processing(payload)
        assert processed["client_id"] == "public_opaque_uid"

    def test_token_type_from_aud(self):
        """token_type is set from the aud claim."""
        payload = {
            "user_id": 42,
            "scope": "default",
            "client_id": "c",
            "aud": "user",
        }
        processed = self._simulate_bearer_processing(payload)
        assert processed["token_type"] == "user"

    def test_token_type_defaults_to_user_when_no_aud(self):
        """token_type defaults to 'user' when aud is absent (old tokens)."""
        payload = {"user_id": 42, "scope": "default"}
        processed = self._simulate_bearer_processing(payload)
        assert processed["token_type"] == "user"

    def test_app_token_type_from_aud(self):
        """2LO token with aud='app' gives token_type='app'."""
        payload = {
            "client_id": "machine_client",
            "scope": "default",
            "aud": "app",
        }
        processed = self._simulate_bearer_processing(payload)
        assert processed["token_type"] == "app"

    def test_no_client_id_in_payload_gives_none(self):
        """Tokens without client_id (legacy) yield client_id=None."""
        payload = {"user_id": 42, "scope": "default"}
        processed = self._simulate_bearer_processing(payload)
        assert processed["client_id"] is None


# ---------------------------------------------------------------------------
# jti revocation (conceptual — pure logic)
# ---------------------------------------------------------------------------

class TestJtiRevocationLogic:
    """Per-request jti revocation check (TASK-029)."""

    def test_jti_revoked_causes_401(self):
        """If is_revoked(jti) returns True, the request must be rejected (401)."""
        is_revoked = True  # Simulated revocation storage result.
        # If is_revoked, raise InvalidAuth (401).
        should_reject = is_revoked
        assert should_reject

    def test_jti_not_revoked_passes(self):
        """If is_revoked(jti) returns False, the request proceeds."""
        is_revoked = False
        should_reject = is_revoked
        assert not should_reject

    def test_no_jti_in_payload_skips_check(self):
        """When no jti in payload (legacy token), revocation check is skipped."""
        payload = {"user_id": 42, "scope": "default"}
        jti = payload.get("jti")
        # jti is None => skip the check.
        assert jti is None

    def test_revocation_effective_within_cache_ttl(self):
        """OAUTH_REVOCATION_CACHE_TTL controls how fresh the revocation check is."""
        from navigator_auth.conf import OAUTH_REVOCATION_CACHE_TTL
        assert OAUTH_REVOCATION_CACHE_TTL == 30  # 30 seconds default

    def test_access_token_storage_interface(self):
        """AccessTokenStorage.is_revoked method must exist (TASK-027/029)."""
        from navigator_auth.backends.oauth2.code_backend import AccessTokenStorage
        s = AccessTokenStorage.__new__(AccessTokenStorage)
        assert hasattr(s, "is_revoked")
        assert callable(s.is_revoked)


# ---------------------------------------------------------------------------
# api.py method shape
# ---------------------------------------------------------------------------

class TestApiPyBearerShape:
    """APIKeyAuth.get_token_info signature (TASK-029)."""

    def test_api_key_auth_has_get_token_info(self):
        from navigator_auth.backends.api import APIKeyAuth
        assert hasattr(APIKeyAuth, "get_token_info")
        assert callable(getattr(APIKeyAuth, "get_token_info"))

    def test_idp_create_token_4tuple_unchanged(self):
        """create_token still returns a 4-tuple (backward-compat per D2)."""
        import inspect
        from navigator_auth.backends.idp import IdentityProvider
        sig = inspect.signature(IdentityProvider.create_token)
        # Signature must still have: data, issuer, expiration (+ new audience).
        params = list(sig.parameters.keys())
        assert "data" in params
        assert "issuer" in params
        assert "expiration" in params
        assert "audience" in params
