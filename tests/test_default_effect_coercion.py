"""Tests for default_effect coercion in PolicyEvaluator.

Regression coverage for 0.20.10: the Rust PEP (`rs_pep`) expects
``default_effect`` as a Python ``str``. Older callers (code written
against navigator-auth <= 0.20.8) stored a ``PolicyEffect`` enum on
``PolicyEvaluator._default_effect``. The evaluator must accept both and
always cross the Rust boundary with a string.
"""
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web

from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.policies import Environment, PolicyEffect
from navigator_auth.abac.policies import evaluator as evaluator_mod
from navigator_auth.abac.policies.evaluator import (
    _RS_PEP_AVAILABLE,
    _coerce_default_effect,
)
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.resources import ResourceType


class TestCoerceDefaultEffectHelper:
    """Pure-Python unit tests — no Rust needed."""

    def test_none_defaults_to_deny(self):
        assert _coerce_default_effect(None) == "deny"

    def test_string_allow_lowercase(self):
        assert _coerce_default_effect("allow") == "allow"

    def test_string_deny_lowercase(self):
        assert _coerce_default_effect("deny") == "deny"

    def test_string_mixed_case(self):
        assert _coerce_default_effect("ALLOW") == "allow"
        assert _coerce_default_effect("Deny") == "deny"

    def test_string_with_whitespace(self):
        assert _coerce_default_effect("  allow  ") == "allow"

    def test_enum_allow(self):
        assert _coerce_default_effect(PolicyEffect.ALLOW) == "allow"

    def test_enum_deny(self):
        assert _coerce_default_effect(PolicyEffect.DENY) == "deny"

    def test_unknown_string_falls_back_to_deny(self):
        assert _coerce_default_effect("banana") == "deny"

    def test_unknown_type_falls_back_to_deny(self):
        assert _coerce_default_effect(42) == "deny"


@pytest.fixture
def user_info():
    return {
        "username": "jlara@trocglobal.com",
        "groups": ["engineering"],
        "roles": ["user"],
    }


@pytest.fixture
def eval_context(user_info):
    request = MagicMock(spec=web.Request)
    request.path = "/api/v1/user/session"
    request.method = "GET"

    class User:
        def __init__(self):
            self.username = user_info["username"]
            self.groups = user_info["groups"]
            self.id = 35

    return EvalContext(request, User(), user_info, None)


@pytest.fixture
def environment():
    return Environment()


@pytest.mark.skipif(
    not _RS_PEP_AVAILABLE,
    reason="rs_pep Rust extension not available in this environment",
)
class TestEvaluatorRustBoundary:
    """Verify the Python->Rust call always receives a string for default_effect."""

    def _make_evaluator(self):
        from navigator_auth.abac.policies.evaluator import PolicyEvaluator
        return PolicyEvaluator()

    def test_enum_assignment_is_coerced_at_call_site(
        self, eval_context, environment
    ):
        evaluator = self._make_evaluator()
        # Simulate a legacy caller assigning the enum directly.
        evaluator._default_effect = PolicyEffect.DENY

        captured = {}

        def fake_evaluate_single(*args, **kwargs):
            captured["default_effect"] = kwargs.get("default_effect")
            return {
                "allowed": False,
                "effect": "deny",
                "matched_policy": None,
                "reason": "stub",
            }

        with patch.object(evaluator_mod, "evaluate_single", side_effect=fake_evaluate_single):
            evaluator.check_access(
                eval_context,
                ResourceType.URI,
                "/api/v1/user/session",
                "uri:read",
                environment,
            )

        assert isinstance(captured["default_effect"], str)
        assert captured["default_effect"] == "deny"

    def test_string_assignment_is_passed_through(
        self, eval_context, environment
    ):
        evaluator = self._make_evaluator()
        evaluator._default_effect = "allow"

        captured = {}

        def fake_evaluate_single(*args, **kwargs):
            captured["default_effect"] = kwargs.get("default_effect")
            return {
                "allowed": True,
                "effect": "allow",
                "matched_policy": None,
                "reason": "stub",
            }

        with patch.object(evaluator_mod, "evaluate_single", side_effect=fake_evaluate_single):
            evaluator.check_access(
                eval_context,
                ResourceType.URI,
                "/api/v1/user/session",
                "uri:read",
                environment,
            )

        assert captured["default_effect"] == "allow"

    def test_filter_resources_also_coerces(self, eval_context, environment):
        evaluator = self._make_evaluator()
        evaluator._default_effect = PolicyEffect.DENY

        captured = {}

        def fake_filter(*args, **kwargs):
            captured["default_effect"] = kwargs.get("default_effect")
            return {"allowed": [], "denied": args[1] if len(args) > 1 else []}

        with patch.object(evaluator_mod, "filter_resources_batch", side_effect=fake_filter):
            evaluator.filter_resources(
                eval_context,
                ResourceType.URI,
                ["/api/v1/a", "/api/v1/b"],
                "uri:read",
                environment,
            )

        assert isinstance(captured["default_effect"], str)
        assert captured["default_effect"] == "deny"

    def test_init_default_is_string(self):
        evaluator = self._make_evaluator()
        assert isinstance(evaluator._default_effect, str)
        assert evaluator._default_effect in ("allow", "deny")
