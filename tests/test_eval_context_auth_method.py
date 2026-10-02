"""FEAT-101 TASK-92 — EvalContext exposes auth_method and mfa."""

from types import SimpleNamespace

from navigator_auth.abac.context import EvalContext


def test_eval_context_auth_method_mfa(make_request):
    """Keys present; defaults None/False; values from dict and object userinfo."""
    req = make_request()
    ctx = EvalContext(req, None, {"auth_method": "passkey", "mfa": True}, {})
    assert ctx.store["auth_method"] == "passkey" and ctx.store["mfa"] is True
    assert "auth_method" in ctx and "mfa" in ctx

    ctx = EvalContext(req, None, SimpleNamespace(auth_method="basic", mfa=0), {})
    assert ctx.store["auth_method"] == "basic" and ctx.store["mfa"] is False

    ctx = EvalContext(req, None, None, {})
    assert ctx.store["auth_method"] is None and ctx.store["mfa"] is False

    ctx = EvalContext(req, None, {}, {})
    assert ctx.store["auth_method"] is None and ctx.store["mfa"] is False
