from typing import Any, Optional
from collections.abc import Mapping, MutableMapping, Iterator
from types import MappingProxyType
from aiohttp import web
from datamodel import BaseModel

# Lazy import to avoid circular dependency at module load time;
# resolved at first EvalContext construction.
_ABAC_TENANT_TRUST_HEADERS: Optional[bool] = None
_ABAC_TENANT_HEADER_ORG: Optional[str] = None
_ABAC_TENANT_HEADER_CLIENT: Optional[str] = None


def _load_tenant_conf() -> tuple[bool, str, str]:
    """Load tenant config once (avoid circular import at module level)."""
    global _ABAC_TENANT_TRUST_HEADERS, _ABAC_TENANT_HEADER_ORG, _ABAC_TENANT_HEADER_CLIENT
    if _ABAC_TENANT_TRUST_HEADERS is None:
        from navigator_auth.conf import (  # noqa: PLC0415
            ABAC_TENANT_TRUST_HEADERS,
            ABAC_TENANT_HEADER_ORG,
            ABAC_TENANT_HEADER_CLIENT,
        )

        _ABAC_TENANT_TRUST_HEADERS = ABAC_TENANT_TRUST_HEADERS
        _ABAC_TENANT_HEADER_ORG = ABAC_TENANT_HEADER_ORG
        _ABAC_TENANT_HEADER_CLIENT = ABAC_TENANT_HEADER_CLIENT
    return _ABAC_TENANT_TRUST_HEADERS, _ABAC_TENANT_HEADER_ORG, _ABAC_TENANT_HEADER_CLIENT


def _resolve_tenant(
    request: web.Request,
    userinfo: Any,
    org_id: Any,
    client_id: Any,
) -> tuple[int, int]:
    """Resolve tenant pair (org_id, client_id) in priority order.

    Priority:
      1. Explicit kwarg (both must be non-None to form a pair).
      2. Request headers X-Org-Id / X-Client-Id (only when
         ABAC_TENANT_TRUST_HEADERS is True and BOTH headers present).
      3. userinfo dict (both keys must be present and non-None).
      4. Default (1, 1) — global sentinel.

    Always returns a pair of ints; falls back to 1 on coercion failure.
    """
    trust_headers, header_org, header_client = _load_tenant_conf()

    def _coerce(v: Any) -> Optional[int]:
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    # 1. Explicit kwargs
    if org_id is not None and client_id is not None:
        o, c = _coerce(org_id), _coerce(client_id)
        if o is not None and c is not None:
            return o, c

    # 2. Headers (gated by ABAC_TENANT_TRUST_HEADERS; both required)
    if trust_headers:
        h_org = request.headers.get(header_org) if request and hasattr(request, "headers") else None
        h_cli = request.headers.get(header_client) if request and hasattr(request, "headers") else None
        if h_org is not None and h_cli is not None:
            o, c = _coerce(h_org), _coerce(h_cli)
            if o is not None and c is not None:
                return o, c

    # 3. userinfo dict
    if isinstance(userinfo, dict):
        u_org = userinfo.get("org_id")
        u_cli = userinfo.get("client_id")
        if u_org is not None and u_cli is not None:
            o, c = _coerce(u_org), _coerce(u_cli)
            if o is not None and c is not None:
                return o, c

    # 4. Global default
    return 1, 1


ASSURANCE_KEYS = ("mfa", "amr", "auth_method")


def bearer_context_from_claims(payload: Mapping[str, Any]) -> MappingProxyType:
    """Return the immutable request-local assurance of a VALIDATED bearer token.

    Args:
        payload: Decoded claims of a token that already passed signature, expiry,
            revocation and generation checks.

    Returns:
        A read-only mapping with ``user_id``, ``mfa`` (bool), ``amr`` (tuple or None)
        and ``auth_method`` (str or None). Missing claims mean "no fresh factor".
    """
    amr = payload.get("amr")
    return MappingProxyType(
        {
            "user_id": payload.get("user_id"),
            "mfa": bool(payload.get("mfa", False)),
            "amr": tuple(str(value) for value in amr) if isinstance(amr, (list, tuple)) and amr else None,
            "auth_method": payload.get("auth_method"),
        }
    )


def _userinfo_to_dict(userinfo: Any) -> dict:
    """Copy userinfo (Mapping, object or None) into a new dict."""
    if userinfo is None:
        return {}
    if isinstance(userinfo, Mapping):
        return dict(userinfo)
    if isinstance(userinfo, BaseModel):
        try:
            return dict(userinfo.to_dict())
        except Exception:  # noqa: BLE001
            pass
    try:
        return {k: v for k, v in vars(userinfo).items() if not k.startswith("_")}
    except TypeError:
        return {}


def effective_userinfo(request: Any, userinfo: Any) -> Any:
    """Return the userinfo ABAC must evaluate for this request.

    Cookie-only and non-bearer requests: ``userinfo`` unchanged. Bearer requests: a NEW
    dict holding the session userinfo minus ``ASSURANCE_KEYS``, plus the token's own
    ``mfa``/``amr``/``auth_method`` from ``request[AUTH_BEARER_CONTEXT_KEY]``; a bearer
    request without a published context gets no assurance. Never mutates the session.
    """
    from navigator_auth.conf import (  # noqa: PLC0415 — lazy, like _load_tenant_conf
        AUTH_BEARER_CONTEXT_KEY,
        AUTH_MECHANISM_BEARER,
        AUTH_MECHANISM_KEY,
    )

    getter = getattr(request, "get", None)
    if getter is None:
        return userinfo
    context = getter(AUTH_BEARER_CONTEXT_KEY)
    if context is None and getter(AUTH_MECHANISM_KEY) != AUTH_MECHANISM_BEARER:
        return userinfo
    base: dict = {k: v for k, v in _userinfo_to_dict(userinfo).items() if k not in ASSURANCE_KEYS}
    if context is None:
        return base
    token_uid = context.get("user_id")
    session_uid = base.get("user_id")
    if token_uid is not None and session_uid is not None and str(token_uid) != str(session_uid):
        return base
    if context["mfa"]:
        base["mfa"] = True
    if context["amr"] is not None:
        base["amr"] = list(context["amr"])
    if context["auth_method"]:
        base["auth_method"] = context["auth_method"]
    return base


class EvalContext(dict, MutableMapping):
    """EvalContext.

    Build The Evaluation Context from Request and User Data.
    Resolves and stores the tenant pair (org_id, client_id) for ABAC scoping.
    """

    def __init__(
        self,
        request: web.Request,
        user: Any,
        userinfo: Any,
        session: Any,
        *args,
        org_id: Any = None,
        client_id: Any = None,
        **kwargs,
    ):
        ## initialize the mutable mapping:
        self.store = {}
        # FEAT-106 review fixes (M9, D9): bearer requests evaluate the validated token's
        # assurance, never the identity-shared session's.
        effective = effective_userinfo(request, userinfo)
        if user is userinfo and effective is not userinfo:
            user = effective  # PDP fallback passes userinfo as the user (pdp.py:405)
        userinfo = effective
        self.store["request"] = request
        self.store["ip_addr"] = request.remote
        self.store["method"] = request.method
        self.store["referer"] = request.headers.get("referer", None)
        self.store["path_qs"] = request.path_qs
        self.store["path"] = request.path
        self.store["headers"] = request.headers
        self.store["url"] = request.rel_url
        try:
            self.store["is_authenticated"] = request.is_authenticated
        except AttributeError:
            if user is not None:
                self.store["is_authenticated"] = True
            else:
                self.store["is_authenticated"] = False
        self.store["user"] = user
        if user is None:
            self.store["user_keys"] = []
        elif isinstance(user, BaseModel):
            self.store["user_keys"] = user.get_fields()
        elif isinstance(user, dict):
            self.store["user_keys"] = list(user.keys())
        else:
            self.store["user_keys"] = user.__dict__.keys()
        self.store["userinfo"] = userinfo
        if isinstance(userinfo, dict):
            self.store["userinfo_keys"] = list(userinfo.keys())
        else:
            try:
                self.store["userinfo_keys"] = userinfo.__dict__.keys()
            except AttributeError:
                self.store["userinfo_keys"] = []
        self.store["session"] = session
        # FEAT-101 (Q5): first-class login-method keys for policies.
        if isinstance(userinfo, dict):
            self.store["auth_method"] = userinfo.get("auth_method")
            self.store["mfa"] = bool(userinfo.get("mfa", False))
        else:
            self.store["auth_method"] = getattr(userinfo, "auth_method", None)
            self.store["mfa"] = bool(getattr(userinfo, "mfa", False))

        # Resolve tenant pair (FEAT-092)
        resolved_org, resolved_client = _resolve_tenant(request, userinfo, org_id, client_id)
        self.store["org_id"] = resolved_org
        self.store["client_id"] = resolved_client

        self.update(*args, **kwargs)
        self._columns = list(self.store.keys())

    def __missing__(self, key):
        return False

    def items(self) -> zip:  # type: ignore
        return zip(self._columns, self.store)

    def keys(self) -> list:
        return self._columns

    def set(self, key, value) -> None:
        self.store[key] = value
        if key not in self._columns:
            self._columns.append(key)

    ### Section: Simple magic methods
    def __len__(self) -> int:
        return len(self.store)

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.store})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.store})>"

    def __contains__(self, key: str) -> bool:
        return key in self._columns

    def __iter__(self) -> Iterator:
        for value in self.store:
            yield value

    def __delitem__(self, key) -> None:
        value = self.store[key]
        del self.store[key]
        self._columns.pop(value, None)

    def __setitem__(self, key, value):
        self.store[key] = value
        if key not in self._columns:
            self._columns.append(key)

    def __getattr__(self, key):
        try:
            return super().__getattribute__("store")[key]
        except KeyError as ex:
            raise AttributeError(key) from ex

    def __setattr__(self, key, value):
        if key == "store":
            super().__setattr__(key, value)
        else:
            self.store[key] = value

    def __delattr__(self, key):
        try:
            del self.store[key]
        except KeyError as ex:
            raise AttributeError(key) from ex
