# F015 — Only tenant resolver is ABAC's (org_id, client_id); needs user or trusted headers
- query: grep tenant in navigator_auth; read abac/context.py:10-60
- citations: navigator_auth/abac/context.py:28 `_resolve_tenant(request, userinfo, org_id, client_id) -> tuple[int, int]` (kwargs → X-Org-Id/X-Client-Id headers only if ABAC_TENANT_TRUST_HEADERS → userinfo → (1,1)); conf.py:802-808 `ABAC_TENANT_TRUST_HEADERS` (default False), `ABAC_TENANT_HEADER_ORG/CLIENT`; sdd/specs/per-tenant-policy-scoping.spec.md.
- digest: There is no pre-authentication tenant → domain mapping. A per-tenant RP ID (user decision U1) cannot reuse _resolve_tenant for usernameless login (no userinfo yet; headers untrusted by default). The RP must be resolved from the request's Origin/host matched against a configured allow-list map (E3: never trust Host blindly). New mechanism → spec must design it.
- confidence: high (absence), medium (proposed approach)
