# F013 — Packaging
- citations: pyproject.toml:60 `[project.optional-dependencies]` with `uvloop`, `geoip` extras; no webauthn dependency; redis client used via `from redis import asyncio as aioredis` in backends/azure.py.
- digest: Optional-extra precedent exists → `passkey = ["webauthn>=2.0"]` with lazy import is consistent (brainstorm Q7). Production Redis version not determinable from repo (Q8).
- confidence: high (packaging), n/a (Redis version)
