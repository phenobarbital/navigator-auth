# Authorization Backends — Allowed Hosts & IPs (PowerBI)

Navigator Auth ships a set of pluggable **authorization backends** that grant
access to a request *before* (or independently of) user authentication. They are
ideal for whitelisting trusted origins such as **Microsoft Power BI**, which
needs to reach embedded/data endpoints by hostname or by Azure-owned IP ranges.

This document focuses on the host/IP based backends and, specifically, on how to
authorize **Power BI** traffic both by **allowed hosts** and by **Azure Service
Tag IP ranges**.

## How authorization is evaluated

During request processing, every configured authorization backend is checked in
order. **If any backend returns `True`, the request is authorized** (logical OR).

```python
# navigator_auth/auth.py
for backend in self._authz_backends:
    if await backend.check_authorization(request):
        return True
```

Backends are selected via the `AUTHORIZATION_BACKENDS` setting (comma-separated).
Default: `allow_hosts`.

```ini
[auth]
AUTHORIZATION_BACKENDS: allow_hosts, allowed_ips
```

Each name maps to a backend class in `navigator_auth/authorizations/`:

| Name (config)             | Class                | Authorizes by                          |
|---------------------------|----------------------|----------------------------------------|
| `allow_hosts`             | `authz_allow_hosts`  | `Origin`/host vs. **fnmatch patterns** |
| `allowed_ips`             | `authz_allowed_ips`  | Client IP vs. **IPs / CIDR ranges**    |
| `hosts`                   | `authz_hosts`        | Exact host/origin match                |
| `useragent`               | `authz_useragent`    | Substring match on `User-Agent`        |

Custom backends can also be referenced by their fully-qualified class path.

---

## 1. Allowed Hosts (`allow_hosts`) — recommended for Power BI

`authz_allow_hosts` compares the request host / `Origin` header against the
`ALLOWED_HOSTS` list using `fnmatch`, so wildcard patterns are supported
(e.g. `*.analysis.windows.net`).

```python
# navigator_auth/authorizations/allow_hosts.py
origin = request.host or request.headers["origin"]
for key in ALLOWED_HOSTS:
    if fnmatch.fnmatch(origin, key):
        return True
```

### Configuration

```ini
[auth]
AUTHORIZATION_BACKENDS: allow_hosts
ALLOWED_HOSTS: *.analysis.windows.net,*.windows.net,*.powerbi.com,*.powerapps.com,*appsource.microsoft.com,*.s-microsoft.com,*.azureedge.net,*.microsoft.com
```

The Power BI domains above mirror Microsoft's published allow-list for Power BI.
See: <https://learn.microsoft.com/en-us/fabric/security/power-bi-allow-list-urls>

> Default for `ALLOWED_HOSTS` is `localhost*` when unset.

---

## 2. Allowed IPs (`allowed_ips`)

`authz_allowed_ips` authorizes based on the **client source IP**. It supports
individual IPs and CIDR ranges, and honors `X-Forwarded-For` **only** when the
direct peer is a configured trusted proxy.

```ini
[auth]
AUTHORIZATION_BACKENDS: allowed_ips
ALLOWED_IPS: 10.0.0.0/8, 192.168.1.50, 13.73.248.16/29
ALLOWED_IP_TRUSTED_PROXIES: 10.0.0.1, 10.0.0.2
```

- `ALLOWED_IPS` — comma-separated IPs and/or CIDR ranges. Invalid entries are
  logged and ignored.
- `ALLOWED_IP_TRUSTED_PROXIES` — proxy IPs allowed to set `X-Forwarded-For`. If
  the peer is not a trusted proxy, the direct `request.remote` is used.

The backend exposes `add_networks(cidrs: list[str]) -> int` to inject ranges at
runtime — this is how Azure Service Tags (below) extend the allow-list on startup.

---

## 3. Power BI via Azure Service Tags (dynamic IP whitelisting)

Hostname matching covers browser-originated Power BI traffic, but **server-side
Power BI / Power Query Online** connectors reach your service from Azure-owned IP
ranges that change over time. Navigator Auth can fetch these ranges automatically
from Microsoft's official **Azure Service Tags** feed and inject them into the
`allowed_ips` backend at startup.

### How it works

1. On `auth_startup`, if `AZURE_SERVICE_TAGS` is set, the handler calls
   `_load_azure_service_tags()` (`navigator_auth/auth.py`).
2. `fetch_service_tag_prefixes()`
   (`navigator_auth/authorizations/azure_service_tags.py`) resolves and downloads
   the Microsoft `ServiceTags_Public_*.json` file and extracts the
   `addressPrefixes` for the requested tags.
3. The resulting CIDR list is injected via `ip_backend.add_networks(prefixes)`.

If `allowed_ips` is **not** in `AUTHORIZATION_BACKENDS`, the fetch is skipped with
a warning.

### Configuration

```ini
[auth]
AUTHORIZATION_BACKENDS: allow_hosts, allowed_ips
ALLOWED_HOSTS: *.analysis.windows.net,*.powerbi.com,*.microsoft.com
AZURE_SERVICE_TAGS: PowerBI, PowerQueryOnline
```

- `AZURE_SERVICE_TAGS` — comma-separated Azure service tag names. Common tags for
  Power BI: `PowerBI`, `PowerQueryOnline`.
- Requires outbound HTTPS access to `microsoft.com` / `download.microsoft.com` at
  startup. If the download fails, it logs an error and continues (no ranges added).

Reference: <https://learn.microsoft.com/en-us/fabric/security/power-bi-allow-list-urls>

---

## 4. Other backends

### Hosts (`hosts`)

`authz_hosts` does a plain exact-match of `request.host` or the `Origin` header
against the `HOSTS` list (no wildcards). Use `allow_hosts` if you need patterns.

### User-Agent (`useragent`)

`authz_useragent` allows requests whose `User-Agent` contains any of the
case-insensitive substrings in `ALLOWED_UA` (default `*`). Useful for trusted
service-to-service callers identified by their UA string.

```ini
[auth]
ALLOWED_UA: NavigatorService, MyInternalBot
```

---

## Recommended Power BI setup

For most deployments serving Power BI, combine host-based and IP-based
authorization so both browser and connector traffic are covered:

```ini
[auth]
AUTHORIZATION_BACKENDS: allow_hosts, allowed_ips
ALLOWED_HOSTS: *.analysis.windows.net,*.windows.net,*.powerbi.com,*.powerapps.com,*appsource.microsoft.com,*.s-microsoft.com,*.azureedge.net,*.microsoft.com
AZURE_SERVICE_TAGS: PowerBI, PowerQueryOnline
ALLOWED_IP_TRUSTED_PROXIES: 10.0.0.1
```

- `allow_hosts` authorizes Power BI **browser/embed** traffic by hostname.
- `allowed_ips` + `AZURE_SERVICE_TAGS` authorizes Power BI **server-side
  connector** traffic by Azure IP range.

## Settings reference

| Setting                      | Section | Default       | Used by        |
|------------------------------|---------|---------------|----------------|
| `AUTHORIZATION_BACKENDS`     | —       | `allow_hosts` | dispatcher     |
| `ALLOWED_HOSTS`              | `auth`  | `localhost*`  | `allow_hosts`  |
| `ALLOWED_IPS`                | `auth`  | empty         | `allowed_ips`  |
| `ALLOWED_IP_TRUSTED_PROXIES` | `auth`  | empty         | `allowed_ips`  |
| `AZURE_SERVICE_TAGS`         | `auth`  | empty         | `allowed_ips`  |
| `ALLOWED_UA`                 | —       | `*`           | `useragent`    |

## Source files

- `navigator_auth/authorizations/allow_hosts.py` — `authz_allow_hosts`
- `navigator_auth/authorizations/allowed_ips.py` — `authz_allowed_ips`
- `navigator_auth/authorizations/azure_service_tags.py` — Service Tag fetcher
- `navigator_auth/authorizations/hosts.py` — `authz_hosts`
- `navigator_auth/authorizations/useragent.py` — `authz_useragent`
- `navigator_auth/auth.py` — backend registration, evaluation, Azure startup hook
- `navigator_auth/conf.py` — settings
