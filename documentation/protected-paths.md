# Protected system paths and probe detection

`protected_paths_middleware` is installed automatically by `AuthHandler.setup()`
and by `PDP.setup()` as the **first (outermost)** middleware. It does two
things:

1. refuses system paths (`/.env`, `/etc/`, `/logs/`, keys, config files...)
   before anything else runs;
2. reports, once per host, a client that keeps getting unauthenticated
   requests rejected (a scanner or a brute-force attempt).

## 1. Hard deny for system paths

The guard answers before authentication, the auth exclude list, the
authorization backends (IP / host / User-Agent) and any ABAC/PBAC policy run.
Consequences:

- a policy that ALLOWs everything, a `/*` entry in the exclude list or an
  authorization backend that grants the request cannot open these paths;
- with ABAC/PBAC disabled (no `PDP`) the paths are still closed, as long as
  `AuthHandler` is set up;
- the built-in rules cannot be turned off.

The answer is a plain `404 Not Found`, the same as an unknown route, so a
scanner cannot tell a blocked file from a missing one.

### Built-in rules

Paths are compared lower-cased, after URL decoding (`/%2eenv` is `/.env`).

| Rule | Examples |
|------|----------|
| Any hidden segment (starts with `.`), except `.well-known` | `/.env`, `/.env.local`, `/api/.env`, `/.git/config`, `/.aws/credentials` |
| Any `..` segment | `/static/../.env` |
| `env/`, `etc/`, `logs/` at the root of the URL **or** of a served directory | `/etc/config.ini`, `/logs/app.log`, `/files/etc/passwd` (static mounted on `/files`), `/service/env/vars` (sub-application) |
| Config, secret, log, backup and source files | `*.env`, `*.ini`, `*.cfg`, `*.conf`, `*.toml`, `*.yaml`, `*.yml`, `*.log`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.sql`, `*.sqlite`, `*.sqlite3`, `*.db`, `*.bak`, `*.old`, `*.orig`, `*.swp`, `*.py`, `*.pyc`, `*.pyo` |
| Secret files without extension, on file-serving routes only | `credentials`, `passwd`, `shadow`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` |

Compression, archive and rotation suffixes are looked through: `dump.sql.gz`,
`config.ini.tar` and `error.log.1` are blocked.

A "served directory" is the `filename` of a static route, or any route
parameter that holds a multi-segment path (`{filepath:.*}`). The extensionless
names are only checked there, so REST routes such as
`/api/v1/users/credentials` keep working; the same goes for `/api/v1/logs` or
`/api/v1/env`, which are not at the root.

`/.well-known/*` stays open because it carries the OAuth/OpenID metadata and
JWKS navigator-auth itself serves (RFC 8615). The other rules still apply below
it: `/.well-known/.secret` or `/.well-known/x.conf` are blocked.

The rules apply to every route, files or not and authenticated or not: an API
route ending in `.log` or `.sql` would also get a 404. None of the known
consumer applications has such a route.

### Adding paths

`AUTH_DENY_PATHS` adds fnmatch patterns (comma-separated, case-insensitive),
matched against the whole path. It cannot remove built-in rules.

```ini
# env/.env
AUTH_DENY_PATHS=/private/*,*.json.bak,/backup*
```

Every blocked request is logged at INFO on the `navigator_auth.security`
logger:

```
Security: blocked GET '/.env' from 203.0.113.7 (hidden file or directory)
```

## 2. Repeated rejected requests from one host

The same middleware sees every request on the way out. A request that ends
**unauthenticated** with a 4xx answer counts against its client IP: a path
blocked by the guard, a missing or bad token rejected by authentication
(401), an unknown route (404), a handler or policy refusal (403...). When one
host reaches the threshold inside the window, a single WARNING is logged:

```
Security: host 203.0.113.7 made 20 unauthenticated requests rejected within 3s
(20 in total, last status 404); possible scan or attack. Recent paths:
['/.env', '/owa/auth/logon.aspx', '/api/v1/pods', '/RDWeb', '/version']
```

The same host is not reported again until the cooldown has passed. Successful
answers and authenticated requests are never counted, so a browser loading a
page's assets does not trigger it. This works with or without ABAC.

Counters live in memory, per worker process: with several workers, each one
counts its own share of the traffic. The client IP honours
`ALLOWED_IP_TRUSTED_PROXIES`: behind a proxy or ingress, list its address
there, otherwise every request counts against the proxy's IP. Forwarding
headers sent by an untrusted peer are ignored.

| Setting | Default | Meaning |
|---------|---------|---------|
| `AUTH_PROBE_THRESHOLD` | `20` | Rejected requests that trigger the warning (`0` disables it) |
| `AUTH_PROBE_WINDOW` | `60` | Sliding window, in seconds |
| `AUTH_PROBE_COOLDOWN` | `300` | Seconds before the same host is reported again |
| `AUTH_PROBE_MAX_HOSTS` | `10000` | Hosts tracked in memory (the least recently seen is dropped) |
| `AUTH_PROBE_IGNORE_IPS` | *(empty)* | Client IPs or CIDR ranges, comma-separated, that are never counted |

### Ignoring load balancer health checks

A load balancer health check hits the server every few seconds, and if its
target answers 401/403/404 the balancer looks like a scanner. The best fix is
a health check path that answers 200; otherwise list the balancer in
`AUTH_PROBE_IGNORE_IPS`. An AWS ALB/NLB sends its health checks from the
private IPs of its nodes, which change over time, so list the **subnets** the
balancer lives in rather than single addresses:

```ini
# env/.env
ALLOWED_IP_TRUSTED_PROXIES=10.0.8.15,10.0.9.22
AUTH_PROBE_IGNORE_IPS=10.0.8.0/24,10.0.9.0/24
```

The list is matched against the **resolved client IP**, the same address the
warning would name. Health checks carry no `X-Forwarded-For`, so they resolve
to the balancer's own IP and are ignored, while the clients the balancer
forwards are still counted under their own IP, as long as the balancer is in
`ALLOWED_IP_TRUSTED_PROXIES`. If it is not, every forwarded request resolves to
the balancer's IP and ignoring that IP turns detection off for all traffic
coming through it.

Keep the ranges tight: anything inside them can probe the server without
being reported. Invalid entries are skipped with a warning that gives their
position, never their value.

## Limits

- The guard covers the application `AuthHandler` / `PDP` are set up on and its
  sub-applications. Routes on a *parent* application are not covered when
  navigator-auth is set up on a sub-application.
- A middleware added in front of the guard after setup runs first, but it can
  only reach a handler through the guard.
- It is a safety net, not a substitute for a clean deployment: secrets should
  never live inside a directory served by a static route.
