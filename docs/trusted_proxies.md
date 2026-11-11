# Trusted proxies and probe exclusions

When navigator-auth runs behind a load balancer, a reverse proxy or a tunnel,
two settings decide which IP address a request is attributed to and which
addresses the security warnings leave alone:

| Setting | Accepts | Where to set it | Used by |
|---------|---------|-----------------|---------|
| `ALLOWED_IP_TRUSTED_PROXIES` | Exact IPs only (no CIDR) | `env/.env`, or the `[auth]` section of `etc/navigator.ini` (the INI value wins) | IP allowlist and PowerBI authorization, User-Agent geo-fence, OAuth2 client-registration rate limit, repeated-probe warning |
| `AUTH_PROBE_IGNORE_IPS` | IPs and CIDR ranges, IPv4 or IPv6 | `env/.env` (environment) only, not the INI file | Repeated-probe warning only |

Both are comma-separated lists; spaces around entries are fine. An invalid
entry is skipped with a startup warning that gives its position in the list,
never its value. Both are read once at startup: restart the workers after
changing them.

## `ALLOWED_IP_TRUSTED_PROXIES`

Behind a proxy, the TCP peer of every request is the proxy, not the client.
Without this setting every client looks like the proxy: the IP allowlist
checks the proxy's address, the OAuth2 registration rate limit puts all
clients in one bucket, and the repeated-probe warning names the proxy.

List the proxies you run. navigator-auth then trusts the forwarding headers
they send, and only theirs.

### How the client IP is resolved

1. **The peer is not listed**: the peer is the client. `X-Forwarded-For` and
   `CF-Connecting-IP` are ignored, because any client can send them.
2. **The peer is listed and sends `X-Forwarded-For`**: the chain is read from
   right to left, skipping listed addresses. The first address that is not
   listed is the client. A well-behaved proxy appends the address it saw on
   the right, so a value a client injects stays on the left and is never
   reached. A malformed entry stops the walk, and the peer is used.
3. **The peer is listed and sends no `X-Forwarded-For`**: a valid
   `CF-Connecting-IP` header is used if present; otherwise the peer is the
   client. This is what happens with a load balancer's own health checks.
4. **Every address in the chain is listed**: `CF-Connecting-IP` if present;
   otherwise no client IP can be resolved, and the probe warning counts the
   peer.

| Peer | `X-Forwarded-For` | Resolved client IP |
|------|-------------------|--------------------|
| `203.0.113.7` (not listed) | `10.0.0.9` | `203.0.113.7` (header ignored) |
| `10.0.8.15` (listed) | `198.51.100.4` | `198.51.100.4` |
| `10.0.8.15` (listed) | `10.0.0.9, 198.51.100.4` | `198.51.100.4` (spoofed left value ignored) |
| `10.0.8.15` (listed) | none | `10.0.8.15` |

### Configure it

```ini
# env/.env
ALLOWED_IP_TRUSTED_PROXIES=10.0.8.15,10.0.8.47,10.0.9.22
```

or, in `etc/navigator.ini`:

```ini
[auth]
ALLOWED_IP_TRUSTED_PROXIES: 10.0.8.15,10.0.8.47,10.0.9.22
```

Rules:

- **Exact addresses only.** A range such as `10.0.8.0/24` is rejected with a
  warning.
- **List every hop you control.** With `ALB → nginx on the same host →
  aiohttp`, the peer is `127.0.0.1` and nginx appends the ALB's address to
  `X-Forwarded-For`; list both `127.0.0.1` and the ALB node IPs.
- **Cloudflare tunnel**: list the address `cloudflared` connects from
  (usually `127.0.0.1`); `CF-Connecting-IP` then gives the visitor's IP.
- **Never list an address clients can reach the server from directly.**
  Anything listed can claim to be any client by setting `X-Forwarded-For`.

### AWS Application Load Balancer

An ALB connects to the server from the private IPs of its nodes, one or more
per subnet. Those IPs change when the ALB scales or AWS replaces a node.
List them with:

```bash
aws ec2 describe-network-interfaces \
  --filters "Name=description,Values=ELB app/<lb-name>/<lb-id>" \
  --query 'NetworkInterfaces[].PrivateIpAddress' --output text
```

`app/<lb-name>/<lb-id>` is the end of the load balancer's ARN
(`arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/app/<lb-name>/<lb-id>`).

Because only exact addresses are accepted, refresh the list after the ALB
changes, for example from the deploy script. Traffic through a node that is
missing from the list resolves to the node's own IP. The symptom is a log
line or warning that names an address from the ALB's subnets instead of a
real client.

A Network Load Balancer works at TCP level and adds no `X-Forwarded-For`.
With client IP preservation on (the default for instance targets), the server
sees the real client as the peer, so the NLB does not go in this list. With
it off, every request appears to come from the NLB.

## `AUTH_PROBE_IGNORE_IPS`

`protected_paths_middleware` logs a security warning when one client IP gets
many unauthenticated requests rejected with a 4xx in a short time (see
`documentation/protected-paths.md`). A load balancer health check that hits a
route answering 401, 403 or 404 every few seconds looks exactly like that,
and triggers the warning again after every cooldown period.

`AUTH_PROBE_IGNORE_IPS` lists the hosts that are never counted. It only
silences that warning: it grants no access, and does not change
authorization, rate limits, or the 404 answer to protected system paths,
which are still blocked and logged.

**First choice: point the health check at a path that answers 200** without
authentication. Successful answers are never counted, so nothing needs to be
ignored. Use this setting when the health check path cannot change.

### Configure it

```ini
# env/.env  (not read from etc/navigator.ini)
AUTH_PROBE_IGNORE_IPS=10.0.8.0/24,10.0.9.0/24
```

Entries can be single addresses (`10.0.8.15`), IPv4 or IPv6 ranges
(`10.0.8.0/24`, `2001:db8::/32`). An IPv4 client reported in IPv6 form by a
dual-stack socket (`::ffff:10.0.8.15`) matches the IPv4 range.

The list is matched against the **resolved client IP** described above, not
against the TCP peer. Health checks carry no `X-Forwarded-For`, so they
resolve to the load balancer's own IP and are ignored, while the clients it
forwards are counted under their own IP.

### AWS load balancers

An ALB or NLB sends its health checks from its node IPs, which change, so
list the load balancer's **subnets** rather than single addresses:

```bash
aws elbv2 describe-load-balancers --names <lb-name> \
  --query 'LoadBalancers[0].AvailabilityZones[].SubnetId' --output text

aws ec2 describe-subnets --subnet-ids <subnet-id> <subnet-id> \
  --query 'Subnets[].CidrBlock' --output text
```

Every host in those subnets is ignored, not only the load balancer. Small
subnets dedicated to the load balancer keep that set tight.

## Using both together

A typical ALB setup:

```ini
# env/.env
ALLOWED_IP_TRUSTED_PROXIES=10.0.8.15,10.0.8.47,10.0.9.22
AUTH_PROBE_IGNORE_IPS=10.0.8.0/24,10.0.9.0/24
```

| Request | Peer | `X-Forwarded-For` | Resolved client | Counted by the probe warning |
|---------|------|-------------------|-----------------|------------------------------|
| ALB health check | `10.0.8.15` | none | `10.0.8.15` | No, inside `10.0.8.0/24` |
| Client through the ALB | `10.0.8.15` | `198.51.100.4` | `198.51.100.4` | Yes |
| Client through an ALB node missing from the trusted list | `10.0.8.99` | `198.51.100.4` | `10.0.8.99` | **No: blind spot** |

Pitfalls:

- **The load balancer is not in `ALLOWED_IP_TRUSTED_PROXIES` but its subnets
  are ignored.** Every request through it resolves to the load balancer's IP,
  so detection is off for all of that traffic. Set both, or neither.
- **The trusted list is stale.** Traffic through the new nodes resolves to
  their own IPs, inside the ignored subnets, and goes unreported (last row
  above). The IP allowlist and the OAuth2 rate limit see the node IP too.
- **The ignored ranges are too wide.** Ignoring the whole VPC
  (`10.0.0.0/16`) lets any compromised host inside it scan the server
  unnoticed.

## Checking the configuration

- Look for these warnings at startup:

  ```
  authz: ignoring invalid trusted proxy IP at position 3 of ALLOWED_IP_TRUSTED_PROXIES
  ignoring invalid IP or CIDR range at position 2 of AUTH_PROBE_IGNORE_IPS
  ```

- Print what the server will use:

  ```bash
  source .venv/bin/activate
  python -c "from navigator_auth.middlewares import probes; \
  print(probes.trusted_proxies); print(probes.probe_tracker.ignored)"
  ```

- With `AUTHZ_DEBUG=true` and logging at DEBUG level, the IP authorization
  backends (`authz_allowed_ips`, `authz_powerbi`) log the peer,
  `X-Forwarded-For`, `CF-Connecting-IP` and the resolved client IP of each
  request they check.
- The probe warning names the resolved IP. If it names an address from the
  load balancer's subnets while real clients are behind it, the trusted list
  is incomplete.
