# Policy-Based Access Control

Completar el desarrollo de la lógica ABAC/PBAC de navigator-auth (https://www.nextlabs.com/products/cloudaz-policy-platform/what-is-policy-based-access-control-pbac/, https://www.researchgate.net/publication/359386645_Policy-Based_Access_Controls) con los siguientes cambios estructurales:
- migrar `class Environment` de datamodel Model a fast pydantic BaseModel, garantizando los default factory pero cubriendo mas variables del environment como segmento del dia (mañana, tarde, noche), horas laborales (leyendo de una configuracion -en navigator_auth.conf- que permita definir hora de inicio y cierre)
- Permitir el parser de policies basadas en YAML (actualmente se definen via JSON) o via código Policy:
```
policy = Policy(
    'only_for_jesus',
    effect=PolicyEffect.ALLOW,
    description="This resource will be used only for Jesus between 9 at 24 monday to saturday",
    subject=['jlara@trocglobal.com'],
    resource=["urn:uri:/private/"],
    environment={
        "hour": list(chain(range(9, 24), range(1))),
        "day_of_week": range(1, 6)
    }
)
pdp.add_policy(policy)
```
- crear un policy storage basado en YAML (usando yaml-rs) buscando un archivo en POLICY_STORAGE_DIR que por defecto sería BASE_DIR / env / policies
- verificar que los decoradores (navigator_auth/abac/decorators.py) soportan class-based views y metodos (evaluar el codigo de los decoradores en navigator_auth/decorators.py que ya soportan ambos modos)
- Aprovechar que estamos integrando Rust, para crear al ABAC/PBAC un modulo para el PEP que permita entregar una lista de archivos y "filtrarlos" eficientemente en base a las reglas de protección del ABAC/PBAC
- Tambien un modulo para la evaluación rápida de recursos (resources) posiblemente usando cython o Rust
- Dejar definidas una serie de ready-to-use Policies para un faster deployment del ABAC/PBAC

¿qué buscamos?, ya por fin implementar ABAC/PBAC para permitir filtrado granular de servicios, tanto a nivel de backend (definir qué tools, MCP services definitions, que agentes o bots tiene acceso el usuario) como a nivel de frontend (que un API Rest permita enviar el usuario y un servicio y se tome la decisión si el usuario en las condiciones PBAC actuales tiene o no acceso al recurso).

---

## Auth-model policy pack (FEAT-105)

*(English addendum; the notes above are the original planning brief and are
unchanged.)*

`navigator_auth/abac/default_policies/auth_model_admin_access.yaml` ships three
policies that govern the **admin path** of the generic model CRUD surfaces.
Nothing loads it automatically; see "Loading the admin policy packs" below.

| Policy | Resource | Actions | Subjects |
|---|---|---|---|
| `user_identities_admin_access` | `uri:/api/v1/user_identity*` | `identity:read`, `identity:revoke`, `identity:delete` | group `superuser` |
| `user_accounts_admin_access` | `uri:/api/v1/user_accounts*` | `account:read`, `account:delete` | group `superuser` |
| `partner_keys_admin_access` | `uri:/api/v1/partner/tokens*` | `partner:read`, `partner:create`, `partner:revoke`, `partner:delete` | group `superuser` |

All three are `allow`, `enforcing`, priority 90 (below `admin_full_access`).

**A missing policy removes access, it never grants it.** The handlers call
`navigator_auth.decorators.policy_allows(policy, request, action=...)`, which
fails closed: no PDP on the application, an undeclared policy name or a policy
that raises while evaluating all yield a denial (with a reason, recorded in
the `AuditLog`). Consequences:

- identities / accounts: owners keep working with no policy (ownership is code,
  not policy); only the cross-user superuser path needs the pack;
- partner keys: with no pack nobody can use the surface, superusers included.

The handler also enforces its own action envelope (`superuser_actions`): an
action outside it is refused even if a policy would allow it, so a widened
policy file cannot widen a handler.

`policy_allows(policy, request, action=None, resource=None, resource_type=None,
require_all=False) -> (allowed, reason, response)` is public and usable by any
handler whose decision depends on request-time data (such as a row's owner).


## Loading the admin policy packs

The built-in admin handlers depend on three packs from
`navigator_auth/abac/default_policies/`. None of them is loaded automatically:
load the ones you need through the PDP's storage — the policy table of the DB
storage, or YAML files read by a `YAMLStorage` the application passes in:

```python
from navigator_auth.conf import POLICY_STORAGE_DIR
from navigator_auth.abac.storages.yaml_storage import YAMLStorage

pdp = PDP(storage=storage, yaml_storage=YAMLStorage(directory=POLICY_STORAGE_DIR))
```

| Pack | Policies | Routes |
|---|---|---|
| `auth_crud_admin_access.yaml` | `users_admin_access`, `groups_admin_access`, `user_groups_admin_access`, `group_permissions_admin_access`, `permissions_admin_access`, `users_grant_role` | `/api/v1/users`, `/api/v1/users/{id}/role`, `/api/v1/groups`, `/api/v1/user_groups`, `/api/v1/usergroups`, `/api/v1/group_permissions`, `/api/v1/permissions` |
| `auth_model_admin_access.yaml` | `user_identities_admin_access`, `user_accounts_admin_access`, `partner_keys_admin_access` | `/api/v1/user_identity`, `/api/v1/user_accounts`, `/api/v1/partner/tokens` |
| `mfa_admin_access.yaml` | `mfa_admin_access` | `DELETE /auth/mfa/{user_id}` (only with `AUTH_BASIC_2FA_ENABLED`) |

- **`POLICY_STORAGE_DIR` is only a setting.** It names a directory (default
  `BASE_DIR/env/policies`); nothing reads it unless the application passes a
  `YAMLStorage` over it, as above. Copying a pack there is not enough on its
  own.
- **A pre-loaded evaluator skips storage.** When the `PolicyEvaluator` given to
  the PDP already holds policies loaded elsewhere (e.g. through
  `PolicyLoader`), `PDP.on_startup` reads neither the DB nor the YAML storage;
  load the packs through that same path instead.
- **Policy names must be unique across sources.** The decorators look a policy
  up by name and get only the last one loaded with that name (YAML loads after
  the DB). A YAML `allow` sharing its name with a DB `deny` replaces the deny in
  `policy_allows` / `check_access`.
- **Missing policies are reported at startup.** `setup_handlers()` declares the
  policy each admin route evaluates
  (`navigator_auth.abac.required_policies.require_policy`), and
  `PDP.on_startup` logs one WARNING per declared policy that is not loaded,
  naming the routes that need it.
- **A missing policy denies, it never errors.** Those requests answer 403 (or
  404 where a row probe must not be confirmed). From 0.26.0 to 0.29.2 a
  missing policy answered 500 instead (`'method' object is not iterable` in
  the decorators' policy lookup).
- `users_grant_role` is held by `security_admin`, not `superuser`: with the
  pack loaded a plain superuser is still refused role changes and changes to
  protected groups, by design.


## Unauthenticated requests and system paths

`abac_middleware` does **not** block unauthenticated requests: it logs
`Access to <path> is not Authenticated.` and hands the request to the handler,
which decides (a protected view raises 401, a static route answers 404 for a
missing file). System paths (`/.env`, `/etc/`, `/logs/`, key and config
files...) never get that far: `protected_paths_middleware` refuses them first,
whatever the policies say, and logs one warning per host that keeps probing.
See [protected-paths.md](protected-paths.md).
