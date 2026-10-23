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
policies that govern the **admin path** of the generic model CRUD surfaces. It
is a pack an operator copies into `POLICY_STORAGE_DIR`; nothing loads it
automatically.

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

