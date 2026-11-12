# Password Recovery Endpoints (BasicAuth backend)

Resumen de los endpoints del flujo de recuperación de contraseña de tres pasos,
firmado con HMAC (FEAT-098). Referencia completa: `docs/password_recovery.rst`
y `sdd/specs/backend-based-password-recovery.spec.md`.

navigator-auth **no envía correos**: el paso 1 entrega un payload listo para
enviar a un callback configurado y la respuesta HTTP nunca incluye el token.

## Endpoints

| Verbo  | Ruta                                  | Paso | Propósito                                          |
|--------|---------------------------------------|------|----------------------------------------------------|
| `POST` | `/api/v1/password-recovery`           | 1    | Solicitar el enlace de recuperación                |
| `GET`  | `/api/v1/password-recovery/{token}`   | 2    | Validar el enlace y obtener un token de confirmación |
| `POST` | `/api/v1/password-recovery/confirm`   | 3    | Fijar la nueva contraseña                          |

Alias legacy (mismo handler):

- `POST /api/v1/forgot-password` → paso 1
- `POST /api/v1/reset-password` → paso 3

## Paso 1 — Solicitud

```http
POST /api/v1/password-recovery
Content-Type: application/json

{"email": "user@example.com"}
```

Siempre responde `200` con el mismo cuerpo, exista o no el correo, haya o no
rate-limit, y falle o no el callback:

```json
{"message": "If that email address is registered, recovery instructions have been sent."}
```

- El token nunca aparece en la respuesta, en Redis (se guarda `sha256(token)`) ni en logs.
- El tiempo de respuesta se rellena a ~250 ms para que la latencia no revele si la cuenta existe.
- El rechazo por rate-limit devuelve el mismo `200` genérico (un `429` revelaría que se rastrea la dirección o IP).

## Paso 2 — Validación

```http
GET /api/v1/password-recovery/{token}
```

`200`:

```json
{"token": "<confirmation token>", "expires_in": 900, "username": "user"}
```

`400`: enlace ausente, expirado o con firma inválida (mensaje genérico, sin
distinguir la causa).

Es idempotente: cada llamada rota un token de confirmación nuevo, pero el token
del paso 1 **no se consume**, así que un refresh o el prefetch de un escáner de
correo no quema el reset.

## Paso 3 — Confirmación

```http
POST /api/v1/password-recovery/confirm
Content-Type: application/json

{"password": "...", "confirm_password": "...", "token": "<confirmation token>"}
```

`202`:

```json
{"action": "Password was changed successfully", "status": "OK"}
```

No hay auto-login: la respuesta no incluye token de sesión ni refresh.

Errores:

- `400` — las contraseñas no coinciden, o el token de confirmación falta, es inválido, expiró o ya se usó.
- `422` — la contraseña incumple la política configurada:

  ```json
  {"violations": [{"rule": "min_length", "message": "..."}]}
  ```

  Un `422` **no** consume ningún token: se puede reintentar con el mismo token de confirmación.

Un paso 3 exitoso:

- Escribe el nuevo hash (mismo hasher del login Basic).
- Pone `is_new = False` (un reset de superusuario lo pone en `True`).
- Borra los registros Redis de los pasos 1 y 2 (no hay replay).
- Revoca la sesión Redis del usuario y todos los `jti` JWT vigentes.

## Callback de notificación

Configure `AUTH_RECOVERY_CALLBACK` con la ruta punteada a un callable (sync o
async) que reciba un único argumento posicional, `NotificationPayload`:

```python
@dataclass(frozen=True)
class NotificationPayload:
    email: str            # dirección solicitada
    display_name: str     # "" si found=False
    username: str         # "" si found=False
    token: str            # token crudo del paso 1; no aparece en ningún otro sitio
    url: str              # AUTH_RECOVERY_URL_TEMPLATE.format(token=token)
    expires_at: datetime
    found: bool           # False => sin cuenta coincidente
```

- `found=False`: no hubo cuenta (o la coincidencia fue ambigua); `token` y `url` van vacíos. El callback decide si envía algo o calla.
- Un callback que lanza excepción se captura y se registra; la respuesta HTTP sigue siendo el `200` genérico.
- Si `AUTH_RECOVERY_URL_TEMPLATE` falta o es inválido, se registra el error y `url` queda vacío.
- `NotificationPayload.__repr__` oculta `token` y `url`.

## Búsqueda de usuario

- Busca por `email` y luego por `alt_email`.
- `User.email` no es único: si coinciden varios usuarios activos, no adivina, registra un warning y sigue la ruta `found=False`.
- Cualquier usuario activo puede recuperar, incluidas cuentas federadas sin contraseña local.

## Migración desde `FORGOT_PASSWORD_CALLBACK`

`FORGOT_PASSWORD_CALLBACK` (el antiguo `handlers/recovery.py`) está deprecado
por un release. Si está definido y `AUTH_RECOVERY_CALLBACK` no, se usa como
fallback con un `DeprecationWarning`. El payload nuevo (`NotificationPayload`)
reemplaza la firma antigua `(request, user, token)`, así que hay que actualizar
el callback al migrar.

## Configuración

Todas las claves `AUTH_RECOVERY_*` y sus valores por defecto están en `docs/settings.rst`.
