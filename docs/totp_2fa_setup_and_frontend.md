# 2FA con TOTP: configuración y frontend

Guía práctica para activar el segundo factor TOTP (compatible con Google
Authenticator, Authy, 1Password…) en navigator-auth y para implementarlo en el
cliente: la página de **profile** (alta, baja, códigos de respaldo) y el **login**
con reto MFA.

Referencia completa del backend: `docs/two_factor_auth.rst` (FEAT-106).
Código: `navigator_auth/handlers/mfa.py`.

## Parte 1 — Configuración en el servidor

### 1.1 Activar MFA

```bash
AUTH_BASIC_2FA_ENABLED=True
AUTH_OTP_SECRET=<clave de alta entropía>   # obligatoria; no hay fallback a SECRET_KEY
AUTH_TOTP_ISSUER="Mi Empresa"              # nombre que verá el usuario en su app
```

Generar una clave: `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Opcionales relevantes:

| Setting                       | Por defecto | Uso |
|-------------------------------|-------------|-----|
| `AUTH_OTP_CHALLENGE_TTL`      | `300`       | Vida del reto de login (s) |
| `AUTH_OTP_MAX_ATTEMPTS`       | `5`         | Intentos por reto; el quinto fallo lo quema |
| `AUTH_OTP_RATE_USER` / `_IP`  | `10/hour`, `30/hour` | Límites estrictos; si Redis falla, rechazan |
| `AUTH_MFA_BACKUP_CODE_COUNT`  | `10`        | Códigos de respaldo por juego |
| `AUTH_MFA_BACKUP_CODE_LENGTH` | `8`         | Caracteres por código |
| `AUTH_MFA_NOTIFY_CALLBACK`    | sin definir | Aviso de seguridad (baja de TOTP, etc.) |
| `AUTH_OTP_EMAIL_CALLBACK`     | sin definir | Envío del OTP por correo (factor de respaldo "email") |

### 1.2 Requisitos de infraestructura

- **Redis ≥ 6.2** (usa `GETDEL`).
- Tablas MFA creadas por las migraciones del paquete (incluida `002_mfa_secrets.sql`)
  y las tablas `auth.vw_users` y `auth.organization_users`.
- Si MFA está activo y algo falta (tablas, Redis, `AUTH_OTP_SECRET`), **todo login
  BasicAuth falla cerrado** con `503 mfa_unavailable`. El arranque no falla.

### 1.3 Política por tenant

La obligatoriedad se define por organización en `auth.tenant_mfa_policy`:

| `mode`      | Efecto |
|-------------|--------|
| `off`       | Sin reto de login. El usuario puede inscribir TOTP, pero no se le exige. |
| `optional`  | Igual que `off` para el login: solo se pide el factor si el usuario ya tiene TOTP. |
| `enforced`  | Todo usuario debe pasar un segundo factor. Sin TOTP, el mínimo es un OTP por correo. |

Cambie la política con `navigator_auth.mfa.policy.apply_tenant_policy(...)`, no con
un `UPDATE` directo: así se revocan los dispositivos de confianza y se audita.
Antes de pasar a `enforced` ejecute `python -m scripts.preflight_mfa --org-id N`.

Un superusuario en tenant `enforced` **debe** tener un factor fuerte (TOTP o passkey);
no tiene el respaldo por correo.

### 1.4 Rutas

Las rutas de gestión exigen sesión activa. Solo `challenge` y `verify` son públicas.

| Método y ruta                    | Sesión | Uso |
|----------------------------------|--------|-----|
| `POST /api/v1/login`             | No     | Devuelve el reto MFA si hace falta |
| `POST /auth/mfa/verify`          | No     | Completa el login con el código |
| `POST /auth/mfa/challenge`       | No     | Reenvía el OTP por correo |
| `POST /auth/mfa/totp/enroll`     | Sí     | Inicia el alta (devuelve URI y secreto) |
| `POST /auth/mfa/totp/confirm`    | Sí     | Confirma el alta con un código |
| `DELETE /auth/mfa/totp`          | Sí     | Da de baja el TOTP propio |
| `POST /auth/mfa/backup-codes`    | Sí     | Regenera los códigos de respaldo |
| `DELETE /auth/mfa/{user_id}`     | Sí     | Baja administrativa (requiere `mfa:disenroll`) |

Todas las respuestas llevan `Cache-Control: no-store`. Los errores tienen la forma
`{"error": "<código>", "message": "..."}`.

---

## Parte 2 — Frontend: página de profile

### 2.1 Alta de TOTP

Flujo en dos llamadas más un QR generado en el cliente (navigator-auth no incluye
librería de QR).

**Paso A — `POST /auth/mfa/totp/enroll`**

Requiere sesión y la **contraseña actual** del usuario en el cuerpo.

```json
{"password": "contraseña actual"}
```

Si el usuario ya tiene un factor fuerte (reemplazo de TOTP), añada además una prueba:
`"code"` (TOTP vigente) o `"backup_code"`. Una sesión iniciada con passkey reciente
(menos de `AUTH_OTP_CHALLENGE_TTL`) también sirve. Un OTP por correo o la cookie de
dispositivo de confianza **no** valen.

Respuesta `201`:

```json
{
  "enrollment_token": "<opaco>",
  "uri": "otpauth://totp/Mi%20Empresa:user?secret=...&issuer=Mi%20Empresa",
  "secret_b32": "JBSWY3DPEHPK3PXP",
  "expires_in": 300
}
```

Esta es la única respuesta que contiene el secreto. El registro pendiente dura
5 minutos y no reemplaza al TOTP activo hasta confirmarse.

**Paso B — mostrar QR y pedir un código de prueba**

Renderice `uri` como QR con una librería (por ejemplo `qrcode` de npm) y muestre
`secret_b32` como alternativa manual.

**Paso C — `POST /auth/mfa/totp/confirm`**

```json
{"enrollment_token": "<del paso A>", "code": "123456"}
```

Respuesta `200`:

```json
{"status": "confirmed", "backup_codes": ["ABCD2345", "..."]}
```

`backup_codes` aparece **solo** en la primera confirmación (cuando el usuario no
tenía códigos). Muéstrelos una sola vez, con opción de copiar o descargar, y
obligue al usuario a confirmar que los guardó. No se pueden volver a leer.

Los códigos erróneos gastan el presupuesto de 5 intentos del registro pendiente.
Cuando se agota, hay que repetir desde el paso A.

### 2.2 Código de ejemplo

```javascript
// Helper: sesión por cookie (CSRF) o Bearer; ajuste a su app.
async function mfaApi(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  const token = sessionStorage.getItem("token");
  if (token) headers["Authorization"] = `Bearer ${token}`;
  else headers["X-CSRF-Token"] = csrfToken();   // ver docs/passkey_frontend.md
  const res = await fetch(path, {
    method, headers, credentials: "same-origin",
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// 1) Iniciar alta
async function startTotpEnrollment(password) {
  const r = await mfaApi("POST", "/auth/mfa/totp/enroll", { password });
  if (r.status === 403 && r.data.error === "invalid_credentials")
    throw new Error("Contraseña incorrecta");
  if (r.status === 403 && r.data.error === "strong_factor_proof_required")
    throw new Error("Falta un código TOTP o de respaldo para reemplazar el factor");
  if (r.status === 429) throw new Error("Demasiados intentos, espere");
  if (!r.ok) throw new Error(r.data.error || "No se pudo iniciar el alta");
  return r.data;   // {enrollment_token, uri, secret_b32, expires_in}
}

// 2) Dibujar el QR (ejemplo con la librería "qrcode")
//    import QRCode from "qrcode";
//    await QRCode.toCanvas(canvasEl, enrollment.uri);

// 3) Confirmar
async function confirmTotpEnrollment(enrollmentToken, code) {
  const r = await mfaApi("POST", "/auth/mfa/totp/confirm",
    { enrollment_token: enrollmentToken, code });
  if (!r.ok) throw new Error(r.data.error || "Código inválido");
  return r.data;   // {status: "confirmed", backup_codes?: [...]}
}
```

Interfaz sugerida: un asistente de tres pantallas (contraseña → QR + código →
códigos de respaldo). Si `expires_in` vence (300 s), vuelva a la primera pantalla.

### 2.3 Baja de TOTP

`DELETE /auth/mfa/totp` con contraseña y una prueba (`code` o `backup_code`):

```json
{"password": "...", "code": "123456"}
```

Respuesta `200 {"status": "disenrolled"}`.

Un superusuario en tenant `enforced` recibe `409 strong_factor_required` y no puede
quitar su último factor fuerte; muestre un mensaje explicando que antes necesita
registrar un passkey.

Tras la baja se invalidan los dispositivos de confianza y los códigos de respaldo
sin usar, y se envía el aviso de `AUTH_MFA_NOTIFY_CALLBACK`.

### 2.4 Regenerar los códigos de respaldo

`POST /auth/mfa/backup-codes` solo para usuarios con factor fuerte. Requiere la
contraseña **y** una prueba reciente de factor fuerte (`code` TOTP, `backup_code`
sin usar, o sesión con passkey reciente):

```json
{"password": "...", "code": "123456"}
```

Respuesta `201`: `{"backup_codes": [...], "count": 10}`. Sin la prueba responde
`403 strong_factor_proof_required`. Muéstrelos una sola vez.

### 2.5 Estado del usuario en la página de profile

No hay un endpoint `GET` dedicado que diga "TOTP activo". Opciones:

- Guardar el estado en su propio endpoint de profile usando la información que ya
  tenga su aplicación.
- Añadir un endpoint de estado en el backend (hoy no existe).
- Usar el resultado del último intento como señal: `enroll` con `code` requerido
  devuelve `strong_factor_proof_required` cuando ya hay un factor fuerte.

Dependiendo de su caso, conviene el segundo punto: un `GET /auth/mfa/status` que
devuelva `{totp: bool, backup_codes_remaining: int}` evita adivinar en el cliente.

---

## Parte 3 — Frontend: login con TOTP

### 3.1 Flujo

```
POST /api/v1/login {username, password}
   ├─ 200  → sesión abierta (MFA no exigido para este usuario)
   ├─ 401 + {"mfa_required": true, ...}  → pedir el segundo factor
   └─ 403 / 503 → refusal (ver tabla de errores)

POST /auth/mfa/verify {challenge, provider, code, remember_device?}
   └─ 200 → misma respuesta que un login normal (token, refresh, etc.)
```

La respuesta de reto es un `401` (no un `200`) y no incluye sesión ni token:

```json
{
  "mfa_required": true,
  "challenge": "<reto opaco>",
  "providers": ["totp", "backup"],
  "preferred": "totp",
  "expires_in": 300
}
```

- `providers` indica qué opciones ofrece el servidor: `totp`, `backup` o `email`.
  Un usuario con TOTP confirmado ve TOTP en lugar de email.
- `provider` en `verify` debe ser uno de los listados.

### 3.2 Código de ejemplo

```javascript
async function login(username, password) {
  const res = await fetch("/api/v1/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json().catch(() => ({}));

  if (res.status === 401 && data.mfa_required) {
    return { mfaRequired: true, ...data };   // {challenge, providers, preferred, expires_in}
  }
  if (!res.ok) throw Object.assign(new Error(data.error || "Login fallido"),
                                   { status: res.status, code: data.error });
  return { mfaRequired: false, session: data };
}

async function verifyMfa({ challenge, provider, code, rememberDevice, deviceLabel }) {
  const res = await fetch("/auth/mfa/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",     // necesario para la cookie nav_mfa_device
    body: JSON.stringify({
      challenge, provider, code,
      remember_device: !!rememberDevice,
      device_label: deviceLabel || "",
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || "Código inválido"),
                                   { status: res.status, code: data.error });
  return data;   // igual que un login normal: token, refresh_token, ...
}

// Uso
const step1 = await login(user, pass);
if (step1.mfaRequired) {
  const code = await askUserForCode(step1.providers, step1.preferred);
  const session = await verifyMfa({
    challenge: step1.challenge,
    provider: step1.preferred,          // "totp" (o "backup" si usa un código de respaldo)
    code,
    rememberDevice: true,
  });
}
```

### 3.3 Pantalla de verificación

- Campo numérico de 6 dígitos para `totp` (`inputmode="numeric"`,
  `autocomplete="one-time-code"`), y otro campo para el código de respaldo
  (8 caracteres) cuando el usuario elige "Usar un código de respaldo"
  (`provider: "backup"`).
- Checkbox "Recordar este dispositivo". Solo aparece útil si el tenant tiene
  `remember_days > 0` y solo se ofrece tras un factor fuerte. Omite el OTP en logins
  futuros, nunca la contraseña. Se guarda en la cookie `nav_mfa_device`
  (`HttpOnly`, `Secure`, `SameSite=Lax`), por eso el `fetch` necesita
  `credentials: "same-origin"`.
- Si `providers` incluye `email`, ofrezca "Reenviar código" que llame a
  `POST /auth/mfa/challenge {challenge}` (responde `202 {"status": "accepted",
  "expires_in": ...}`).
- Muestre una cuenta atrás con `expires_in`; al agotarse, vuelva al formulario de login.

### 3.4 Errores

| Respuesta | Significado | Qué hacer en la UI |
|-----------|-------------|--------------------|
| `401 invalid_challenge` | Reto inexistente, vencido o quemado | Volver al login |
| `401` en `verify` | Código incorrecto (intentos 1–4 conservan el reto) | Permitir reintento; tras el 5.º fallo el reto se quema |
| `429 rate_limited` | Límite por usuario o IP | Pedir esperar |
| `403 strong_factor_required` | Superusuario en tenant `enforced` sin TOTP ni passkey | Indicar que use passkey o contacte a un administrador |
| `403 no_factor_available` | Sin factor usable (sin correo válido, o solo passkey sin códigos de respaldo) | Sugerir iniciar con passkey |
| `503 mfa_unavailable` | MFA no disponible (Redis, BD, configuración) | Mensaje de servicio no disponible; no hay login posible |

Tras un `verify` exitoso, la sesión queda con `mfa=true` y `amr` con `pwd` y
`totp` (o `backup`). Con un dispositivo recordado queda `["pwd", "trusted_device"]`,
que una política ABAC puede rechazar si exige un factor fresco.

### 3.4.1 Login por OAuth2

Si su flujo usa el formulario OAuth2 (`POST /oauth2/login`), el servidor renderiza
`oauth/mfa.html` y el usuario envía el factor a `POST /oauth2/login/mfa`, que redirige
a `/oauth2/authorize` conservando PKCE, `state`, `nonce`, `scope` y `prompt`. Si usa
su propia pantalla en lugar de esa plantilla, siga el contrato de esa ruta en lugar
del de `/auth/mfa/verify`.

---

## Notas de seguridad para el frontend

- Nunca guarde ni registre en logs `secret_b32`, `uri`, `enrollment_token`, `challenge`,
  códigos TOTP ni códigos de respaldo.
- Pida la contraseña de nuevo en cada operación de gestión: el servidor la exige aunque
  la sesión esté activa.
- Los códigos de respaldo se muestran una vez; ofrezca descarga o copia y una
  confirmación explícita.
- Cambiar contraseña, completar una recuperación, alta o baja de TOTP y borrar el último
  passkey invalidan los dispositivos de confianza: informe al usuario de que tendrá que
  pasar de nuevo el segundo factor.
- Un reloj del dispositivo desajustado es la causa más común de códigos TOTP rechazados;
  indíquelo en el mensaje de error.
