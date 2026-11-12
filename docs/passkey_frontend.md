# Passkeys: guía de implementación en el frontend

Cómo integrar el backend `PasskeyAuth` (WebAuthn / FIDO2) desde un cliente web.
La configuración del servidor, los relying parties y el modelo de seguridad están
en `docs/passkey.rst`; aquí solo se cubre lo que hace el navegador.

Ejemplo ejecutable: `examples/passkey_server.py` y `examples/static/passkey_app.html`.

## Requisitos

- Contexto seguro: `https://`, o `http://localhost` en desarrollo.
- El `Origin` de la página debe estar en `PASSKEY_RELYING_PARTIES` del servidor
  (coincidencia exacta de esquema, host y puerto). Si no, todo el flujo falla.
- Si hay un proxy o balanceador delante, debe reenviar el header `Origin` del
  navegador sin cambios.
- Un navegador actual con los helpers JSON de WebAuthn:
  `PublicKeyCredential.parseCreationOptionsFromJSON`,
  `parseRequestOptionsFromJSON` y `credential.toJSON()` (Chrome, Safari y Firefox recientes).

Detección de soporte:

```javascript
const supported = !!(window.PublicKeyCredential
  && PublicKeyCredential.parseCreationOptionsFromJSON
  && PublicKeyCredential.parseRequestOptionsFromJSON);
```

## Endpoints que usa el cliente

| Método y ruta                                          | Auth            | Uso                                           |
|--------------------------------------------------------|-----------------|-----------------------------------------------|
| `POST /api/v1/auth/passkey/register/options`           | Sesión + CSRF   | Inicia el alta; devuelve las opciones WebAuthn |
| `POST /api/v1/auth/passkey/register/verify`            | Sesión + CSRF   | Envía la attestation; responde `201 {"status": "registered", "id": ...}` |
| `POST /api/v1/auth/passkey/login/options`              | Pública         | Devuelve `{challenge_id, publicKey}`          |
| `POST /api/v1/login` + `X-Auth-Method: PasskeyAuth`    | Pública         | Cierra el login; mismo cuerpo que el login Basic más `auth_method`, `mfa`, `amr` |
| `GET /api/v1/auth/passkey/credentials`                 | Sesión          | Lista los passkeys del usuario                |
| `PATCH /api/v1/auth/passkey/credentials/{id}`          | Sesión + CSRF   | Renombra (`{"label": "..."}`) → `200 {"status": "renamed"}` |
| `DELETE /api/v1/auth/passkey/credentials/{id}`         | Sesión + CSRF   | Elimina → `204`, o `409` si es el último método de login |

## Autenticación y CSRF en las peticiones

El alta y la gestión requieren una sesión ya iniciada.

- **Sesión por cookie**: el middleware CSRF exige que el header `X-CSRF-Token`
  sea igual a la cookie `csrf_token`. Use `credentials: "same-origin"`.
- **Bearer token**: envíe `Authorization: Bearer <token>`; la verificación CSRF no aplica.

```javascript
function csrfToken() {
  return document.cookie.split("; ")
    .find((c) => c.startsWith("csrf_token="))?.split("=")[1];
}
```

## 1. Registrar un passkey (usuario ya autenticado)

1. `POST register/options` con cuerpo `{}`.
2. Pasar el resultado por `PublicKeyCredential.parseCreationOptionsFromJSON` y llamar a `navigator.credentials.create`.
3. Enviar `credential.toJSON()` (y un `label` opcional) a `register/verify`.

```javascript
async function enrollPasskey(label) {
  const headers = {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken(),        // omitir si se usa Bearer
  };

  const optsRes = await fetch("/api/v1/auth/passkey/register/options", {
    method: "POST", headers, credentials: "same-origin", body: "{}",
  });
  if (!optsRes.ok) throw new Error("No se pudo iniciar el alta");

  let credential;
  try {
    credential = await navigator.credentials.create({
      publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(await optsRes.json()),
    });
  } catch (err) {
    // NotAllowedError: el usuario canceló o venció el tiempo
    // InvalidStateError: este autenticador ya tiene un passkey para la cuenta
    throw err;
  }

  const res = await fetch("/api/v1/auth/passkey/register/verify", {
    method: "POST", headers, credentials: "same-origin",
    body: JSON.stringify({ credential: credential.toJSON(), label }),
  });
  if (res.status !== 201) throw new Error("El servidor rechazó el passkey");
  return res.json();                    // {"status": "registered", "id": ...}
}
```

El reto es de un solo uso y caduca (`PASSKEY_CHALLENGE_TTL`, 300 s por defecto).
Si el usuario tarda más, repita desde `register/options`.

## 2. Iniciar sesión con passkey

El login son dos llamadas: `login/options` y después `POST /api/v1/login` con el
header `X-Auth-Method: PasskeyAuth`.

`login/options` acepta un `username` opcional:

- **Con username** (flujo "usuario primero"): la respuesta lista los passkeys de
  ese usuario. Para un usuario inexistente devuelve ids señuelo, de modo que la
  forma de la respuesta no revela si la cuenta existe.
- **Sin username**: `allowCredentials` va vacío y el autenticador ofrece los
  passkeys que tenga (credenciales descubribles). Es lo que usa la UI condicional.

```javascript
async function passkeySignIn(username, mediation, signal) {
  const startRes = await fetch("/api/v1/auth/passkey/login/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(username ? { username } : {}),
  });
  if (!startRes.ok) throw new Error("No se pudo iniciar el login");
  const started = await startRes.json();      // {challenge_id, publicKey}

  const credential = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(started.publicKey),
    ...(mediation ? { mediation } : {}),
    ...(signal ? { signal } : {}),
  });

  const res = await fetch("/api/v1/login", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Method": "PasskeyAuth",
    },
    body: JSON.stringify({
      challenge_id: started.challenge_id,
      credential: credential.toJSON(),
    }),
  });
  if (!res.ok) throw new Error("Passkey rechazado");   // siempre el mismo 401
  return res.json();      // body de login Basic + auth_method, mfa, amr
}
```

La respuesta es la misma que la del login Basic (incluye `token` y el refresh
token), más:

| Campo         | Valor                                                                 |
|---------------|-----------------------------------------------------------------------|
| `auth_method` | `"passkey"`                                                           |
| `mfa`         | `true` si el autenticador verificó al usuario (biometría o PIN)       |
| `amr`         | `["hwk", "user"]`, o `["hwk"]` sin verificación de usuario            |

### UI condicional (autofill)

Muestra los passkeys en el autocompletado del campo de usuario, sin botón aparte:

```html
<input name="username" autocomplete="username webauthn">
```

```javascript
if (await PublicKeyCredential.isConditionalMediationAvailable?.()) {
  const ctrl = new AbortController();
  passkeySignIn(undefined, "conditional", ctrl.signal)
    .then(onSignedIn)
    .catch(() => {});          // abortado o cancelado: seguir con el formulario normal
  // Si el usuario pulsa otro botón de login: ctrl.abort();
}
```

Aborte la petición condicional pendiente antes de lanzar otra llamada a
`navigator.credentials.get`, o el navegador rechazará la segunda.

## 3. Gestionar passkeys

```javascript
const api = (method, path, body) => fetch(`/api/v1/auth/passkey/credentials${path}`, {
  method,
  credentials: "same-origin",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
  body: body ? JSON.stringify(body) : undefined,
});

const list   = () => api("GET", "").then((r) => r.json());
const rename = (id, label) => api("PATCH", `/${id}`, { label });
const remove = (id) => api("DELETE", `/${id}`);     // 204, o 409 si es el último método
```

- La lista nunca incluye la clave pública, el contador de firmas ni el handle de usuario.
- Un `409` al borrar significa que ese passkey es el único método de acceso del usuario
  (sin contraseña ni identidad externa enlazada). Muestre un mensaje pidiendo configurar otro método antes.
- El borrado en el servidor no elimina el passkey del autenticador del usuario;
  avíselo en la UI.

## Manejo de errores

| Situación                                         | Qué ve el cliente                         | Qué hacer |
|---------------------------------------------------|-------------------------------------------|-----------|
| Usuario cancela o vence el tiempo                 | `NotAllowedError` en `credentials.*`      | Volver al formulario; no es un error del servidor |
| Autenticador ya registrado para la cuenta         | `InvalidStateError` en `create`           | Informar que este dispositivo ya tiene un passkey |
| Cualquier fallo de login (firma, origin, reto caducado o reutilizado, sin verificación de usuario, credencial desconocida) | `401` idéntico | Mostrar un mensaje genérico y reiniciar desde `login/options`. El servidor no distingue la causa a propósito |
| Cuenta deshabilitada                              | `403`                                     | Informar que la cuenta está inactiva |
| Origin no incluido en los relying parties         | Falla `register/options` o `login/options` | Es configuración del servidor, no del cliente |
| Último método de login al borrar                  | `409`                                     | Pedir otro método primero |

Cada reto se consume una sola vez: tras cualquier fallo en `/api/v1/login`,
pida un `login/options` nuevo en lugar de reintentar con el mismo `challenge_id`.

## Buenas prácticas

- Ofrezca el passkey como opción junto al login con contraseña, y proponga el alta
  tras un login exitoso.
- Pida un `label` al registrar (por ejemplo "MacBook de casa") para que el usuario
  distinga sus passkeys en la lista.
- Si usa tokens Bearer, decida conscientemente dónde guardarlos. El ejemplo usa
  `sessionStorage` solo por simplicidad.
- Tras el login, las políticas ABAC del servidor pueden exigir `auth_method == "passkey"`
  o `mfa == true`; maneje el `403` correspondiente guiando al usuario a reautenticarse con passkey.
- No intente deducir en el cliente si una cuenta existe: la API está diseñada para
  que no se pueda.
