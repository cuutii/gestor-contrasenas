# 🔐 Bóveda — Gestor de contraseñas local

Gestor de contraseñas **100 % en el navegador**: no hay servidor, no hay base de datos y **no se hace ni una sola petición de red**. Tus contraseñas se cifran con AES-GCM en tu propia compu y así es como quedan guardadas.

## 🌐 Demo

🔗 **https://cuutii.github.io/gestor-contrasenas/**

> Probalo con contraseñas de prueba. Para tus cuentas más críticas, preferí un gestor auditado profesionalmente — más abajo explico por qué.

---

## ✨ Qué hace

- **Cifrado real**: AES-GCM de 256 bits, con clave derivada por **PBKDF2-SHA-256 a 600.000 iteraciones** (recomendación actual de OWASP).
- **Contraseña maestra que nunca se guarda**: se usa para derivar la clave y se descarta. No está ni en claro ni cifrada.
- **Clave no exportable**: se pide al navegador como `CryptoKey` con `extractable: false`. Aunque un script malicioso se colara, no podría leer los bytes de la clave, solo pedir que se descifre.
- **IV nuevo en cada guardado**: reusar un IV con la misma clave rompe AES-GCM; por eso cada guardado genera uno distinto.
- **Bloqueo automático** a los 5 minutos de inactividad, y manual con un botón. Al bloquear se borra la clave de memoria, se vacía la lista y se limpian todos los campos.
- **Generador de contraseñas** con aleatoriedad criptográfica y selección **sin sesgo** (muestreo por rechazo, no `n % largo`).
- **Copia de seguridad** exportable/importable **cifrada**.
- **Búsqueda** por título, usuario o sitio.
- **Responsive** y con soporte de `prefers-reduced-motion`.

---

## 🛡️ Qué protege — y qué no

Esto va en el pie de la página también. Ocultar los límites de un gestor de contraseñas sería engañar al usuario.

### ✓ Protege contra

| Amenaza                                     | Cómo                                                                           |
| ------------------------------------------- | ------------------------------------------------------------------------------ |
| Que un servidor filtrado exponga tus claves | **No hay servidor.** No existe nada que filtrar.                               |
| Que alguien lea el archivo guardado         | Está cifrado; abrirlo exige la contraseña maestra.                             |
| Que la página hable con terceros            | **Cero peticiones de red.** Sin CDN, sin analíticas, sin API.                  |
| Que un script lea la clave                  | La clave es `extractable: false` y solo vive en memoria mientras está abierta. |
| Inyección de HTML (XSS básico)              | **Nunca se usa `innerHTML`**: todo pasa por `textContent`.                     |

### ✗ NO protege contra

| Amenaza                               | Por qué                                                                                        |
| ------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Que pierdas la contraseña maestra** | **No hay recuperación.** Es matemático, no una política.                                       |
| Malware en tu equipo                  | Un troyano que graba lo que tipeás no lo puede detener ningún gestor.                          |
| Que te miren por encima del hombro    | Físico, no criptográfico.                                                                      |
| Robo del equipo apagado               | Mientras esté bloqueada está cifrada; si te roban el equipo encendido y abierto, es otro tema. |

### ⚠️ Límites honestos

- **Es local a este navegador.** No se sincroniza con otros dispositivos. Es la consecuencia directa de no tener servidor: la misma decisión que lo hace opaco a terceros.
- **Si perdés la contraseña maestra, perdiste todo.** No hay "olvidé mi contraseña" ni copia en ningún lado salvo la que exportes vos.
- **No está auditado.** Este proyecto lo escribí para aprender y mostrar; **un gestor auditado por profesionales (Bitwarden, KeePass, 1Password) es más confiable** para las contraseñas que de verdad no podés perder.

**Recomendación:** usá este para credenciales de poca monta, pruebas y aprendizaje. Para correo, banco y todo lo que no podés permitirte perder, usá Bitwarden o KeePass.

---

## 📱 Instalarla como app

Como tiene manifest y service worker, el navegador ofrece **instalarla**: en el celular aparece el botón de "Agregar a pantalla de inicio" y en el navegador de escritorio el ícono de instalar al costado de la barra de direcciones.

### Qué ganás instalándola

| Beneficio             | Detalle                                                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Anda sin internet** | Los archivos quedan guardados; no hace falta señal ni WiFi para abrirla.                                                                  |
| **Ventana propia**    | Se abre sin barra de direcciones.                                                                                                         |
| **Menos phishing**    | Al no haber barra de direcciones donde se pueda escribir una URL parecida, se complica el ataque de "página falsa que imita a la bóveda". |
| **Ícono propio**      | Candado azul, el mismo que ves arriba.                                                                                                    |

### ⚠️ Qué NO cambia — leé esto antes de instalarla

- **No la vuelve más segura.** La seguridad la pone `src/crypto.js`. Instalar es una cuestión de comodidad, no de protección.
- **No crea una bóveda separada.** La app instalada y el sitio web comparten **exactamente los mismos datos**, porque viven en el mismo origen (`cuutii.github.io`). Si la abrís en el navegador vas a ver la misma bóveda, sin más.
- **Tu bóveda sigue atada a esa dirección.** Este es el punto más importante de esta sección:
  > Si algún día se desactiva Pages, se borra el repo o cambia el nombre, **la app instalada deja de abrirse y tu bóveda queda ahí, inaccesible**. El navegador además puede llegar a borrar el almacenamiento de orígenes que no se usan durante semanas.
  >
  > **Por eso la exportación cifrada no es opcional: es tu único respaldo.** Hacela y guardala en un pendrive.

### ¿Y el service worker, agrega seguridad?

**No. Agrega disponibilidad.** De hecho trae un riesgo propio que se mitiga así:

> Un service worker guarda código. Si usáramos "caché primero" como en un mapa, y mañana corrigiera un fallo de seguridad, vos seguirías ejecutando la versión vieja guardada **sin enterarte nunca**. Por eso `sw.js` usa **"red primero, caché de respaldo"**: siempre intenta bajar la última versión, y solo usa la caché si no hay internet.

Además, `sw.js` se limita a lo suyo: solo intercepta **GET del propio sitio**, jamás modifica una respuesta y no hace ninguna petición propia.

Cuando aparece una versión nueva, **no se recarga sola** — aparece un aviso. Recargar a la fuerza en un gestor de contraseñas sería descuidado: podría caerse en el medio de que estás tipeando tu contraseña maestra.

---

## 🧪 Cómo funciona por dentro

### El viaje de tu contraseña maestra

```
contraseña maestra ─┐
                    ├─→ PBKDF2 (600.000 iter + sal de 16 bytes)
   sal guardada ────┘                    │
                                         ▼
                            CryptoKey AES-GCM 256 bits
                              (NO exportable, solo RAM)
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
             cifrar() el JSON                          descifrar() al abrir
                    │                                         │
                    ▼                                         ▼
         { sal, iv, data } en base64  ←——— localStorage ———→ entradas en claro
        (esto es lo único que hay en el disco)            (SOLO en memoria)
```

### Formato guardado

```json
{
  "v": 1,
  "kdf": "PBKDF2",
  "hash": "SHA-256",
  "iter": 600000,
  "sal": "…",   ← NO es secreta: el navegador la necesita para derivar
  "iv":  "…",   ← distinto en cada guardado
  "data": "…"   ← LO CIFRADO: todo lo demás está acá adentro
}
```

`sal`, `iv` e `iter` van en claro porque sin ellos no se podría descifrar, y ninguno revela la contraseña maestra ni las guardadas.

---

## 📁 Estructura del proyecto

```
09-gestor-contrasenas/
├── index.html             ← pantalla + CSP (aquí NO puede haber onclick= inline)
├── style.css              ← estilos, sin fuentes externas
├── manifest.json          ← lo que hace que el navegador ofrezca instalarla
├── sw.js                  ← service worker (script clásico): red primero, caché de respaldo
├── src/
│   ├── crypto.js          ← núcleo: derivar clave, cifrar, descifrar (módulo ESM)
│   └── app.js             ← lógica de la interfaz (módulo ESM, sin innerHTML, jamás)
├── img/                   ← íconos (SVG fuente + PNG 192/512, con y sin maskable)
├── servidor-prueba.ps1    ← servidor local para probar en localhost
├── package.json           ← scripts: test, lint, format
├── eslint.config.js       ← flat config de ESLint (@eslint/js + eslint-config-prettier)
├── .prettierrc.json       ← formato de código (Prettier)
├── .editorconfig          ← preferencias del editor
├── .gitignore
├── LICENSE
└── README.md              ← este archivo
```

`src/app.js` y `src/crypto.js` son **módulos ESM**: `index.html` carga `src/app.js` con `<script type="module">`, y `app.js` importa de `crypto.js` lo que usa (`crearBoveda`, `abrirBoveda`, `guardarBoveda`). Nada depende de globales implícitas entre archivos. `sw.js` en cambio sigue siendo un script clásico, porque los service workers no se cargan como módulos de forma estándar.

## ▶️ Cómo probarla

```
powershell -ExecutionPolicy Bypass -File servidor-prueba.ps1
```

y abrí `http://localhost:8127`. Doble clic sobre `index.html` **no sirve**, porque `crypto.subtle` solo está disponible en contextos seguros (`https://` o `localhost`).

---

## 🛠 Herramientas de desarrollo

`package.json` trae scripts para ESLint, Prettier y Vitest. Antes de usarlos hay que instalar las dependencias (esto baja paquetes a `node_modules/`; no toca el sitio publicado):

```bash
npm install
```

| Comando                | Qué hace                                                               |
| ---------------------- | ---------------------------------------------------------------------- |
| `npm run lint`         | Corre ESLint con la configuración de `eslint.config.js` (flat config). |
| `npm run format`       | Reformatea los archivos según `.prettierrc.json`.                      |
| `npm run format:check` | Chequea el formato sin modificar archivos.                             |
| `npm test`             | Corre la suite de Vitest una vez.                                      |
| `npm run test:watch`   | Vitest en modo watch.                                                  |

Los tests, cuando existan, van en `tests/` (esa carpeta está prevista en la configuración de ESLint y en Vitest, pero todavía no hay archivos de test en el repo).

Estas herramientas son solo para desarrollo: el sitio publicado en GitHub Pages no usa npm, no tiene build step y no depende de `node_modules/`.

---

## 🚫 Las reglas de este proyecto

Hay tres reglas que no se tocan, y conviene saber por qué:

**1. Nunca `innerHTML`.**
Con `innerHTML`, un fragmento de HTML inyectado se ejecuta como código. En un gestor, eso equivaldría a entregar las contraseñas. Todo lo que se dibuja pasa por `createElement()` y `textContent`.

Verificación:

```bash
grep -nE "\.(inner|outer)HTML" src/app.js
# esperado: 0 resultados
```

El comando está escrito **a propósito con `(inner|outer)`** y no con la palabra completa: si se escribiera el literal con el punto, el grep atraparía la propia línea donde se documenta la regla y daría falsa alarma. (Me pasó tres veces antes de entenderlo.)

**2. Nunca recursos externos.**
Cada petición a un tercero es una oportunidad de que se filtre que usás este gestor. Por eso no hay CDN ni fuentes de Google: solo tipografías del sistema.

```bash
grep -nE 'fonts\.googleapis|cdn\.|unpkg|jsdelivr|XMLHttpRequest|sendBeacon' src/*.js *.js *.html
# esperado: sin resultados
```

Ojo con `fetch()`: **`sw.js` sí lo usa**, porque necesita pedir los archivos del propio sitio para cachearlos. Lo que no puede existir es un `fetch()` hacia afuera. Eso se comprueba así:

```bash
grep -nE "fetch\(\s*['\"\`]?https?://" src/*.js *.js *.html
# esperado: sin resultados — ningún fetch hacia otro dominio
```

**3. La CSP no se relaja.**

```
default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self';
img-src 'self' data:; font-src 'self'; connect-src 'none';
base-uri 'none'; form-action 'none'
```

- `connect-src 'none'` es la garantía de que la página **no puede** llamar a ningún lado, ni siquiera si alguien logra inyectar código. _(Verificado: un `fetch()` a un dominio externo es bloqueado y lo registra en consola.)_
- `worker-src 'self'` es el que permite registrar el service worker. **No es un relajamiento**: sin esa directiva, `default-src 'none'` lo habría bloqueado en silencio y la app simplemente no se podría instalar. Igual que `script-src`, solo admite scripts del propio sitio.

> **Límite de la CSP en GitHub Pages:** al no poder enviar cabeceras HTTP propias, la política va en una `<meta>`, y el navegador ignora en `meta` algunas directivas (`frame-ancestors` entre ellas). No es una CSP tan fuerte como la que se manda por cabecera.

---

## 🐛 Bugs que encontré probando (y por qué importa)

Un proyecto de seguridad **hay que probarlo**, no solo leerlo. Los chequeos estáticos pasaron todos y aun así la app estaba rota:

1. **`ReferenceError: temporizador is not defined` en `bloquear()`.** Usé la variable suelta `temporizador` en vez de `estado.temporizador`. Como `app.js` va en modo estricto, eso lanzaba un error **en la primera línea de la función**: el botón de bloquear **no hacía nada** y la clave quedaba viva en memoria indefinidamente. Los grep de seguridad no lo habrían visto nunca; lo cazó la prueba funcional de "bloquear y verificar que `estado.clave === null`".

2. **Comentario falso propio.** Dejé escrito que `grep innerHTML *.js` daba 0 resultados, cuando daba 5 (los comentarios que explicaban la regla). Se corrigió el comando por uno que sí funciona: `grep -nE '\.innerHTML'`.

3. **Botón con restos de plantilla** y un `onclick=""` que la propia CSP habría bloqueado. Reemplazado y enganchado desde `app.js`.

---

## 📄 Licencia

MIT
