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

| Amenaza | Cómo |
|---|---|
| Que un servidor filtrado exponga tus claves | **No hay servidor.** No existe nada que filtrar. |
| Que alguien lea el archivo guardado | Está cifrado; abrirlo exige la contraseña maestra. |
| Que la página hable con terceros | **Cero peticiones de red.** Sin CDN, sin analíticas, sin API. |
| Que un script lea la clave | La clave es `extractable: false` y solo vive en memoria mientras está abierta. |
| Inyección de HTML (XSS básico) | **Nunca se usa `innerHTML`**: todo pasa por `textContent`. |

### ✗ NO protege contra

| Amenaza | Por qué |
|---|---|
| **Que pierdas la contraseña maestra** | **No hay recuperación.** Es matemático, no una política. |
| Malware en tu equipo | Un troyano que graba lo que tipeás no lo puede detener ningún gestor. |
| Que te miren por encima del hombro | Físico, no criptográfico. |
| Robo del equipo apagado | Mientras esté bloqueada está cifrada; si te roban el equipo encendido y abierto, es otro tema. |

### ⚠️ Límites honestos

- **Es local a este navegador.** No se sincroniza con otros dispositivos. Es la consecuencia directa de no tener servidor: la misma decisión que lo hace opaco a terceros.
- **Si perdés la contraseña maestra, perdiste todo.** No hay "olvidé mi contraseña" ni copia en ningún lado salvo la que exportes vos.
- **No está auditado.** Este proyecto lo escribí para aprender y mostrar; **un gestor auditado por profesionales (Bitwarden, KeePass, 1Password) es más confiable** para las contraseñas que de verdad no podés perder.

**Recomendación:** usá este para credenciales de poca monta, pruebas y aprendizaje. Para correo, banco y todo lo que no podés permitirte perder, usá Bitwarden o KeePass.

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

## 📁 Estructura

```
09-gestor-contrasenas/
├── index.html     ← pantalla + CSP (aquí NO puede haber onclick= inline)
├── crypto.js      ← el núcleo: derivar clave, cifrar, descifrar
├── app.js         ← lógica de la interfaz (sin innerHTML, jamás)
├── style.css      ← estilos, sin fuentes externas
└── README.md      ← este archivo
```

## ▶️ Cómo probarla

```
powershell -ExecutionPolicy Bypass -File servidor-prueba.ps1
```

y abrí `http://localhost:8127`. Doble clic sobre `index.html` **no sirve**, porque `crypto.subtle` solo está disponible en contextos seguros (`https://` o `localhost`).

---

## 🚫 Las reglas de este proyecto

Hay tres reglas que no se tocan, y conviene saber por qué:

**1. Nunca `innerHTML`.**
Con `innerHTML`, un fragmento de HTML inyectado se ejecuta como código. En un gestor, eso equivaldría a entregar las contraseñas. Todo lo que se dibuja pasa por `createElement()` y `textContent`.

Verificación real (con el punto, para que no atrape a los comentarios que explican la regla):

```bash
grep -nE '\.innerHTML|\.outerHTML|insertAdjacent\w*' app.js
# esperado: sin resultados
```

**2. Nunca recursos externos.**
Cada petición a un tercero es una oportunidad de que se filtre que usás este gestor. Por eso no hay CDN ni fuentes de Google: solo tipografías del sistema.

```bash
grep -nE 'fonts\.googleapis|cdn\.|unpkg|jsdelivr|fetch\(|XMLHttpRequest' *.js *.html
# esperado: sin resultados
```

**3. La CSP no se relaja.**

```
default-src 'none'; script-src 'self'; style-src 'self';
img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'
```

`connect-src 'none'` es la garantía de que la página **no puede** llamar a ningún lado, ni siquiera si alguien logra inyectar código.

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
