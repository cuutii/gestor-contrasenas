/* ============================================================
   CRIPTOGRAFÍA DEL BÓVEDA — núcleo de seguridad
   ============================================================
   Este es el archivo MÁS IMPORTANTE del proyecto. Si algo acá
   está mal, todas las contraseñas quedan expuestas.

   Qué hace, en una frase:
   tu contraseña maestra + una sal -> una clave AES-GCM que
   sirve para cifrar y descifrar, y NUNCA se guarda en disco.

   ══════════════════════════════════════════════════════════
   LAS CUATRO REGLAS DE ORO DE ESTE ARCHIVO
   ══════════════════════════════════════════════════════════
   1. La contraseña maestra NUNCA se guarda. Ni en claro, ni
      cifrada, ni "para después". Se usa y se descarta.
   2. La clave derivada se pide como CryptoKey NO exportable
      (`extractable: false`). Aunque un atacante inyecte un
      script, no puede leer los bytes de la clave: solo puede
      pedirle al navegador que cifre o descifre.
   3. El IV (el nonce) es NUEVO en cada guardado. Reusar un IV
      con la misma clave en AES-GCM rompe la seguridad y deja
      descifrar mensajes.
   4. En el disco solo hay CIPHERTEXT. Nunca un byte de texto
      claro.
   ============================================================ */

/* ------------------------------------------------------------
   Parámetros de derivación de clave (KDF)
   ------------------------------------------------------------
   PBKDF2 "estira" tu contraseña muchas veces para que adivinarla
   cueste caro. 600.000 iteraciones es la recomendación actual
   de OWASP para PBKDF2-SHA-256.

   Se guarda el número usado (campo `iter`) por si en el futuro
   subimos el valor: así las bóvedas viejas siguen abriéndose.
   ------------------------------------------------------------ */
const KDF = Object.freeze({
  nombre: "PBKDF2",
  hash: "SHA-256",
  iteraciones: 600000
});

/* Longitud del IV de AES-GCM: 96 bits, que es el tamaño que
   recomienda la norma para el modo autenticado. */
const IV_BYTES = 12;

/* Tamaño de la sal: 128 bits aleatorios. La sal NO es secreta
   (va guardada en claro junto al cifrado), pero tiene que ser
   única por bóveda para que dos personas con la misma contraseña
   no produzcan el mismo cifrado. */
const SAL_BYTES = 16;


/* ============================================================
   CONVERSORES binario <-> base64
   ============================================================
   `crypto.subtle` trabaja con ArrayBuffer y el JSON del disco
   necesita texto, así que hay que traducir. Se hacen a mano en
   lugar de usar `btoa(String.fromCharCode(...array))` porque el
   `...` (spread) revienta la pila del navegador con arrays
   grandes.
   ============================================================ */

function bufAbase64(buffer) {
  const u8 = new Uint8Array(buffer);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function base64Abuf(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8.buffer;
}


/* ============================================================
   1) DERIVAR LA CLAVE A PARTIR DE LA CONTRASEÑA MAESTRA
   ============================================================
   Entrada : contraseña maestra (string) + sal (ArrayBuffer)
   Salida  : CryptoKey de AES-GCM de 256 bits, NO exportable

   ¿Por qué no exportable? Porque si fuera exportable, cualquier
   script malicioso podría pedir `crypto.subtle.exportKey()` y
   quedarse con la clave. Sin exportar, la clave solo vive en el
   interior del navegador y jamás se escribe en JavaScript.
   ============================================================ */
async function derivarClave(contrasenaMaestra, sal, iteraciones) {
  const codificador = new TextEncoder();

  /* importKey convierte la contraseña en una "base" para PBKDF2.
     Passphrase NO es un algoritmo: hay que meter el texto crudo. */
  const claveBase = await crypto.subtle.importKey(
    "raw",
    codificador.encode(contrasenaMaestra),
    "PBKDF2",
    false,            // extractable = false  ← REGLA 2
    ["deriveKey"]
  );

  /* deriveKey estira esa base con la sal y las iteraciones, y ya
     de paso la convierte en una clave AES-GCM lista para usar. */
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: sal, iterations: iteraciones, hash: KDF.hash },
    claveBase,
    { name: "AES-GCM", length: 256 },
    false,            // sigue sin ser exportable
    ["encrypt", "decrypt"]
  );
}


/* ============================================================
   2) CIFRAR UN OBJETO COMPLETO
   ============================================================
   Devuelve { iv, data } en base64. El IV es distinto en cada
   llamada, aunque el contenido sea idéntico. ← REGLA 3
   ============================================================ */
async function cifrarObjeto(clave, objeto) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const texto = new TextEncoder().encode(JSON.stringify(objeto));

  const cifrado = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },   // IV nuevo, siempre
    clave,
    texto
  );

  return { iv: bufAbase64(iv), data: bufAbase64(cifrado) };
}


/* ============================================================
   3) DESCIFRAR
   ============================================================
   Si la contraseña maestra está mal, o el archivo fue alterado,
   AES-GCM lanza `OperationError` (su "etiqueta de autenticación"
   no coincide). Nosotros lo traducimos a un error entendible.

   Esto también significa que NO SE PUEDE descifrar probando
   claves a lo loco: cada intento falla de inmediato.
   ============================================================ */
async function descifrarObjeto(clave, ivB64, dataB64) {
  try {
    const descifrado = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64Abuf(ivB64) },
      clave,
      base64Abuf(dataB64)
    );
    return JSON.parse(new TextDecoder().decode(descifrado));
  } catch (e) {
    /* Distinguimos las dos causas para poder avisar bien:
       - OperationError: contraseña maestra incorrecta o archivo
         corrupto/manipulado.
       - Cualquier otra: JSON inválido, es decir, la contraseña
         era correcta pero los datos no tienen buena pinta. */
    if (e && e.name === "OperationError") {
      throw new Error("CONTRASENA_INCORRECTA");
    }
    throw new Error("DATOS_CORRUPTOS");
  }
}


/* ============================================================
   4) FORMATO DEL ARCHIVO DE LA BÓVEDA
   ============================================================
   Así se ve el JSON que se guarda en localStorage. Notá que
   TODO lo sensible está dentro de `data`, cifrado:

   {
     "v": 1,                    versión del formato
     "kdf": "PBKDF2",           algoritmo de estiramiento
     "hash": "SHA-256",         hash usado por ese KDF
     "iter": 600000,            cuántas iteraciones usó
     "sal": "…",                sal en base64 (NO es secreta)
     "iv": "…",                 IV del último guardado
     "data": "…"                ← LO CIFRADO. Todo lo demás
   }

   `iter`, `sal` e `iv` van en claro porque el navegador los
   necesita para poder descifrar. Ninguno revela la contraseña
   ni las contraseñas guardadas.
   ============================================================ */

function armarBoveda(sal, iteraciones, iv, data) {
  return {
    v: 1,
    kdf: KDF.nombre,
    hash: KDF.hash,
    iter: iteraciones,
    sal: bufAbase64(sal),
    iv: iv,
    data: data
  };
}


/* ============================================================
   5) NUEVA BÓVEDA
   ============================================================
   Genera la sal, deriva la clave y devuelve la bóveda cifrada
   junto con la clave viva (que el llamador debe descartar con
   `bloquear()` cuando se vaya).
   ============================================================ */
async function crearBoveda(contrasenaMaestra) {
  if (typeof contrasenaMaestra !== "string" || contrasenaMaestra.length === 0) {
    throw new Error("FALTA_CONTRASENA");
  }

  const sal = crypto.getRandomValues(new Uint8Array(SAL_BYTES));
  const clave = await derivarClave(contrasenaMaestra, sal, KDF.iteraciones);
  const { iv, data } = await cifrarObjeto(clave, { entradas: [] });

  return { boveda: armarBoveda(sal, KDF.iteraciones, iv, data), clave: clave };
}


/* ============================================================
   6) ABRIR UNA BÓVEDA EXISTENTE
   ============================================================ */
async function abrirBoveda(contrasenaMaestra, bovedaGuardada) {
  if (!bovedaGuardada || typeof bovedaGuardada !== "object") {
    throw new Error("NO_HAY_BOVEDA");
  }

  const iteraciones = Number(bovedaGuardada.iter) || KDF.iteraciones;
  const sal = base64Abuf(bovedaGuardada.sal);
  const clave = await derivarClave(contrasenaMaestra, sal, iteraciones);

  /* Si la contraseña está mal esto lanza CONTRASENA_INCORRECTA.
     La clave derivada en ese caso queda en el olvido: no se usa. */
  const contenido = await descifrarObjeto(clave, bovedaGuardada.iv, bovedaGuardada.data);

  if (!contenido || !Array.isArray(contenido.entradas)) {
    throw new Error("DATOS_CORRUPTOS");
  }

  return { clave: clave, entradas: contenido.entradas };
}


/* ============================================================
   7) RE-CIFRAR (para guardar cambios)
   ============================================================
   Cada vez que se agrega o edita una entrada hay que volver a
   cifrar TODO el contenido con un IV nuevo. Si usáramos el IV
   viejo romperíamos AES-GCM. ← REGLA 3
   ============================================================ */
async function guardarBoveda(clave, bovedaPrevia, entradas) {
  const { iv, data } = await cifrarObjeto(clave, { entradas: entradas });
  const nueva = Object.assign({}, bovedaPrevia, { iv: iv, data: data });
  return nueva;
}
