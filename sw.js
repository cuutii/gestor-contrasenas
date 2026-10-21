/* ============================================================
   SERVICE WORKER de la Bóveda  (sw.js)
   ------------------------------------------------------------
   ¿Qué hace? Guarda los archivos de la app para que pueda
   abrirse SIN INTERNET. Eso es todo lo que hace.

   ══════════════════════════════════════════════════════════
   POR QUÉ NO USAMOS LA MISMA ESTRATEGIA QUE PERITO MAP
   ══════════════════════════════════════════════════════════
   En Perito Map la estrategia es "caché primero": si está
   guardado, se usa eso y no se consulta la red. Para un mapa
   que tiene que andar en la estepa sin señal, es lo correcto.

   ACÁ ES AL REVÉS, y la razón es de seguridad:

     Si mañana corrijo un fallo de seguridad y lo subo, con
     "caché primero" seguirías ejecutando la versión vieja que
     tenés guardada — y NUNCA te enterarías del arreglo.

   Así que acá va RED PRIMERO: siempre se intenta bajar la
   última versión, y la caché se usa únicamente cuando no hay
   internet. En criollo: la app anda sin conexión, pero nunca
   a costa de quedarse con código viejo.

   ══════════════════════════════════════════════════════════
   LAS TRES REGLAS DE ESTE ARCHIVO
   ══════════════════════════════════════════════════════════
   1. SOLO toca peticiones GET del propio sitio (same-origin).
      Cualquier otra cosa la ignora y deja pasar sin tocar.
   2. JAMÁS modifica la respuesta. Solo la cachea tal cual vino.
   3. No hace ninguna petición propia. No habla con nadie: no
      hay analytics, ni telemetría, ni nada por el estilo.

   Consecuencia honesta: este service worker NO añade
   seguridad. Añade disponibilidad. La seguridad la sigue
   poniendo crypto.js.
   ============================================================ */

// Nombre de la caché. Si cambiamos la versión (V2, V3...), el
// navegador descarga todo de nuevo y borra la anterior.
// v2: la lógica migró a src/ (módulos ESM); los nombres viejos
// ./app.js y ./crypto.js ya no existen, hay que cachear los nuevos.
const CACHE_V1 = "gestor-contrasenas-v2";

// Archivos que deben funcionar sin internet.
// Los paths son relativos a sw.js, que vive en la raíz.
const ARCHIVOS = [
  "./",
  "./index.html",
  "./style.css",
  "./src/crypto.js",
  "./src/app.js",
  "./manifest.json",
  "./img/icono.svg",
  "./img/icono-192.png",
  "./img/icono-512.png",
  "./img/icono-maskable-192.png",
  "./img/icono-maskable-512.png"
];

/* ------------------------------------------------------------
   1) INSTALACIÓN: guardamos la "cáscara" de la app.
   ------------------------------------------------------------ */
self.addEventListener("install", evento => {
  // Con skipWaiting la versión nueva pasa a estar activa sin
  // esperar a que cierres todas las pestañas viejas. Para una
  // app de seguridad esto importa: si hay un arreglo, querés
  // que se aplique apenas se pueda.
  self.skipWaiting();

  evento.waitUntil(
    caches
      .open(CACHE_V1)
      .then(cache => cache.addAll(ARCHIVOS))
      // Si falta un ícono, que no se rompa la instalación entera.
      .catch(error => console.warn("No se pudo precachear todo:", error))
  );
});

/* ------------------------------------------------------------
   2) ACTIVACIÓN: borramos las cachés de versiones anteriores.
   ------------------------------------------------------------ */
self.addEventListener("activate", evento => {
  evento.waitUntil(
    caches
      .keys()
      .then(nombres =>
        Promise.all(
          nombres
            .filter(nombre => nombre !== CACHE_V1) // todo menos la actual
            .map(nombre => caches.delete(nombre))
        )
      )
      .then(() => self.clients.claim()) // tomamos control de las pestañas abiertas
  );
});

/* ------------------------------------------------------------
   3) PETICIONES: red primero, caché de respaldo.
   ------------------------------------------------------------ */
self.addEventListener("fetch", evento => {
  const peticion = evento.request;

  // REGLA 1: solo GET. Un POST (por ejemplo un envío de formulario)
  // jamás debe ser interceptado ni guardado.
  if (peticion.method !== "GET") return;

  // REGLA 1 (parte 2): solo lo nuestro. Si por algún motivo algo
  // intentara salir a otro dominio, este worker se niega a tocarlo:
  // ni lo cachea, ni lo proxya, ni lo transforma. Simplemente no
  // interviene y el navegador la resuelve solo.
  let propia;
  try {
    propia = new URL(peticion.url).origin === self.location.origin;
  } catch {
    return; // URL ilegible: mejor no tocar nada
  }
  if (!propia) return;

  // ESTRATEGIA: red primero.
  evento.respondWith(
    fetch(peticion)
      .then(respuesta => {
        // Guardamos copia SOLO si la respuesta es buena (200) y
        // viene de la red. Así la caché siempre refleja lo último
        // que se pudo bajar, no errores.
        if (respuesta && respuesta.status === 200) {
          const copia = respuesta.clone();
          caches.open(CACHE_V1).then(cache => cache.put(peticion, copia));
        }
        return respuesta;
      })
      .catch(() =>
        // No hay internet: intentamos con lo guardado. Si tampoco
        // está, devolvemos una respuesta de error VÁLIDA — nunca
        // undefined, que rompería la petición entera y dejaría la
        // pantalla en blanco sin explicación.
        caches
          .open(CACHE_V1)
          .then(cache => cache.match(peticion))
          .then(
            guardada =>
              guardada ||
              new Response("Sin conexión y este archivo no está guardado.", {
                status: 503,
                statusText: "Sin conexión",
                headers: { "Content-Type": "text/plain; charset=utf-8" }
              })
          )
      )
  );
});
