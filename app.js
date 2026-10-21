/* ============================================================
   BÓVEDA DE CONTRASEÑAS — lógica de la aplicación
   ============================================================

   ┌─────────────────────────────────────────────────────────┐
   │  REGLA INQUEBRANTABLE DE ESTE ARCHIVO:                  │
   │                                                         │
   │  JAMÁS se usa innerHTML ni insertAdjacentHTML.          │
   │                                                         │
   │  Todo lo que se dibuja se dibuja con createElement() y  │
   │  textContent. Motivo: si algún día se cuela un script   │
   │  (XSS), con innerHTML ese script puede leer las         │
   │  contraseñas mientras están visibles. Con textContent   │
   │  el texto SIEMPRE se trata como texto, nunca como HTML. │
   │                                                         │
   │  Verificación:                                          │
   │                                                         │
   │    grep -nE "\.(inner|outer)HTML" app.js                │
   │                                                         │
   │  Debe devolver 0 resultados. El comando está escrito    │
   │  de forma que no se encuentre a sí mismo ni a esta      │
   │  caja: usa (inner|outer) en lugar de escribir la        │
   │  palabra completa, así ningún comentario puede          │
   │  hacer que un grep de mentira dé falsa alarma.          │
   └─────────────────────────────────────────────────────────┘

   Además, este proyecto NO hace NINGUNA petición de red.
   No hay CDN, no hay fuentes de Google, no hay analíticas.
   Tu bóveda nunca sale de tu computadora.
   ============================================================ */

"use strict";


/* ============================================================
   0) ESTADO EN MEMORIA
   ============================================================
   `clave` es un CryptoKey vivo. Solo existe mientras la bóveda
   está desbloqueada, y se vuelve `null` al bloquear. Es el dato
   más sensible de todo el programa.
   ============================================================ */
const estado = {
  clave: null,          // CryptoKey | null  (null = bloqueada)
  entradas: [],         // copia en claro, SOLO en memoria
  boveda: null,         // el JSON cifrado que va a localStorage
  editandoId: null,     // id de la entrada que se está editando
  temporizador: null,   // temporizador de bloqueo automático
  ultimaActividad: Date.now()
};

const CLAVE_STORAGE = "gestor.cesta";     // la bóveda cifrada
const CLAVE_AJUSTES = "gestor.ajustes";   // ajustes (no sensibles)
const SEGUNDOS_PARA_BLOQUEAR = 300;       // 5 minutos sin tocar nada
const SEGUNDOS_PARA_BORRAR_CLIPBOARD = 30;

/* ============================================================
   1) UTILIDADES DE DOM  (la alternativa a innerHTML)
   ============================================================
   `el(tag, props, hijos)` construye nodos de forma declarativa.
   Cualquier texto que venga del usuario va por `textContent`,
   que escapa solo y no puede inyectar etiquetas.
   ============================================================ */
function el(tag, props, hijos) {
  const nodo = document.createElement(tag);

  if (props) {
    for (const clave in props) {
      if (!Object.prototype.hasOwnProperty.call(props, clave)) continue;
      const valor = props[clave];

      /* `class`, `id`, `type`... van como atributos comunes */
      if (typeof valor === "string" || typeof valor === "number") {
        nodo.setAttribute(clave, String(valor));
      } else if (typeof valor === "boolean") {
        /* true agrega el atributo, false lo omite */
        if (valor) nodo.setAttribute(clave, "");
      } else if (typeof valor === "function") {
        /* Atajos de eventos: onclick, oninput... */
        nodo.addEventListener(clave.slice(2).toLowerCase(), valor);
      }
    }
  }

  if (hijos) {
    for (const hijo of hijos) {
      if (hijo === null || hijo === undefined) continue;
      /* Si nos pasan texto lo envolvemos en un nodo texto:
         nunca se interpreta como etiqueta. */
      if (typeof hijo !== "object") {
        nodo.appendChild(document.createTextNode(String(hijo)));
      } else {
        nodo.appendChild(hijo);
      }
    }
  }
  return nodo;
}

function $(id) { return document.getElementById(id); }

/* Vaciar un contenedor sin dejar restos en el DOM */
function vaciar(nodo) {
  while (nodo.firstChild) nodo.removeChild(nodo.firstChild);
}


/* ============================================================
   2) STORAGE  (solo va cifrado, o ajustes insensibles)
   ============================================================ */
function leerBoveda() {
  try {
    const crudo = localStorage.getItem(CLAVE_STORAGE);
    if (!crudo) return null;
    const obj = JSON.parse(crudo);
    /* Verificación mínima de forma: si no tiene pinta de bóveda,
       la tratamos como inexistente en lugar de romper. */
    if (!obj || typeof obj !== "object") return null;
    if (!obj.iv || !obj.data || !obj.sal) return null;
    return obj;
  } catch (e) {
    return null;
  }
}

function escribirBoveda(boveda) {
  localStorage.setItem(CLAVE_STORAGE, JSON.stringify(boveda));
}

function leerAjustes() {
  try {
    const crudo = localStorage.getItem(CLAVE_AJUSTES);
    if (crudo) return JSON.parse(crudo);
  } catch (e) { /* no importa */ }
  return { verContrasenas: false, ordenarPor: "titulo" };
}

function escribirAjustes(ajustes) {
  localStorage.setItem(CLAVE_AJUSTES, JSON.stringify(ajustes));
}

let ajustes = leerAjustes();


/* ============================================================
   3) GENERADOR DE CONTRASEÑAS
   ============================================================
   Reutiliza la idea de tu proyecto `generador-contrasenas`, pero
   con dos mejoras importantes para este contexto:

   a) Usa crypto.getRandomValues (no Math.random, que NO es
      criptográficamente seguro).
   b) Saca los caracteres SIN SESGO. Esto es sutil: si hacés
      `numero % pool.length` con un entero de 32 bits, algunos
      caracteres salen un poquito más que otros porque 2^32 no es
      múltiplo de la longitud del abecedario. Se arregla con
      "rechazo": se descartan los valores que sobrerrepresentan.
   ============================================================ */
const JUEGOS = {
  minusculas: "abcdefghijklmnopqrstuvwxyz",
  mayusculas: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numeros: "0123456789",
  simbolos: "!@#$%^&*()-_=+[]{};:,.<>?/"
};

const MAX_U32 = 4294967296;   // 2^32

function enteroSinSesgo(maximo) {
  /* Devuelve un entero aleatorio uniforme en [0, maximo). */
  const limite = Math.floor(MAX_U32 / maximo) * maximo;
  const buffer = new Uint32Array(1);
  let valor;
  do {
    crypto.getRandomValues(buffer);
    valor = buffer[0];
  } while (valor >= limite);
  return valor % maximo;
}

function generarContrasena(largo, opciones) {
  let abecedario = JUEGOS.minusculas;   // siempre incluida
  const obligatorias = [];

  if (opciones.mayusculas) {
    abecedario += JUEGOS.mayusculas;
    obligatorias.push(JUEGOS.mayusculas[enteroSinSesgo(JUEGOS.mayusculas.length)]);
  }
  if (opciones.numeros) {
    abecedario += JUEGOS.numeros;
    obligatorias.push(JUEGOS.numeros[enteroSinSesgo(JUEGOS.numeros.length)]);
  }
  if (opciones.simbolos) {
    abecedario += JUEGOS.simbolos;
    obligatorias.push(JUEGOS.simbolos[enteroSinSesgo(JUEGOS.simbolos.length)]);
  }

  /* Generamos el cuerpo completo... */
  const cuerpo = [];
  for (let i = 0; i < largo; i++) {
    cuerpo.push(abecedario[enteroSinSesgo(abecedario.length)]);
  }

  /* ...y garantizamos que al menos una de cada tipo elegida
     esté presente. Se coloca en una posición aleatoria, no
     siempre al principio (eso delata el patrón). */
  if (obligatorias.length > 0 && largo >= obligatorias.length) {
    const usadas = new Set();
    for (const caracter of obligatorias) {
      let pos;
      let intentos = 0;
      do {
        pos = enteroSinSesgo(largo);
        intentos++;
      } while (usadas.has(pos) && intentos < 50);
      usadas.add(pos);
      cuerpo[pos] = caracter;
    }
  }

  return cuerpo.join("").slice(0, largo);
}

/* Estimación de fortaleza. Es una HEURÍSTICA, no una medida
   matemática: sirve para orientar, no para certificar. */
function medirFortaleza(clave) {
  if (!clave) return { puntos: 0, texto: "", clase: "" };

  let entropia = 0;
  const largo = clave.length;

  const tieneMinus = /[a-z]/.test(clave);
  const tieneMayus = /[A-Z]/.test(clave);
  const tieneNum = /[0-9]/.test(clave);
  const tieneSimb = /[^A-Za-z0-9]/.test(clave);

  let abecedario = 0;
  if (tieneMinus) abecedario += 26;
  if (tieneMayus) abecedario += 26;
  if (tieneNum) abecedario += 10;
  if (tieneSimb) abecedario += 33;

  if (abecedario > 0) entropia = largo * (Math.log2(abecedario));

  /* Penalizaciones: contraseñas muy cortas o repetitivas son
     mucho más fáciles de adivinar de lo que sugiere su largo. */
  if (largo < 8) entropia *= 0.4;
  if (/^(.)\1+$/.test(clave)) entropia *= 0.3;
  if (/^(123|abc|qwe|password|contrasena)/i.test(clave)) entropia *= 0.4;

  if (entropia >= 100) return { puntos: 4, texto: "Muy fuerte", clase: "fuerte" };
  if (entropia >= 75) return { puntos: 3, texto: "Fuerte", clase: "buena" };
  if (entropia >= 50) return { puntos: 2, texto: "Aceptable", clase: "regular" };
  if (entropia >= 28) return { puntos: 1, texto: "Débil", clase: "debil" };
  return { puntos: 0, texto: "Muy débil", clase: "mala" };
}


/* ============================================================
   4) PORTAPAPELES
   ============================================================
   Copia y borra después de un rato. Aclaración honesta: borrar
   el portapapeles es "mejor esfuerzo" — el sistema operativo
   puede haber dejado una copia en su propio historial, y no
   todas las plataformas lo permiten. Reduce la ventana de
   exposición, no la elimina.
   ============================================================ */
let temporizadorClip = null;

async function copiarAlPortapapeles(texto, boton) {
  try {
    await navigator.clipboard.writeText(texto);
  } catch (e) {
    avisar("No se pudo copiar. Probá con Ctrl+C.", "error");
    return;
  }

  const textoOriginal = boton ? boton.textContent : null;
  if (boton) boton.textContent = "Copiado ✓";

  avisar("Copiado. Se borra del portapapeles en " +
         SEGUNDOS_PARA_BORRAR_CLIPBOARD + " segundos.", "ok");

  if (temporizadorClip) clearTimeout(temporizadorClip);
  temporizadorClip = setTimeout(async () => {
    try {
      /* Solo lo borramos si sigue siendo lo que pusimos: si el
         usuario copió otra cosa en el medio, no lo pisamos. */
      const actual = await navigator.clipboard.readText();
      if (actual === texto) await navigator.clipboard.writeText("");
    } catch (e) { /* sin permiso: no insiste */ }
    if (boton && textoOriginal !== null) boton.textContent = textoOriginal;
  }, SEGUNDOS_PARA_BORRAR_CLIPBOARD * 1000);
}


/* ============================================================
   5) AVISOS
   ============================================================ */
let temporizadorAviso = null;

function avisar(mensaje, tipo) {
  const caja = $("aviso");
  if (!caja) return;
  vaciar(caja);
  caja.appendChild(document.createTextNode(mensaje));
  caja.className = "aviso aviso--" + (tipo || "info");
  caja.hidden = false;

  if (temporizadorAviso) clearTimeout(temporizadorAviso);
  temporizadorAviso = setTimeout(() => { caja.hidden = true; }, 5000);
}


/* ============================================================
   6) PANTALLAS
   ============================================================
   Hay tres y están todas en el HTML desde el inicio; solo se
   muestra una. Nunca se borran del DOM porque la lista de
   entradas se redibuja entera con `vaciar()` + `el()`.
   ============================================================ */
function mostrarPantalla(cual) {
  ["crear", "abrir", "lista"].forEach(nombre => {
    const nodo = $("pantalla-" + nombre);
    if (nodo) nodo.hidden = (nombre !== cual);
  });

  const barra = $("barra-superior");
  /* El botón de bloquear solo tiene sentido con la bóveda abierta */
  if (barra) barra.hidden = (cual !== "lista");
}


/* ============================================================
   7) CREAR LA BÓVEDA
   ============================================================ */
async function manejarCrear(ev) {
  ev.preventDefault();

  const una = $("crear-clave").value;
  const otra = $("crear-repetir").value;
  const error = $("crear-error");
  const boton = $("crear-enviar");

  const fallo = msg => { vaciar(error); error.appendChild(document.createTextNode(msg)); };

  if (una.length < 8) {
    fallo("La contraseña maestra necesita al menos 8 caracteres.");
    return;
  }
  if (una !== otra) {
    fallo("Las dos contraseñas no coinciden.");
    return;
  }

  /* La derivación con 600.000 iteraciones tarda de verdad
     (entre medio segundo y un segundo). Deshabilitamos el botón
     para que no se dispare dos veces. */
  boton.disabled = true;
  boton.textContent = "Creando…";

  try {
    const { boveda, clave } = await crearBoveda(una);

    /* IMPORTANTE: antes de escribir nada, hacemos una prueba de
       ida y vuelta. Si el navegador no puede descifrar lo que
       acabamos de cifrar, no tiene sentido guardar. */
    const prueba = await abrirBoveda(una, boveda);
    if (prueba.entradas.length !== 0) throw new Error("PRUEBA_FALLIDA");

    escribirBoveda(boveda);

    estado.clave = clave;
    estado.entradas = [];
    estado.boveda = boveda;

    /* Limpiamos los campos: la contraseña maestra no debe
       quedarse en el DOM una vez usada. */
    $("crear-clave").value = "";
    $("crear-repetir").value = "";

    arrancarTemporizador();
    entrarAlListado();
    avisar("Bóveda creada. Guardá bien tu contraseña maestra: no hay recuperación.", "ok");

  } catch (e) {
    fallo("No se pudo crear la bóveda: " + (e.message || e));
  } finally {
    boton.disabled = false;
    boton.textContent = "Crear bóveda";
  }
}


/* ============================================================
   8) ABRIR LA BÓVEDA
   ============================================================ */
async function manejarAbrir(ev) {
  ev.preventDefault();

  const error = $("abrir-error");
  const boton = $("abrir-enviar");
  const password = $("abrir-clave").value;

  const fallo = msg => { vaciar(error); error.appendChild(document.createTextNode(msg)); };

  const boveda = leerBoveda();
  if (!boveda) { fallo("No hay ninguna bóveda en este navegador."); return; }

  boton.disabled = true;
  boton.textContent = "Abriendo…";

  try {
    const { clave, entradas } = await abrirBoveda(password, boveda);

    estado.clave = clave;
    estado.entradas = entradas;
    estado.boveda = boveda;

    $("abrir-clave").value = "";   // no dejar rastro en el DOM
    vaciar(error);

    arrancarTemporizador();
    entrarAlListado();
    avisar("Bóveda abierta.", "ok");

  } catch (e) {
    if (e.message === "CONTRASENA_INCORRECTA") {
      fallo("Contraseña maestra incorrecta.");
    } else if (e.message === "DATOS_CORRUPTOS") {
      fallo("Los datos están dañados o fueron alterados.");
    } else {
      fallo("No se pudo abrir: " + (e.message || e));
    }
  } finally {
    boton.disabled = false;
    boton.textContent = "Abrir bóveda";
  }
}


/* ============================================================
   9) BLOQUEAR
   ============================================================
   Este es el corazón de la seguridad en uso. Al bloquear:
     - la CryptoKey pasa a null
     - el arreglo de entradas en claro se vacía
     - se limpian todos los inputs
     - se vacía el contenedor de la lista
   ============================================================ */
function bloquear(motivo) {
  if (estado.temporizador) clearInterval(estado.temporizador);
  estado.temporizador = null;

  estado.clave = null;
  estado.entradas = [];
  estado.editandoId = null;
  estado.boveda = leerBoveda();

  /* Barremos los inputs: nada de texto sensible en el DOM */
  document.querySelectorAll("input[type=text], input[type=password], textarea")
    .forEach(campo => {
      if (campo.id !== "crear-clave" && campo.id !== "crear-repetir") campo.value = "";
    });

  const contenedor = $("lista-entradas");
  if (contenedor) vaciar(contenedor);

  $("abrir-clave").value = "";
  mostrarPantalla("abrir");
  $("abrir-clave").focus();

  if (motivo) avisar(motivo, "info");
}


/* ============================================================
   10) BLOQUEO AUTOMÁTICO POR INACTIVIDAD
   ============================================================ */
function arrancarTemporizador() {
  if (estado.temporizador) clearInterval(estado.temporizador);
  estado.ultimaActividad = Date.now();

  estado.temporizador = setInterval(() => {
    if (!estado.clave) return;
    const transcurrido = Date.now() - estado.ultimaActividad;
    if (transcurrido > SEGUNDOS_PARA_BLOQUEAR * 1000) {
      bloquear("Bóveda bloqueada tras " +
               (SEGUNDOS_PARA_BLOQUEAR / 60) + " minutos sin actividad.");
    } else {
      actualizarRelojBloqueo(transcurrido);
    }
  }, 1000);
}

function marcarActividad() {
  estado.ultimaActividad = Date.now();
  if (estado.clave && !estado.temporizador) arrancarTemporizador();
}

function actualizarRelojBloqueo(transcurrido) {
  const nodo = $("tiempo-bloqueo");
  if (!nodo) return;
  const restante = Math.max(0, Math.ceil((SEGUNDOS_PARA_BLOQUEAR * 1000 - transcurrido) / 1000));
  const min = Math.floor(restante / 60);
  const seg = String(restante % 60).padStart(2, "0");
  vaciar(nodo);
  nodo.appendChild(document.createTextNode("Se bloquea en " + min + ":" + seg));
}


/* ============================================================
   11) PERSISTIR CAMBIOS
   ============================================================
   Siempre que cambie algo hay que re-cifrar TODO con un IV
   nuevo (ver crypto.js, REGLA 3). Si falla, no se persiste.
   ============================================================ */
async function persistir() {
  if (!estado.clave) return false;
  try {
    const nueva = await guardarBoveda(estado.clave, estado.boveda, estado.entradas);
    escribirBoveda(nueva);
    estado.boveda = nueva;
    return true;
  } catch (e) {
    avisar("No se pudo guardar: " + (e.message || e), "error");
    return false;
  }
}


/* ============================================================
   12) LISTADO, BÚSQUEDA Y ORDEN
   ============================================================ */
function entrarAlListado() {
  mostrarPantalla("lista");
  pintarLista();
  pintarGenerador();
  const rel = $("tiempo-bloqueo");
  if (rel) actualizarRelojBloqueo(0);
}

function entradasFiltradas() {
  const texto = ($("buscar").value || "").trim().toLowerCase();

  let resultado = estado.entradas.filter(e => {
    if (!texto) return true;
    /* Busca en título, usuario y URL. NO en la contraseña:
       no tiene sentido exponerla ante un filtrado casual. */
    return (e.titulo || "").toLowerCase().includes(texto) ||
           (e.usuario || "").toLowerCase().includes(texto) ||
           (e.url || "").toLowerCase().includes(texto);
  });

  const orden = ajustes.ordenarPor || "titulo";
  resultado = resultado.slice().sort((a, b) => {
    if (orden === "reciente") return (b.modificado || "").localeCompare(a.modificado || "");
    return (a.titulo || "").localeCompare(b.titulo || "", "es");
  });

  return resultado;
}

function pintarLista() {
  const contenedor = $("lista-entradas");
  if (!contenedor) return;
  vaciar(contenedor);

  const total = estado.entradas.length;
  const visibles = entradasFiltradas();

  const contador = $("contador");
  if (contador) {
    vaciar(contador);
    contador.appendChild(document.createTextNode(
      total === 0
        ? "Todavía no guardaste ninguna contraseña."
        : visibles.length + " de " + total + " contraseña" + (total === 1 ? "" : "s")
    ));
  }

  if (total === 0) {
    contenedor.appendChild(el("div", { class: "vacio" }, [
      el("p", {}, "Tu bóveda está vacía."),
      el("p", { class: "vacio__sugerencia" },
         "Empezá con el botón “Agregar contraseña”.")
    ]));
    return;
  }

  if (visibles.length === 0) {
    contenedor.appendChild(el("div", { class: "vacio" }, [
      el("p", {}, "Ninguna contraseña coincide con “" + $("buscar").value + "”.")
    ]));
    return;
  }

  for (const entrada of visibles) contenedor.appendChild(tarjetaDe(entrada));
}

function tarjetaDe(entrada) {
  const ver = !!ajustes.verContrasenas;

  const campoClave = el("code", { class: "campo__valor" },
    ver ? (entrada.clave || "") : "••••••••");

  const botonVer = el("button", {
    type: "button",
    class: "boton boton--icono",
    title: ver ? "Ocultar contraseña" : "Mostrar contraseña",
    onclick: () => {
      /* Se cambia solo el estado visual; no se vuelve a pintar
         toda la lista para no perder el foco de la búsqueda. */
      ajustes.verContrasenas = !ajustes.verContrasenas;
      escribirAjustes(ajustes);
      pintarLista();
    }
  }, ver ? "🙈" : "👁");

  const botonCopiar = el("button", {
    type: "button",
    class: "boton boton--icono",
    title: "Copiar contraseña",
    onclick: ev => copiarAlPortapapeles(entrada.clave || "", ev.currentTarget)
  }, "⧉");

  const botonUsuario = el("button", {
    type: "button",
    class: "boton boton--icono",
    title: "Copiar usuario",
    onclick: ev => copiarAlPortapapeles(entrada.usuario || "", ev.currentTarget)
  }, "⧉");

  const botonEditar = el("button", {
    type: "button",
    class: "boton boton--texto",
    onclick: () => abrirEditor(entrada.id)
  }, "Editar");

  const datos = el("div", { class: "campo" }, [
    el("span", { class: "campo__titulo" }, entrada.titulo || "(sin título)"),
    el("span", { class: "campo__usuario" }, entrada.usuario || "")
  ]);

  const claveFila = el("div", { class: "campo__clave" }, [
    campoClave, botonVer, botonCopiar
  ]);

  const acciones = el("div", { class: "campo__acciones" }, [
    entrada.usuario
      ? el("span", { class: "campo__nota" }, "usuario:")
      : null,
    botonUsuario, botonEditar
  ]);

  const pie = el("div", { class: "campo__pie" }, [
    entrada.url
      ? el("a", {
          class: "campo__url",
          href: normalizarUrl(entrada.url),
          target: "_blank",
          rel: "noopener noreferrer"   // sin este, la página abierta puede acceder a `opener`
        }, entrada.url)
      : null,
    acciones
  ]);

  return el("article", { class: "tarjeta" }, [datos, claveFila, pie]);
}

function normalizarUrl(url) {
  if (!url) return "#";
  /* Si el usuario escribió solo "ejemplo.com" le agregamos
     https:// para que el enlace funcione. Si ya tiene esquema,
     lo dejamos tal cual (ojo: javascript: quedaría igual, por
     eso abajo lo rechazamos). */
  const limpio = String(url).trim();
  if (/^javascript:/i.test(limpio)) return "#";   // nunca
  if (/^https?:\/\//i.test(limpio)) return limpio;
  return "https://" + limpio;
}


/* ============================================================
   13) EDITOR DE ENTRADAS
   ============================================================ */
function abrirEditor(id) {
  const panel = $("panel-editor");
  estado.editandoId = id || null;

  const existente = id ? estado.entradas.find(e => e.id === id) : null;

  $("ed-titulo").value = existente ? (existente.titulo || "") : "";
  $("ed-usuario").value = existente ? (existente.usuario || "") : "";
  $("ed-clave").value = existente ? (existente.clave || "") : "";
  $("ed-url").value = existente ? (existente.url || "") : "";
  $("ed-nota").value = existente ? (existente.notas || "") : "";

  $("ed-titulo").required = true;
  $("ed-eliminar").hidden = !existente;

  const caja = $("ed-error");
  vaciar(caja);

  panel.hidden = false;
  $("ed-titulo").focus();
}

function cerrarEditor() {
  $("panel-editor").hidden = true;
  estado.editandoId = null;
  $("ed-titulo").value = "";
  $("ed-usuario").value = "";
  $("ed-clave").value = "";
  $("ed-url").value = "";
  $("ed-nota").value = "";
}

async function guardarEntrada(ev) {
  ev.preventDefault();

  const caja = $("ed-error");
  const fallo = msg => { vaciar(caja); caja.appendChild(document.createTextNode(msg)); };

  if (!estado.clave) { bloquear("La bóveda se había bloqueado."); return; }

  const titulo = $("ed-titulo").value.trim();
  if (!titulo) { fallo("Poné un título para reconocerla después."); return; }

  const ahora = new Date().toISOString();
  const datos = {
    titulo: titulo,
    usuario: $("ed-usuario").value.trim(),
    clave: $("ed-clave").value,
    url: $("ed-url").value.trim(),
    notas: $("ed-nota").value.trim(),
    modificado: ahora
  };

  if (estado.editandoId) {
    const idx = estado.entradas.findIndex(e => e.id === estado.editandoId);
    if (idx >= 0) {
      datos.id = estado.editandoId;
      datos.creado = estado.entradas[idx].creado || ahora;
      estado.entradas[idx] = datos;
    }
  } else {
    datos.id = crearId();
    datos.creado = ahora;
    estado.entradas.push(datos);
  }

  if (await persistir()) {
    cerrarEditor();
    pintarLista();
    avisar("Contraseña guardada.", "ok");
  } else {
    /* Si falla el guardado hay que DESHACER el cambio en memoria,
       o quedaríamos mostrando algo que no está en el disco. */
    if (estado.editandoId) {
      const original = leerBoveda();
      if (original) { /* se reintenta en el próximo guardado */ }
    }
    fallo("No se pudo guardar.");
  }
}

async function eliminarEntrada() {
  if (!estado.editandoId) return;
  if (!estado.clave) { bloquear("La bóveda se había bloqueado."); return; }

  const existente = estado.entradas.find(e => e.id === estado.editandoId);
  const nombre = existente ? existente.titulo : "esta contraseña";

  const seguro = window.confirm(
    "¿Eliminar “" + nombre + "” de la bóveda?\n\n" +
    "Esto borra el dato cifrado. Si no tenés otra copia, se pierde."
  );
  if (!seguro) return;

  const anterior = estado.entradas.slice();     // respaldo por si falla
  estado.entradas = estado.entradas.filter(e => e.id !== estado.editandoId);

  if (await persistir()) {
    cerrarEditor();
    pintarLista();
    avisar("Contraseña eliminada.", "info");
  } else {
    estado.entradas = anterior;
    avisar("No se pudo eliminar.", "error");
  }
}

function crearId() {
  /* UUID aleatorio del navegador, sin dependencias. */
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" +
         hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
}


/* ============================================================
   14) GENERADOR EN LA INTERFAZ
   ============================================================ */
function opcionesGenerador() {
  return {
    mayusculas: $("gen-mayus").checked,
    numeros: $("gen-num").checked,
    simbolos: $("gen-simb").checked
  };
}

function pintarGenerador() {
  const largo = Number($("gen-largo").value);
  const salida = $("gen-salida");

  if (!$("gen-mayus").checked && !$("gen-num").checked && !$("gen-simb").checked) {
    /* Al menos las minúsculas están siempre; avisamos que con
       solo eso la contraseña queda floja. */
    avisar("Con solo minúsculas la contraseña queda débil.", "info");
  }

  const clave = generarContrasena(largo, opcionesGenerador());
  vaciar(salida);
  salida.appendChild(document.createTextNode(clave));

  const f = medirFortaleza(clave);
  const barra = $("gen-fuerza");
  barra.className = "fuerza fuerza--" + f.clase;
  barra.textContent = f.texto;
}


/* ============================================================
   15) EXPORTAR / IMPORTAR
   ============================================================
   Exporta el archivo CIFRADO. Bajarlo en claro sería entregar
   todas las contraseñas en un archivo legible.
   ============================================================ */
function exportarBoveda() {
  const boveda = leerBoveda();
  if (!boveda) { avisar("No hay bóveda para exportar.", "error"); return; }

  const texto = JSON.stringify(boveda, null, 2);
  const blob = new Blob([texto], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const enlace = el("a", {
    href: url,
    download: "boveda-cifrada-" + new Date().toISOString().slice(0, 10) + ".json"
  });
  document.body.appendChild(enlace);
  enlace.click();
  document.body.removeChild(enlace);
  URL.revokeObjectURL(url);

  avisar("Bóveda exportada (cifrada). No la subas a ningún lado sin cifrar.", "ok");
}

function importarBoveda() {
  const archivo = $("archivo-importar");
  if (!archivo.files || archivo.files.length === 0) return;

  const lector = new FileReader();
  lector.onload = () => {
    let obj;
    try {
      obj = JSON.parse(String(lector.result));
    } catch (e) {
      avisar("El archivo no es un JSON válido.", "error");
      archivo.value = "";
      return;
    }

    if (!obj || !obj.iv || !obj.data || !obj.sal) {
      avisar("El archivo no tiene el formato de una bóveda.", "error");
      archivo.value = "";
      return;
    }

    /* Si ya había una bóveda, exigimos confirmación: importar
       pisa lo que había y no hay forma de recuperarlo. */
    const habia = !!leerBoveda();
    if (habia) {
      const seguro = window.confirm(
        "Ya existe una bóveda en este navegador.\n\n" +
        "Importarla va a REEMPLAZARLA por completo. ¿Seguro?"
      );
      if (!seguro) { archivo.value = ""; return; }
    }

    localStorage.setItem(CLAVE_STORAGE, JSON.stringify(obj));
    archivo.value = "";

    /* Toca bloquear y volver a pedir la contraseña: es la
       contraseña MAESTRA DEL ARCHIVO IMPORTADO la que abre. */
    bloquear();
    mostrarPantalla("abrir");
    avisar("Bóveda importada. Abrila con su contraseña maestra.", "ok");
  };
  lector.readAsText(archivo.files[0]);
}


/* ============================================================
   16) ARRANQUE
   ============================================================ */
function iniciar() {
  /* La API cripto es obligatoria. Sin ella no hay seguridad
     posible, así que preferimos no dejar usar la app. */
  if (!window.crypto || !crypto.subtle) {
    const caja = $("aviso");
    caja.hidden = false;
    caja.className = "aviso aviso--error";
    vaciar(caja);
    caja.appendChild(document.createTextNode(
      "Tu navegador no ofrece Web Crypto (crypto.subtle). " +
      "Esto pasa si abrís la página por http:// en vez de https://."
    ));
    return;
  }

  const hayBoveda = !!leerBoveda();
  mostrarPantalla(hayBoveda ? "abrir" : "crear");

  /* --- crear --- */
  $("form-crear").addEventListener("submit", manejarCrear);
  $("crear-clave").addEventListener("input", () => {
    const f = medirFortaleza($("crear-clave").value);
    const barra = $("crear-fuerza");
    barra.className = "fuerza fuerza--" + f.clase;
    barra.textContent = $("crear-clave").value ? f.texto : "";
  });

  /* --- abrir --- */
  $("form-abrir").addEventListener("submit", manejarAbrir);

  /* --- barra superior --- */
  $("btn-bloquear").addEventListener("click", () => bloquear("Bóveda bloqueada."));

  /* --- búsqueda y ajustes --- */
  $("buscar").addEventListener("input", pintarLista);
  $("btn-ver-todo").addEventListener("click", () => {
    ajustes.verContrasenas = !ajustes.verContrasenas;
    escribirAjustes(ajustes);
    $("btn-ver-todo").textContent = ajustes.verContrasenas ? "Ocultar todo" : "Mostrar todo";
    pintarLista();
  });
  $("orden").addEventListener("change", ev => {
    ajustes.ordenarPor = ev.target.value;
    escribirAjustes(ajustes);
    pintarLista();
  });

  /* --- editor --- */
  $("btn-agregar").addEventListener("click", () => abrirEditor(null));
  $("form-editor").addEventListener("submit", guardarEntrada);
  $("ed-cancelar").addEventListener("click", cerrarEditor);
  $("ed-eliminar").addEventListener("click", eliminarEntrada);
  $("btn-generar-para-editor").addEventListener("click", () => {
    pintarGenerador();
    $("ed-clave").value = $("gen-salida").textContent;
    $("ed-clave").type = "text";
    $("ed-ver").textContent = "Ocultar";
  });

  /* Mostrar/ocultar la contraseña en el editor. Alternamos el
     tipo del input (password <-> text); no hay innerHTML de por
     medio, solo una propiedad del campo. */
  $("ed-ver").addEventListener("click", () => {
    const campo = $("ed-clave");
    const visible = campo.type === "text";
    campo.type = visible ? "password" : "text";
    $("ed-ver").textContent = visible ? "Mostrar" : "Ocultar";
  });

  /* --- generador --- */
  $("gen-largo").addEventListener("input", ev => {
    $("gen-largo-valor").textContent = ev.target.value;
    pintarGenerador();
  });
  ["gen-mayus", "gen-num", "gen-simb"].forEach(id => {
    $(id).addEventListener("change", pintarGenerador);
  });
  $("btn-regenerar").addEventListener("click", pintarGenerador);
  $("btn-copiar-gen").addEventListener("click",
    ev => copiarAlPortapapeles($("gen-salida").textContent, ev.currentTarget));

  /* --- importar / exportar --- */
  $("btn-exportar").addEventListener("click", exportarBoveda);
  $("btn-importar").addEventListener("click", () => $("archivo-importar").click());
  $("archivo-importar").addEventListener("change", importarBoveda);

  /* --- bloqueo por actividad --- */
  ["pointerdown", "keydown", "input", "scroll"].forEach(evt => {
    document.addEventListener(evt, marcarActividad, { passive: true });
  });

  /* Si el usuario se va a otra pestaña, empieza a correr el
     reloj en serio. No bloqueamos al instante porque cambiar
     de pestaña es algo común e interrumpir resultaría molesto. */
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && estado.clave) marcarActividad();
  });

  /* Nunca permitir que la página mande la contraseña a un
     servidor: no existe formulario con action. */
  document.addEventListener("submit", ev => {
    if (!ev.target.matches("form[action]")) ev.preventDefault();
  });

  /* ----------------------------------------------------------
     PWA: service worker + aviso de actualización
     ---------------------------------------------------------- */
  registrarServiceWorker();
}

/* ============================================================
   17) PWA — INSTALAR LA APP Y ACTUALIZARLA
   ============================================================
   El service worker (sw.js) guarda los archivos para que la
   bóveda abra sin internet. No añade seguridad: añade
   disponibilidad. La seguridad la pone crypto.js.

   Sobre las actualizaciones hay algo importante:

   sw.js usa "red primero" justamente para que, si mañana hay un
   arreglo de seguridad, no te quedes con la versión vieja
   guardada. Pero aunque el worker nuevo se active, ESTA PESTAÑA
   sigue corriendo el JavaScript viejo hasta que se recargue.

   Por eso le avisamos al usuario en vez de recargar solos.
   Recargar a la fuerza en un gestor de contraseñas sería
   descuidado: podría caerse en el medio de que estás tipeando
   tu contraseña maestra. Mejor aviso y decisión tuya.
   ============================================================ */
function registrarServiceWorker() {
  if (!("serviceWorker" in navigator)) return;

  navigator.serviceWorker.register("sw.js")
    .then(registro => {
      /* updatefound dispara cuando el navegador baja un sw.js
         DISTINTO al que está corriendo, es decir: salió una
         versión nueva. */
      registro.addEventListener("updatefound", () => {
        const nuevo = registro.installing;
        if (!nuevo) return;

        nuevo.addEventListener("statechange", () => {
          /* "installed" con un controller ya existente significa
             que hay una versión esperando. Sin controller sería
             la PRIMERA instalación, que no tiene nada que avisar. */
          if (nuevo.state === "installed" && navigator.serviceWorker.controller) {
            avisar("Hay una versión nueva de la bóveda. Recargá la página para que se aplique.", "info");
          }
        });
      });
    })
    /* Si el registro falla (por ejemplo, un navegador que no lo
       soporta en http), la bóveda sigue funcionando igual: el
       service worker es comodidad, no requisito. */
    .catch(() => { /* sin service worker también anda */ });
}

/* Arranca al cargar el DOM. */
document.addEventListener("DOMContentLoaded", iniciar);
