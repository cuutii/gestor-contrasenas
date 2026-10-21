import { describe, it, expect } from "vitest";
import { crearBoveda, guardarBoveda, abrirBoveda } from "../src/crypto.js";

/* ============================================================
   FIXTURES
   Valores largos y distintivos: si aparecieran en el JSON
   persistido sería un fallo, y la probabilidad de que el
   base64 aleatorio los contenga por accidente es despreciable.
   ============================================================ */
const CONTRASENA = "Ma3stra!faltante-de-prueba-ZXCV90";

const ENTRADA = {
  id: "id-test-7734",
  titulo: "Bóveda-TEST-título-ÚNICO-7734",
  usuario: "ana.loyola.prueba@correo-TEST-8842.example",
  clave: "S3cr3ta!clave-NO-DEBE-APARECER-#2026",
  url: "https://ejemplo-prueba.example/login",
  notas: "nota-secreta-NOTA-PRUEBA-31415",
  creado: "2026-01-01T00:00:00.000Z",
  modificado: "2026-01-01T00:00:00.000Z"
};

function base64Abytes(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

describe("round-trip: crear → guardar → abrir", () => {
  it("la entrada vuelve idéntica con la misma contraseña", async () => {
    const { boveda, clave } = await crearBoveda(CONTRASENA);
    const persistida = await guardarBoveda(clave, boveda, [ENTRADA]);

    const { entradas, clave: claveAbierta } = await abrirBoveda(
      CONTRASENA,
      persistida
    );

    expect(entradas).toStrictEqual([ENTRADA]);

    /* La clave re-derivada debe seguir siendo NO exportable (REGLA 2) */
    expect(claveAbierta.extractable).toBe(false);
    expect(claveAbierta.usages).toEqual(
      expect.arrayContaining(["decrypt", "encrypt"])
    );
  });

  it("una bóveda recién creada abre vacía", async () => {
    const { boveda } = await crearBoveda(CONTRASENA);
    const { entradas } = await abrirBoveda(CONTRASENA, boveda);
    expect(entradas).toStrictEqual([]);
  });

  it("si falta el campo 'iter' cae en el default 600000 y la bóveda igual abre", async () => {
    const { boveda } = await crearBoveda(CONTRASENA);
    const sinIter = { ...boveda };
    delete sinIter.iter;

    const { entradas } = await abrirBoveda(CONTRASENA, sinIter);
    expect(entradas).toStrictEqual([]);
  });
});

describe("datos en claro: el JSON listo para persistir", () => {
  it("NO contiene título, usuario/email, contraseña de la entrada ni la contraseña maestra", async () => {
    const { boveda, clave } = await crearBoveda(CONTRASENA);
    const persistida = await guardarBoveda(clave, boveda, [ENTRADA]);

    /* Esto es exactamente lo que app.js escribe en localStorage
       con JSON.stringify(boveda). */
    const json = JSON.stringify(persistida);

    /* Contralé positivo: si la búsqueda no funcionara, este sí fallaría */
    expect(JSON.stringify([ENTRADA])).toContain(ENTRADA.titulo);
    expect(JSON.stringify([ENTRADA])).toContain(ENTRADA.clave);

    /* Negativos: nada de lo sensible aparece en el texto persistido */
    expect(json).not.toContain(ENTRADA.titulo);
    expect(json).not.toContain(ENTRADA.usuario);
    expect(json).not.toContain(ENTRADA.clave);
    expect(json).not.toContain(ENTRADA.url);
    expect(json).not.toContain(ENTRADA.notas);
    expect(json).not.toContain(CONTRASENA);

    /* Estructural: las entradas no quedan como campo propio de la bóveda */
    expect(Object.hasOwn(persistida, "entradas")).toBe(false);
  });

  it("el cifrado es reversible: la entrada sale igual por el otro lado", async () => {
    const { boveda, clave } = await crearBoveda(CONTRASENA);
    const persistida = await guardarBoveda(clave, boveda, [ENTRADA]);
    const { entradas } = await abrirBoveda(CONTRASENA, persistida);
    expect(entradas[0].clave).toBe(ENTRADA.clave);
    expect(entradas[0].usuario).toBe(ENTRADA.usuario);
  });
});

describe("metadatos de la bóveda persistida", () => {
  it("trae v, kdf, hash, iter, sal, iv y data con los valores esperados", async () => {
    const { boveda, clave } = await crearBoveda(CONTRASENA);
    const persistida = await guardarBoveda(clave, boveda, [ENTRADA]);

    expect(persistida.v).toBe(1);
    expect(persistida.kdf).toBe("PBKDF2");
    expect(persistida.hash).toBe("SHA-256");
    expect(persistida.iter).toBe(600000);

    /* Claves exactas del objeto persistido */
    expect(Object.keys(persistida).sort()).toEqual([
      "data",
      "hash",
      "iter",
      "iv",
      "kdf",
      "sal",
      "v"
    ]);

    /* Todo lo opaco viene en base64 válido */
    const base64 = /^[A-Za-z0-9+/]+={0,2}$/;
    expect(persistida.sal).toMatch(base64);
    expect(persistida.iv).toMatch(base64);
    expect(persistida.data).toMatch(base64);

    /* Longitudes: sal = 16 bytes (128 bits), iv = 12 bytes (96 bits) */
    expect(base64Abytes(persistida.sal).length).toBe(16);
    expect(base64Abytes(persistida.iv).length).toBe(12);

    /* data = JSON cifrado + tag de autenticación GCM de 16 bytes */
    const plano = new TextEncoder().encode(
      JSON.stringify({ entradas: [ENTRADA] })
    );
    expect(base64Abytes(persistida.data).length).toBe(plano.length + 16);

    /* guardarBoveda preserva los metadatos de la bóveda original */
    expect(persistida.kdf).toBe(boveda.kdf);
    expect(persistida.sal).toBe(boveda.sal);
    expect(persistida.iter).toBe(boveda.iter);
  });
});

describe("IV nuevo en cada guardado (REGLA 3)", () => {
  it("dos guardados del mismo contenido producen iv y data distintos", async () => {
    const { boveda, clave } = await crearBoveda(CONTRASENA);

    const a = await guardarBoveda(clave, boveda, [ENTRADA]);
    const b = await guardarBoveda(clave, boveda, [ENTRADA]);

    expect(a.iv).not.toBe(b.iv);
    expect(a.data).not.toBe(b.data);
    expect(a.sal).toBe(b.sal); /* la sal es por bóveda, no por guardado */
  });
});
