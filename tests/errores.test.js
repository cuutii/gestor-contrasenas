import { describe, it, expect } from "vitest";
import { crearBoveda, abrirBoveda } from "../src/crypto.js";

const CONTRASENA = "Ma3stra!faltante-de-prueba-ZXCV90";

async function errorDe(promesa) {
  try {
    await promesa;
  } catch (e) {
    return e;
  }
  throw new Error("Se esperaba un rechazo y la promesa se resolvió");
}

function base64Abytes(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

function bytesAbase64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

/* Cifra un payload arbitrario con la clave viva devuelta por crearBoveda.
   Solo se usa para fabricar bóvedas con contenido inválido y comprobar
   que la API pública rechaza las dos formas de datos corruptos. */
async function cifrarCon(clave, textoPlano) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    clave,
    new TextEncoder().encode(textoPlano)
  );
  return { iv: bytesAbase64(iv), data: bytesAbase64(new Uint8Array(buffer)) };
}

describe("validaciones de entrada", () => {
  it("crearBoveda sin contraseña → FALTA_CONTRASENA", async () => {
    for (const invalida of ["", null, undefined, 42, {}]) {
      const err = await errorDe(crearBoveda(invalida));
      expect(err.message).toBe("FALTA_CONTRASENA");
    }
  });

  it("abrirBoveda sin bóveda → NO_HAY_BOVEDA", async () => {
    for (const invalida of [null, undefined, "texto", 42]) {
      const err = await errorDe(abrirBoveda(CONTRASENA, invalida));
      expect(err.message).toBe("NO_HAY_BOVEDA");
    }
  });
});

describe("contraseña incorrecta", () => {
  it("rechaza con CONTRASENA_INCORRECTA", async () => {
    const { boveda } = await crearBoveda(CONTRASENA);
    const err = await errorDe(
      abrirBoveda("otra-contraseña-distinta-9876", boveda)
    );

    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe("CONTRASENA_INCORRECTA");
  });

  it("una contraseña casi idéntica también falla", async () => {
    const { boveda } = await crearBoveda(CONTRASENA);
    const err = await errorDe(abrirBoveda(CONTRASENA + " ", boveda));
    expect(err.message).toBe("CONTRASENA_INCORRECTA");
  });
});

describe("datos alterados", () => {
  it("un byte cambiado en 'data' con la contraseña CORRECTA es rechazado", async () => {
    const { boveda } = await crearBoveda(CONTRASENA);

    const bytes = base64Abytes(boveda.data);
    bytes[0] ^= 0xff;
    const alterada = { ...boveda, data: bytesAbase64(bytes) };

    const err = await errorDe(abrirBoveda(CONTRASENA, alterada));

    /* COMPORTAMIENTO REAL (documentado, no forzado):
       descifrarObjeto() mapea TODO OperationError de AES-GCM a
       CONTRASENA_INCORRECTA, incluida la manipulación del ciphertext.
       El código comenta esto deliberadamente ("contraseña maestra
       incorrecta o archivo corrupto/manipulado").
       ⇒ Alterar `data` NO produce DATOS_CORRUPTOS: el tag GCM falla
         antes de llegar a JSON.parse. La causa original queda en .cause */
    expect(err.message).toBe("CONTRASENA_INCORRECTA");
    expect(err.cause).toBeDefined();
    expect(err.cause.name).toBe("OperationError");
  });
});

describe("DATOS_CORRUPTOS (vías alcanzables con la API pública)", () => {
  it("el payload cifrado descifra bien pero no trae un arreglo en 'entradas'", async () => {
    const { clave, boveda } = await crearBoveda(CONTRASENA);
    const { iv, data } = await cifrarCon(
      clave,
      JSON.stringify({ entradas: "no soy un arreglo" })
    );

    const err = await errorDe(abrirBoveda(CONTRASENA, { ...boveda, iv, data }));
    expect(err.message).toBe("DATOS_CORRUPTOS");
  });

  it("el payload cifrado descifra pero el JSON es inválido", async () => {
    const { clave, boveda } = await crearBoveda(CONTRASENA);
    const { iv, data } = await cifrarCon(clave, "{esto-no-es-json");

    const err = await errorDe(abrirBoveda(CONTRASENA, { ...boveda, iv, data }));
    expect(err.message).toBe("DATOS_CORRUPTOS");
  });
});
