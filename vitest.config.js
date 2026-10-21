import { defineConfig } from "vitest/config";

/* Config propia de Vitest. NO toca package.json.
   PBKDF2-SHA-256 con 600.000 iteraciones es lento a propósito:
   el suite completo realiza ~13 derivaciones de clave.
   Se amplía el timeout para que ningún test corte por lentitud. */
export default defineConfig({
  test: {
    environment: "node",
    testTimeout: 120000,
    hookTimeout: 120000
  }
});
