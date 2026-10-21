/* Configuración flat de ESLint (formato ESLint 9+/10, NO .eslintrc).
   Reglas recomendadas de @eslint/js + entornos explícitos por tipo
   de archivo, y eslint-config-prettier AL FINAL para que ESLint no
   emita reglas de formato que peleen con Prettier. */
import js from "@eslint/js";
import globals from "globals";
import prettier from "eslint-config-prettier";

export default [
  /* El binario de eslint y el eslint.config.js no son código del sitio */
  { ignores: ["node_modules/**", "*.comentado.*", "src/**/*.comentado.*"] },

  js.configs.recommended,

  /* Lógica de la app (módulos ESM en navegador) y tests futuros */
  {
    files: ["src/**/*.js", "tests/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser
      }
    }
  },

  /* sw.js es un service worker CLÁSICO (no módulo): su global es
     `self`, no `window`. Se incluye `browser` además de
     `serviceworker` porque comparten APIs web (URL, Response...). */
  {
    files: ["sw.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        ...globals.browser,
        ...globals.serviceworker
      }
    }
  },

  /* Este archivo corre en Node durante `npm run lint` */
  {
    files: ["eslint.config.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.node
      }
    }
  },

  /* Siempre al final: desactiva reglas de estilo que ya resuelve
     Prettier (`npm run format`). */
  prettier
];
