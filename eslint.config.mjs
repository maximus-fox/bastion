import js from '@eslint/js';
import globals from 'globals';

// Extension files are classic scripts (no bundler), so top-level declarations
// are globals shared within their context. Lint for real bugs, not style.
const scriptRules = {
  'no-unused-vars': ['warn', { vars: 'local', args: 'none', caughtErrors: 'none' }],
  'no-empty': ['warn', { allowEmptyCatch: true }],
  'no-useless-assignment': 'warn',
};

export default [
  { ignores: ['node_modules/', '*.zip'] },
  js.configs.recommended,
  {
    files: ['*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
      globals: { ...globals.browser, ...globals.webextensions },
    },
    rules: scriptRules,
  },
  {
    files: ['background.js'],
    languageOptions: { globals: { ...globals.serviceworker, ...globals.webextensions } },
  },
  {
    // defined in defaults.js, loaded before these scripts
    files: ['background.js', 'content.js', 'settings-preload.js', 'popup.js', 'warning.js'],
    languageOptions: { globals: { DEFAULT_SETTINGS: 'readonly' } },
  },
  {
    // popup.html and warning.html load i18n.js first
    files: ['popup.js', 'warning.js'],
    languageOptions: {
      globals: {
        LANGS: 'readonly', currentLang: 'writable', t: 'readonly', setLang: 'readonly',
        gradeDesc: 'readonly', defaultLang: 'readonly', applyLang: 'readonly',
      },
    },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: globals.node },
  },
  {
    // page.evaluate() / sw() callbacks run in the browser or the service worker
    files: ['tests/**/*.mjs'],
    languageOptions: { globals: { ...globals.browser, ...globals.webextensions, migrateSettings: 'readonly' } },
  },
];
