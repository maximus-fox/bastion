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
    // popup.html loads i18n.js before popup.js
    files: ['popup.js'],
    languageOptions: {
      globals: { LANGS: 'readonly', currentLang: 'writable', t: 'readonly', setLang: 'readonly', gradeDesc: 'readonly' },
    },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: globals.node },
  },
  {
    // page.evaluate() callbacks run in the browser
    files: ['tests/**/*.mjs'],
    languageOptions: { globals: globals.browser },
  },
];
