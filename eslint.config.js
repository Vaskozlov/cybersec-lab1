import js from '@eslint/js';
import security from 'eslint-plugin-security';
import globals from 'globals';

export default [
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { globals: globals.node },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'security/detect-object-injection': 'error',
    },
  },
];
