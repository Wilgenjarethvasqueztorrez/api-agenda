import { defineConfig } from 'eslint/config';
import globals from 'globals';
import js from '@eslint/js';
import { FlatCompat } from '@eslint/eslintrc';

const compat = new FlatCompat({
  baseDirectory: import.meta.dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all
});

export default defineConfig([{
  languageOptions: {
    globals: {
      ...globals.node,
      ...globals.jest,
    },

    ecmaVersion: 12,
    sourceType: 'module',
    parserOptions: {},
  },

  extends: compat.extends('eslint:recommended'),

  rules: {
    'indent': ['error', 2],
    'linebreak-style': ['error', 'unix'],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],

    'no-unused-vars': ['error', {
      'argsIgnorePattern': '^_',
    }],

    'no-console': 'warn',
    'prefer-const': 'error',
    'no-var': 'error',
    'object-shorthand': 'error',
    'prefer-template': 'error',
  },
}]);