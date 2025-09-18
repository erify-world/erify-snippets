module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
  ],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { 'argsIgnorePattern': '^_' }],
    '@typescript-eslint/no-explicit-any': 'off', // Allow any for complex integrations
    'no-unused-vars': 'off', // Use TypeScript version instead
  },
  env: {
    node: true,
    jest: true,
    es2022: true,
  },
  ignorePatterns: ['dist/', 'node_modules/', 'docs/'],
};