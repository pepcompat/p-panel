// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'eslint.config.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        process: 'readonly',
        __dirname: 'readonly',
        require: 'readonly',
        module: 'readonly',
        console: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // NB: no consistent-type-imports — NestJS DI needs runtime imports for emitDecoratorMetadata.
      // Security: the Center API must never spawn processes or touch docker.sock.
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'child_process', message: 'No shell/process execution in the Center API.' },
            {
              name: 'node:child_process',
              message: 'No shell/process execution in the Center API.',
            },
          ],
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'Literal[value=/docker\\.sock/]',
          message: 'No docker.sock access from the Center API.',
        },
      ],
      'no-console': 'error',
    },
  },
  {
    // test tooling (DB creation/migration) and the CLI seeder may use these
    files: ['test/**/*.ts', 'prisma/seed.ts'],
    rules: {
      'no-restricted-imports': 'off',
      'no-console': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
);
