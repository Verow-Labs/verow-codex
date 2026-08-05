import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { ignores: ['dist/**', 'fixtures/**'] },
  {
    languageOptions: {
      globals: {
        Buffer: 'readonly',
        process: 'readonly',
        TextDecoder: 'readonly',
        URL: 'readonly',
      },
    },
  },
);
