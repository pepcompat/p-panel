import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['test/unit/**/*.spec.ts'],
    environment: 'node',
    env: { LOG_LEVEL: 'fatal' },
  },
});
