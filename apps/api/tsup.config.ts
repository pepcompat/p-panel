import { defineConfig } from 'tsup';

// Bundles the workspace-only @ppanel/shared-contracts (TS source) into the output; all npm deps stay external.
// tsup switches to SWC automatically because tsconfig has emitDecoratorMetadata (required by NestJS DI).
export default defineConfig({
  entry: { main: 'src/main.ts' },
  format: ['cjs'],
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  sourcemap: true,
  clean: true,
  splitting: false,
  noExternal: ['@ppanel/shared-contracts'],
  tsconfig: 'tsconfig.json',
});
