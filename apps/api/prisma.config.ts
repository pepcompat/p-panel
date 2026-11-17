import { existsSync } from 'node:fs';
import path from 'node:path';
import { defineConfig } from 'prisma/config';

// prisma.config.ts disables Prisma's implicit .env loading; load it explicitly (never overrides real env).
for (const file of [path.join(__dirname, '.env'), path.join(__dirname, '../../.env')]) {
  if (existsSync(file)) process.loadEnvFile(file);
}

export default defineConfig({
  schema: path.join(__dirname, 'prisma/schema.prisma'),
  migrations: {
    path: path.join(__dirname, 'prisma/migrations'),
    seed: 'tsx prisma/seed.ts',
  },
});
