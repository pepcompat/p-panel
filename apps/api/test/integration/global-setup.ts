import { PrismaClient } from '@prisma/client';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { TEST_DATABASE_URL, ADMIN_DATABASE_URL, TEST_DB_NAME } from './env';

/** Test tooling only: creates `ppanel_test` if missing and applies committed migrations. */
export default async function setup(): Promise<void> {
  const admin = new PrismaClient({ datasourceUrl: ADMIN_DATABASE_URL });
  try {
    const rows = await admin.$queryRaw<Array<{ exists: boolean }>>`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = ${TEST_DB_NAME}) AS "exists"`;
    if (!rows[0]?.exists) await admin.$executeRawUnsafe(`CREATE DATABASE "${TEST_DB_NAME}"`);
  } finally {
    await admin.$disconnect();
  }
  const root = path.resolve(__dirname, '../..');
  execFileSync(path.join(root, 'node_modules/.bin/prisma'), ['migrate', 'deploy'], {
    cwd: root,
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
    stdio: 'pipe',
  });
}
