import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { PrismaService } from '../../apps/api/src/common/prisma.service';
import { SECURITY_DATABASE_URL } from './lib/db-url';

/** Creates the isolated `ppanel_security` database if missing and applies committed migrations. */
export default async function setup(): Promise<void> {
  const url = SECURITY_DATABASE_URL;
  const dbName = new URL(url).pathname.replace(/^\//, '');
  if (!/^[a-z_]+$/.test(dbName)) throw new Error(`unexpected security DB name ${dbName}`);
  const adminUrl = url.replace(`/${dbName}?`, '/ppanel?');
  const admin = new PrismaService({ DATABASE_URL: adminUrl } as never);
  try {
    const rows = await admin.$queryRaw<
      Array<{ exists: boolean }>
    >`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = ${dbName}) AS "exists"`;
    if (!rows[0]?.exists) await admin.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
  } finally {
    await admin.$disconnect();
  }
  const api = path.resolve(__dirname, '../../apps/api');
  execFileSync(path.join(api, 'node_modules/.bin/prisma'), ['migrate', 'deploy'], {
    cwd: api,
    env: { ...process.env, DATABASE_URL: url },
    stdio: 'pipe',
  });
}
