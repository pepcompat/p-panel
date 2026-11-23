/**
 * Dev seeder (team standard). Refuses to run when NODE_ENV=production.
 * Users (password `password`): superadmin=platform_owner, admin=ops_admin, dev=deployer, user1=viewer — all global.
 */
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';

function uuidv7(): string {
  const b = randomBytes(16);
  const ts = BigInt(Date.now());
  for (let i = 0; i < 6; i++) b[i] = Number((ts >> BigInt(8 * (5 - i))) & 0xffn);
  b[6] = (b[6]! & 0x0f) | 0x70;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export const SEED_USERS = [
  { name: 'superadmin', displayName: 'Super Admin', role: 'platform_owner' },
  { name: 'admin', displayName: 'Ops Admin', role: 'ops_admin' },
  { name: 'dev', displayName: 'Developer', role: 'deployer' },
  { name: 'user1', displayName: 'Viewer One', role: 'viewer' },
] as const;

export async function seed(prisma: PrismaClient): Promise<void> {
  if (process.env.NODE_ENV === 'production')
    throw new Error('[seed] refusing to seed: NODE_ENV=production');
  const passwordHash = await argon2.hash('password', {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });
  for (const u of SEED_USERS) {
    const email = `${u.name}@ppanel.local`;
    const user = await prisma.user.upsert({
      where: { email },
      create: { id: uuidv7(), email, displayName: u.displayName, passwordHash },
      update: {},
    });
    const has = await prisma.roleBinding.findFirst({
      where: { userId: user.id, roleKey: u.role, scopeType: 'global' },
    });
    if (!has)
      await prisma.roleBinding.create({
        data: { id: uuidv7(), userId: user.id, roleKey: u.role, scopeType: 'global' },
      });
  }
}

const isCli = /seed\.[cm]?[tj]s$/.test(process.argv[1] ?? '');
if (isCli) {
  for (const f of [path.join(__dirname, '../.env'), path.join(__dirname, '../../../.env')])
    if (existsSync(f)) process.loadEnvFile(f);
  if (process.env.NODE_ENV === 'production') {
    console.error('[seed] refusing to seed: NODE_ENV=production');
    process.exit(1);
  }
  const prisma = new PrismaClient();
  seed(prisma)
    .then(() =>
      console.log(
        `[seed] ok: ${SEED_USERS.map((u) => `${u.name}@ppanel.local`).join(', ')} (password: "password")`,
      ),
    )
    .catch((e: unknown) => {
      console.error('[seed] failed', e);
      process.exitCode = 1;
    })
    .finally(() => void prisma.$disconnect());
}
