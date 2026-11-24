import type { PrismaService } from '../../../apps/api/src/common/prisma.service';

export async function userTables(prisma: PrismaService): Promise<string[]> {
  const rows = await prisma.$queryRaw<Array<{ table_name: string }>>`
    SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> '_prisma_migrations'
     ORDER BY table_name`;
  return rows.map((r) => r.table_name);
}

/** md5 per table over every row (text form). Used for "no state change" assertions. */
export async function snapshot(
  prisma: PrismaService,
  exclude: string[] = ['audit_events'],
): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const t of await userTables(prisma)) {
    if (exclude.includes(t)) continue;
    // table names come from information_schema (not user input)
    const r = await prisma.$queryRawUnsafe<Array<{ h: string | null }>>(
      `SELECT md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) AS h FROM "${t}" x`,
    );
    out[t] = r[0]?.h ?? '';
  }
  return out;
}

export function diff(a: Record<string, string>, b: Record<string, string>): string[] {
  return Object.keys({ ...a, ...b }).filter((k) => a[k] !== b[k]);
}
