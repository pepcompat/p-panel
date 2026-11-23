/** P6 pure helpers: schedules, path policy, target ↔ snapshot mapping, manifests, run status mapping, impact. */
import {
  BACKUP_FORBIDDEN_PATHS,
  BACKUP_MANIFEST_MAX_ENTRIES,
  type BackupManifestEntry,
  backupManifestEntrySchema,
  type BackupManifestRow,
  type BackupManifestSummary,
  type BackupPolicyTarget,
  backupRunResultSchema,
  type BackupSnapshotRef,
  type RestoreImpactItem,
  type restoreTargetSchema,
} from '@ppanel/shared-contracts';
import { Cron } from 'croner';
import type { z } from 'zod';
import { sha256Hex, stableStringify } from '../common/crypto';

export type RestoreTarget = z.infer<typeof restoreTargetSchema>;

// ---------------------------------------------------------------- schedules

export function isValidTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return tz.length > 0;
  } catch {
    return false;
  }
}

/** null when valid, else a human message. 5-field cron only (no seconds / years). */
export function scheduleError(cron: string, timezone: string): string | null {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return 'cron must have exactly 5 fields (minute hour day month weekday)';
  if (!isValidTimezone(timezone)) return `unknown IANA timezone: ${timezone}`;
  try {
    const c = new Cron(parts.join(' '), { timezone, paused: true });
    if (!c.nextRun(new Date())) return 'cron never fires';
  } catch (e) {
    return `invalid cron: ${(e as Error).message.slice(0, 200)}`;
  }
  return null;
}

/** First slot strictly after `after` (UTC Date) for cron in `timezone`. */
export function nextRunAfter(cron: string, timezone: string, after: Date): Date | null {
  const c = new Cron(cron.trim().split(/\s+/).join(' '), { timezone, paused: true });
  return c.nextRun(after) ?? null;
}

// ---------------------------------------------------------------- path policy

function under(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}/`);
}

/** Why a backup/restore path is not allowed (null = ok). Paths are already canonical (schema). */
export function pathViolation(path: string): string | null {
  if (path === '/') return 'the filesystem root contains /proc, /sys and /dev';
  const p = path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
  for (const f of BACKUP_FORBIDDEN_PATHS) {
    if (under(p, f)) return `${p} is under the forbidden path ${f}`;
    // parents of the agent's own dirs are allowed (auto-excluded); parents of pseudo-fs are not
    if (under(f, p) && !AGENT_DIRS.includes(f)) return `${p} contains the forbidden path ${f}`;
  }
  return null;
}

const AGENT_DIRS: readonly string[] = ['/var/lib/ppanel-agent', '/etc/ppanel-agent'];

/** Excludes that must be added for paths containing the agent's own state / config dirs. */
export function agentExcludes(paths: string[]): string[] {
  return AGENT_DIRS.filter((d) => paths.some((p) => under(d, p.replace(/\/$/, '')) && d !== p));
}

// ---------------------------------------------------------------- targets ↔ snapshots

export function targetLabel(t: BackupPolicyTarget): string {
  switch (t.type) {
    case 'paths':
      return t.paths.join(', ');
    case 'volume':
      return `volume ${t.app}/${t.volume}`;
    default:
      return `${t.type} ${t.app}/${t.service}/${t.database}`;
  }
}

/** Job-shape target (backupTargetSchema) of a stored policy target (drops applicationId). */
export function jobTarget(t: BackupPolicyTarget): Record<string, unknown> {
  if (t.type === 'paths') return { type: 'paths', paths: t.paths, excludes: t.excludes };
  if (t.type === 'volume') return { type: 'volume', app: t.app, volume: t.volume };
  return {
    type: t.type,
    app: t.app,
    service: t.service,
    database: t.database,
    user: t.user,
    passwordSecretKey: t.passwordSecretKey,
    ...(t.port ? { port: t.port } : {}),
  };
}

function sameTarget(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  return stableStringify(a) === stableStringify(b);
}

/**
 * Maps a backup.run result onto the dispatched targets. Returns null when the result does not prove
 * that EVERY target has a snapshot (→ the run is a failure, never `uploaded`).
 */
export function mapSnapshots(
  targets: BackupPolicyTarget[],
  output: unknown,
): {
  snapshots: BackupSnapshotRef[];
  resticVersion: string | null;
  manifest: unknown[];
  truncated: boolean;
} | null {
  const parsed = backupRunResultSchema.safeParse(output);
  if (!parsed.success) return null;
  const r = parsed.data;
  const used = new Set<number>();
  const out: BackupSnapshotRef[] = [];
  r.snapshots.forEach((s, pos) => {
    let idx: number | undefined;
    if (typeof s.target === 'number') idx = s.target;
    else if (s.target && typeof s.target === 'object') {
      const i = targets.findIndex(
        (t, j) => !used.has(j) && sameTarget(jobTarget(t), s.target as Record<string, unknown>),
      );
      idx = i >= 0 ? i : undefined;
    } else idx = pos;
    if (idx === undefined || idx >= targets.length || used.has(idx)) return;
    used.add(idx);
    out.push({
      target: idx,
      targetType: targets[idx]!.type,
      snapshotId: s.snapshotId,
      shortId: s.shortId ?? s.snapshotId.slice(0, 8),
      sizeBytes: s.sizeBytes ?? null,
      filesNew: s.filesNew ?? null,
      filesChanged: s.filesChanged ?? null,
      durationMs: s.durationMs ?? null,
    });
  });
  if (used.size !== targets.length) return null;
  out.sort((a, b) => a.target - b.target);
  return {
    snapshots: out,
    resticVersion: r.resticVersion ?? null,
    manifest: r.manifest,
    truncated: r.truncated === true,
  };
}

/**
 * Validates + bounds a run manifest (one entry per target, agent shape). Invalid entries are dropped
 * and counted; at most BACKUP_MANIFEST_MAX_ENTRIES hashed files are stored per run.
 */
export function boundManifest(
  raw: unknown[],
  agentTruncated: boolean,
): { entries: BackupManifestEntry[]; summary: BackupManifestSummary; invalid: number } {
  const entries: BackupManifestEntry[] = [];
  let invalid = 0;
  let budget = BACKUP_MANIFEST_MAX_ENTRIES;
  let truncated = agentTruncated;
  for (const e of raw.slice(0, 20)) {
    const p = backupManifestEntrySchema.safeParse(e);
    if (!p.success) {
      invalid++;
      continue;
    }
    const entry = p.data;
    if (entry.files && entry.files.length > budget) {
      entry.files = entry.files.slice(0, budget);
      entry.truncated = true;
    }
    budget -= entry.files?.length ?? 0;
    if (entry.truncated) truncated = true;
    entries.push(entry);
  }
  if (raw.length > 20) invalid += raw.length - 20;
  let files = 0;
  let bytes = 0;
  let databases = 0;
  for (const e of entries) {
    if (e.type === 'postgres' || e.type === 'mysql') {
      databases++;
      bytes += e.bytes ?? 0;
    } else {
      files += Math.max(e.fileCount, e.files?.length ?? 0);
      for (const f of e.files ?? []) bytes += f.size;
    }
  }
  return { entries, invalid, summary: { files, bytes, databases, truncated } };
}

/** Manifest entries of one target (agent shape: `target` index; snapshot id as fallback). */
export function manifestFor(
  entries: BackupManifestEntry[],
  targets: BackupPolicyTarget[],
  index: number,
  snapshotId?: string,
): BackupManifestEntry[] {
  if (!targets[index]) return [];
  return entries.filter(
    (e) => e.target === index || (snapshotId !== undefined && e.snapshotId === snapshotId),
  );
}

/** Flattened manifest rows (GET /backup-runs/:id, paginated). */
export function manifestRows(entries: BackupManifestEntry[]): BackupManifestRow[] {
  const rows: BackupManifestRow[] = [];
  for (const e of entries) {
    if (e.type === 'postgres' || e.type === 'mysql')
      rows.push({
        kind: 'database',
        target: e.target,
        snapshotId: e.snapshotId,
        database: e.database ?? '',
        bytes: e.bytes ?? 0,
        sha256: e.sha256 ?? null,
        tables: e.tables ?? [],
      });
    else
      for (const f of e.files ?? [])
        rows.push({ kind: 'file', target: e.target, snapshotId: e.snapshotId, ...f });
  }
  return rows;
}

// ---------------------------------------------------------------- restore planning

/** Does the requested restore target address the snapshot's backup target? (null = ok) */
export function restoreTargetMismatch(
  source: BackupPolicyTarget,
  target: RestoreTarget,
): string | null {
  if (source.type !== target.type)
    return `snapshot holds a ${source.type} target, not ${target.type}`;
  if (source.type === 'paths' && target.type === 'paths') {
    for (const inc of target.include) {
      if (!source.paths.some((p) => under(inc, p.replace(/\/$/, ''))))
        return `${inc} is not inside the backed-up paths`;
    }
    return null;
  }
  if (source.type === 'volume' && target.type === 'volume') {
    if (source.app !== target.app || source.volume !== target.volume)
      return `snapshot holds volume ${source.app}/${source.volume}`;
    return null;
  }
  if (
    (source.type === 'postgres' || source.type === 'mysql') &&
    (target.type === 'postgres' || target.type === 'mysql')
  ) {
    for (const k of ['app', 'service', 'database', 'user', 'passwordSecretKey'] as const)
      if (source[k] !== target[k]) return `${k} differs from the backed-up database target`;
    return null;
  }
  return 'target type mismatch';
}

export function approvalReasons(
  target: RestoreTarget,
  environment: string,
): Array<'in_place' | 'production'> {
  const out: Array<'in_place' | 'production'> = [];
  if (target.mode === 'in_place') out.push('in_place');
  if (environment === 'production') out.push('production');
  return out;
}

export function computeImpact(
  source: BackupPolicyTarget,
  target: RestoreTarget,
  ctx: { snapshotId: string; restoreId: string; appKind: string | null; manifestFiles: number },
): RestoreImpactItem[] {
  const items: RestoreImpactItem[] = [];
  const short = ctx.restoreId.replace(/-/g, '').slice(-8);
  if (target.type === 'paths') {
    const paths = target.include.length ? target.include : (source as { paths: string[] }).paths;
    for (const p of paths)
      items.push(
        target.mode === 'in_place'
          ? {
              effect: 'overwrite',
              kind: 'path',
              ref: p,
              detail: `Files under ${p} are overwritten with the snapshot ${ctx.snapshotId.slice(0, 8)} version (files not in the snapshot are kept)`,
            }
          : {
              effect: 'create',
              kind: 'path',
              ref: `<agent stateDir>/restores/${ctx.restoreId}${p}`,
              detail: `${p} is restored into an isolated staging directory (mode 0700); nothing live is touched`,
            },
      );
    if (ctx.manifestFiles)
      items.push({
        effect: 'note',
        kind: 'path',
        ref: 'manifest',
        detail: `${ctx.manifestFiles} files in the manifest will be re-hashed after the restore`,
      });
  } else if (target.type === 'volume') {
    items.push(
      target.mode === 'in_place'
        ? {
            effect: 'overwrite',
            kind: 'volume',
            ref: `ppanel-${target.app}-${target.volume}`,
            detail: 'The live volume content is replaced by the snapshot',
          }
        : {
            effect: 'create',
            kind: 'volume',
            ref: `ppanel-${target.app}-restore-${short}`,
            detail: 'A NEW volume is created from the snapshot; the live volume is not touched',
          },
    );
  } else {
    items.push(
      target.mode === 'in_place'
        ? {
            effect: 'overwrite',
            kind: 'database',
            ref: `${target.app}/${target.service}/${target.database}`,
            detail:
              'The live database is restored from the dump (DROP … IF EXISTS + CREATE per object); writes since the snapshot are lost',
          }
        : {
            effect: 'create',
            kind: 'database',
            ref: `scratch ${target.type} container (network ppanel-restore-${short})`,
            detail:
              'A temporary scratch DB container is created, the dump restored and row counts compared, then the container is removed',
          },
    );
  }
  if (target.mode === 'in_place') {
    items.push({
      effect: 'note',
      kind: 'application',
      ref: 'safety_backup',
      detail:
        'A safety backup of the current state of the same target is taken first and must succeed',
    });
    if (target.type !== 'paths') {
      const app = target.app;
      if (target.type === 'volume')
        items.push({
          effect: 'downtime',
          kind: 'application',
          ref: app,
          detail: `Application ${app} is stopped during the restore, then started and health-checked`,
        });
      else
        items.push({
          effect: 'downtime',
          kind: 'application',
          ref: app,
          detail: `The DB service must stay up for the restore; application ${app} sees the database change underneath it and is re-applied + health-checked afterwards`,
        });
    }
  }
  items.push({
    effect: 'note',
    kind: 'config',
    ref: 'config_vs_data',
    detail:
      'A data restore does not roll back application config or images, and a config/deployment rollback never restores data',
  });
  return items;
}

export function restorePlanHash(input: {
  runId: string;
  snapshotId: string;
  serverId: string;
  target: RestoreTarget;
  impact: RestoreImpactItem[];
}): string {
  return sha256Hex(stableStringify(input));
}

/** Bounded copy of arbitrary agent output for storage (≤ maxBytes serialized). */
export function boundJson(value: unknown, maxBytes = 65_536): unknown {
  if (value === undefined) return null;
  const s = JSON.stringify(value);
  if (s === undefined) return null;
  if (Buffer.byteLength(s) <= maxBytes) return value;
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    let size = 2;
    for (const v of value) {
      const n = Buffer.byteLength(JSON.stringify(v) ?? 'null') + 1;
      if (size + n > maxBytes - 64) break;
      out.push(v);
      size += n;
    }
    return { truncated: true, total: value.length, items: out };
  }
  return { truncated: true, bytes: Buffer.byteLength(s) };
}
