'use client';

import type { ReactNode } from 'react';
import type { ConnectionPolicy, Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { OutlineTag, ToneBadge, type Tone } from '@/components/ui/badge';
import { Tip } from '@/components/ui/tooltip';
import { connectionPath } from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import {
  findingKey,
  findingTone,
  pathHealth,
  pathState,
  probeFor,
  vpcDisplay,
  type PathHealth,
} from '@/lib/p9-gates';
import type { MgmtPath, ServerView } from '@/lib/api/p9-types';

/** Private first: it is the preferred management path. */
export const PATH_ORDER: readonly MgmtPath[] = ['private', 'public'];

const HEALTH: Record<PathHealth, { glyph: string; cls: string; key: MessageKey }> = {
  ok: { glyph: '●', cls: 'text-ok', key: 'p9.health.ok' },
  down: { glyph: '✕', cls: 'text-crit', key: 'p9.health.down' },
  unknown: { glyph: '○', cls: 'text-off', key: 'p9.health.unknown' },
};

export const policyKey = (p: ConnectionPolicy): MessageKey => `policy.${p}` as MessageKey;
export const pathKey = (p: MgmtPath): MessageKey => `p9.pathName.${p}` as MessageKey;

/** Text for one probe: "Private · healthy · 2 ms · 18 s ago" (also the screen-reader label). */
export function useProbeText() {
  const { t } = useI18n();
  return (s: ServerView, path: MgmtPath, now: number) => {
    const p = probeFor(s, path);
    const h = pathHealth(p);
    return [
      t(pathKey(path)),
      t(HEALTH[h].key),
      p?.latencyMs != null ? `${p.latencyMs} ms` : null,
      p?.error ?? null,
      p?.checkedAt ? relativeTime(p.checkedAt, t, now) : null,
    ]
      .filter(Boolean)
      .join(' · ');
  };
}

/** One glyph per management path (never colour alone); the active path is underlined + labelled. */
export function PathHealthDots({ server, now }: { server: ServerView; now: number }) {
  const { t } = useI18n();
  const text = useProbeText();
  const active = server.connection?.activePath ?? null;
  return (
    <span className="inline-flex items-center gap-1.5" data-testid="path-dots">
      {PATH_ORDER.map((path) => {
        const h = pathHealth(probeFor(server, path));
        const label =
          text(server, path, now) + (active === path ? ` · ${t('p9.path.active')}` : '');
        return (
          <Tip key={path} content={label}>
            <span
              tabIndex={0}
              aria-label={label}
              data-path={path}
              data-health={h}
              className={cn(
                'inline-flex items-center gap-0.5 rounded-[3px] px-1 font-mono text-[11px]',
                active === path ? 'bg-chip-2 font-semibold' : 'text-fg-muted',
              )}
            >
              <span aria-hidden="true" className={HEALTH[h].cls}>
                {HEALTH[h].glyph}
              </span>
              <span aria-hidden="true">{path === 'private' ? 'prv' : 'pub'}</span>
            </span>
          </Tip>
        );
      })}
    </span>
  );
}

/** Policy + active path badge (+ dots). Falls back to the P1 address-based label without P9 data. */
export function ConnectionSummary({
  server,
  now,
  showPolicy = true,
}: {
  server: ServerView;
  now: number;
  showPolicy?: boolean;
}) {
  const { t } = useI18n();
  const st = pathState(server);
  const fallback = connectionPath(server);
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5" data-testid="connection-summary">
      {showPolicy && <OutlineTag>{t(policyKey(server.connectionPolicy))}</OutlineTag>}
      <ToneBadge tone={st?.tone ?? fallback.tone} size="sm" className="text-[11.5px]">
        <span data-testid="active-path" data-path={st?.activePath ?? 'none'}>
          {t(st?.key ?? fallback.key)}
        </span>
      </ToneBadge>
      {server.connection && server.connection.endpoints.length > 0 && (
        <PathHealthDots server={server} now={now} />
      )}
    </span>
  );
}

/** VPC with its source. Unknown is said out loud; agent facts never imply a VPC. */
export function VpcLabel({ server, full }: { server: ServerView; full?: boolean }) {
  const { t } = useI18n();
  const v = vpcDisplay(server);
  if (!v.known)
    return (
      <Tip content={t('p9.vpc.unknownWhy')}>
        <span tabIndex={0} data-testid="vpc-label" data-source="unknown" className="inline-flex">
          <ToneBadge tone="off" size="sm" glyph="?">
            {t('p9.vpc.unknown')}
          </ToneBadge>
        </span>
      </Tip>
    );
  return (
    <span
      data-testid="vpc-label"
      data-source={v.source}
      className="inline-flex flex-wrap items-center gap-1 text-[11.5px]"
    >
      <span className="font-mono" title={v.uuid}>
        {v.name ?? (full ? v.uuid : `${v.uuid.slice(0, 8)}…`)}
      </span>
      <OutlineTag>{t(v.key)}</OutlineTag>
    </span>
  );
}

/** Address with a verified marker (✓ verified / ▲ unverified), never colour alone. */
export function AddressValue({
  server,
  scope,
}: {
  server: ServerView;
  scope: 'public' | 'private';
}) {
  const { t } = useI18n();
  const value = scope === 'public' ? server.publicIpv4 : server.privateIpv4;
  const rec = server.addresses.find(
    (a) => a.scope === scope && a.family === 'ipv4' && (!value || a.address === value),
  );
  const shown = value ?? rec?.address ?? null;
  if (!shown) return <span className="text-fg-subtle">{t('common.dash')}</span>;
  const verified = !!rec?.verifiedAt;
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <span className="truncate font-mono">{shown}</span>
      {scope === 'private' && (
        <span
          data-testid="private-verified"
          data-verified={verified}
          className={cn('text-[11px]', verified ? 'text-ok' : 'text-warn')}
          title={verified ? t('p9.addr.verified') : t('p9.addr.unverified')}
        >
          <span aria-hidden="true">{verified ? '✓' : '▲'}</span>
          <span className="sr-only">
            {verified ? t('p9.addr.verified') : t('p9.addr.unverified')}
          </span>
        </span>
      )}
    </span>
  );
}

export function FindingBadge({ code }: { code: string }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={findingTone(code)} size="sm" className="font-mono">
      <span data-testid="finding-code">{code}</span>
      <span className="sr-only"> {t(findingKey(code))}</span>
    </ToneBadge>
  );
}

export function SourceTag({ source }: { source: 'provider' | 'inventory' | 'agent' | null }) {
  const { t } = useI18n();
  return (
    <OutlineTag>
      {t(source ? (`p9.source.${source}` as MessageKey) : 'p9.source.unknown')}
    </OutlineTag>
  );
}

export function StatusTone({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <ToneBadge tone={tone} size="sm">
      {children}
    </ToneBadge>
  );
}

export const serverName = (servers: readonly Server[] | undefined, id: string) =>
  servers?.find((s) => s.id === id)?.name ?? id.slice(0, 8);

/** Section heading row used across P9 cards. */
export function CardTitle({
  id,
  children,
  actions,
}: {
  id?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <h2 id={id} className="m-0 flex-1 text-[15px] font-semibold">
        {children}
      </h2>
      {actions}
    </div>
  );
}
