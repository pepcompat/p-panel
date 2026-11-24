'use client';

import Link from 'next/link';
import { useId } from 'react';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import type { SshGrant } from '@/lib/api/p10-types';
import {
  BLOCK_KEY,
  allowedPaths,
  grantRequestHref,
  hostKeyState,
  hostKeysHref,
  installedUsers,
  minutesLeft,
  terminalGate,
  terminalHref,
} from '@/lib/p10-gates';
import { useCredentials, useGrants, useHostKeys, useSshEndpoints } from '@/lib/p10-queries';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { pathKey } from '@/components/p9/net-bits';
import { Button } from '@/components/ui/button';
import { Card, DefList } from '@/components/ui/card';
import { OutlineTag, ToneBadge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, Notice } from '@/components/ui/states';
import { Tip } from '@/components/ui/tooltip';
import { Fingerprint, GrantStatusBadge } from './bits';
import { MismatchBanner } from './host-keys-view';

function useSshFacts(server: Server, withHostKeys: boolean) {
  const { me, can } = useAuth();
  const grants = useGrants();
  const creds = useCredentials(can('fleet.read'));
  const hostKeys = useHostKeys(server.id, withHostKeys);
  const gate = terminalGate({
    server,
    permissions: me?.permissions,
    userId: me?.user.id,
    grants: grants.data,
    credentials: creds.data,
    hostKeys: withHostKeys ? hostKeys.data : undefined,
  });
  return { gate, creds, hostKeys, grants };
}

/**
 * "Open Terminal" for a server card / detail header. Enabled only with an active grant (and, on the
 * detail page, a trusted host key); otherwise disabled with the reason and a link to fix it.
 */
export function OpenTerminalAction({
  server,
  variant,
}: {
  server: Server;
  variant: 'card' | 'detail';
}) {
  const { t } = useI18n();
  const reasonId = useId();
  const { gate } = useSshFacts(server, variant === 'detail');
  const label = variant === 'card' ? t('card.terminal') : t('detail.openTerminal');
  const cls =
    variant === 'card' ? 'min-h-8 px-3 text-[12.5px]' : 'min-h-[38px] px-3.5 text-[13.5px]';
  if (!gate.block && gate.grant)
    return (
      <Link
        href={terminalHref(gate.grant.id)}
        data-testid="open-terminal"
        className={cn(
          'inline-flex items-center rounded-md bg-[#1c1d1f] font-mono text-white no-underline hover:bg-black hover:text-white hover:no-underline dark:bg-chip',
          cls,
        )}
      >
        {label}
      </Link>
    );
  const reason = t(BLOCK_KEY[gate.block ?? 'noGrant']);
  const fix =
    gate.block === 'noGrant'
      ? { href: grantRequestHref(server.id), text: t('p10.access.request') }
      : gate.block === 'hostKeyMismatch' || gate.block === 'noHostKey'
        ? { href: hostKeysHref(server.id), text: t('p10.access.hostKeys') }
        : gate.block === 'noCredential'
          ? { href: '/ssh?tab=credentials', text: t('p10.access.credentials') }
          : gate.block === 'pendingApproval'
            ? { href: '/ssh?tab=grants', text: t('p10.access.pending') }
            : null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <Tip content={reason}>
        <span tabIndex={0} className="inline-flex rounded-md" aria-describedby={reasonId}>
          <Button
            variant={variant === 'detail' ? 'dark' : 'secondary'}
            size={variant === 'card' ? 'sm' : 'md'}
            className={cn('font-mono', variant === 'detail' && 'min-h-[38px]')}
            disabled
            aria-describedby={reasonId}
            data-testid="open-terminal"
            data-block={gate.block ?? ''}
          >
            {label}
          </Button>
          <span id={reasonId} className="sr-only">
            {reason}
          </span>
        </span>
      </Tip>
      {fix && variant === 'detail' && (
        <Link href={fix.href} className="text-[13px]" data-testid="terminal-fix">
          {fix.text}
        </Link>
      )}
    </span>
  );
}

/** Compact SSH line for a server card: effective endpoint, user, port, auth and scope. */
export function SshAccessLine({ server }: { server: Server }) {
  const { t } = useI18n();
  const { gate } = useSshFacts(server, false);
  const g = gate.grant;
  const eps = useSshEndpoints(server.id, !!g);
  const ep = g ? eps.data?.find((e) => e.path === g.endpointPath) : undefined;
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[12px]" data-testid="ssh-line">
      <span className="w-[52px] shrink-0 text-fg-muted">{t('p10.card.ssh')}</span>
      {g ? (
        <>
          <span className="font-mono">
            {g.sshUser}@{t(pathKey(g.endpointPath))}
            {ep ? ` ${ep.host}:${ep.port}` : ''}
          </span>
          <span className="text-fg-muted">· {t('p10.auth.publicKey')}</span>
          <span className="text-fg-muted">
            · {t('p10.scope.grant', { n: minutesLeft(g.expiresAt) ?? 0 })}
          </span>
        </>
      ) : gate.block === 'pendingApproval' ? (
        <span className="text-warn">▲ {t('p10.block.pendingApproval')}</span>
      ) : gate.block === 'perm' ? (
        <span className="text-fg-subtle">{t('p10.block.perm')}</span>
      ) : gate.block === 'noCredential' ? (
        <span className="text-fg-subtle">{t('p10.block.noCredential')}</span>
      ) : (
        <>
          <span className="text-fg-subtle">{t('p10.card.noGrant')}</span>
          {gate.block !== 'offline' && (
            <Link href={grantRequestHref(server.id)} className="text-[12px]">
              {t('p10.access.request')}
            </Link>
          )}
        </>
      )}
    </div>
  );
}

/** Server detail → Terminal tab: everything that decides whether (and how) a terminal opens. */
export function ServerSshTab({ server }: { server: Server }) {
  const { t, locale } = useI18n();
  const { me, can } = useAuth();
  const { gate, creds, hostKeys, grants } = useSshFacts(server, true);
  const eps = useSshEndpoints(server.id);
  const endpoints = eps.data ?? [];
  const paths = allowedPaths(server.connectionPolicy, endpoints);
  const users = installedUsers(server.id, creds.data ?? []);
  const mine: SshGrant[] = (grants.data ?? []).filter(
    (g) => g.serverId === server.id && g.userId === me?.user.id,
  );
  const keyFps = (creds.data ?? [])
    .filter(
      (c) =>
        c.status === 'active' &&
        c.deployments.some((d) => d.serverId === server.id && d.status === 'installed'),
    )
    .map((c) => c.fingerprintSha256);
  return (
    <div className="flex flex-col gap-4" data-testid="server-ssh-tab">
      {endpoints.map((e) => {
        const hk = hostKeyState(hostKeys.data ?? [], e.path);
        return hk.mismatch && hk.trusted ? (
          <MismatchBanner
            key={e.path}
            server={server.name}
            path={e.path}
            trusted={hk.trusted}
            seen={hk.mismatch}
          />
        ) : null;
      })}
      <Card className="flex flex-col gap-3 p-4" aria-labelledby="ssh-access-h">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="ssh-access-h" className="m-0 flex-1 text-[15px] font-semibold">
            {t('p10.access.title')}
          </h2>
          <OpenTerminalAction server={server} variant="detail" />
        </div>
        {gate.block && (
          <Notice tone={gate.block === 'hostKeyMismatch' ? 'crit' : 'warn'} glyph="▲" role="status">
            {t(BLOCK_KEY[gate.block])}
          </Notice>
        )}
        <DefList
          keyWidth={150}
          rows={[
            [
              t('p10.access.endpoint'),
              gate.grant ? (
                <span>
                  {t(pathKey(gate.grant.endpointPath))}{' '}
                  <span className="font-mono">
                    {endpoints.find((e) => e.path === gate.grant!.endpointPath)?.host ?? '—'}
                  </span>
                </span>
              ) : paths.length ? (
                paths.map((p) => t(pathKey(p))).join(' / ')
              ) : (
                t('p10.grant.noEndpoint')
              ),
            ],
            [
              t('p10.access.port'),
              <span key="port" className="font-mono">
                {gate.grant
                  ? (endpoints.find((e) => e.path === gate.grant!.endpointPath)?.port ?? '—')
                  : [...new Set(endpoints.map((e) => e.port))].join(', ') || '—'}
              </span>,
            ],
            [
              t('p10.sshUser'),
              gate.grant ? (
                <span className="font-mono">{gate.grant.sshUser}</span>
              ) : users.length ? (
                <span className="font-mono">{users.join(', ')}</span>
              ) : (
                t('p10.block.noCredential')
              ),
            ],
            [t('p10.access.auth'), t('p10.auth.publicKeyLong')],
            [
              t('p10.access.key'),
              keyFps.length ? (
                <span className="flex flex-col gap-0.5">
                  {keyFps.map((f) => (
                    <Fingerprint key={f} value={f} />
                  ))}
                </span>
              ) : (
                '—'
              ),
            ],
            [
              t('p10.access.scope'),
              gate.grant
                ? t('p10.access.scopeGrant', {
                    n: minutesLeft(gate.grant.expiresAt) ?? 0,
                    when: gate.grant.expiresAt ? formatDateTime(gate.grant.expiresAt, locale) : '—',
                  })
                : can('ssh.connect')
                  ? t('p10.access.scopeRbacOnly')
                  : t('p10.block.perm'),
            ],
          ]}
        />
      </Card>
      <Card className="flex flex-col gap-3 p-4" aria-labelledby="ssh-ep-h">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="ssh-ep-h" className="m-0 flex-1 text-[15px] font-semibold">
            {t('p10.ep.title')}
          </h2>
          <Link href={hostKeysHref(server.id)} className="text-[13px]">
            {t('p10.access.hostKeys')} →
          </Link>
        </div>
        {eps.isPending ? (
          <TableSkeleton rows={2} label={t('common.loading')} />
        ) : endpoints.length === 0 ? (
          <EmptyState title={t('p10.ep.empty')} body={t('p10.ep.emptyBody')} />
        ) : (
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {endpoints.map((e) => {
              const hk = hostKeyState(hostKeys.data ?? [], e.path);
              const allowed = paths.includes(e.path);
              return (
                <li
                  key={e.path}
                  className="flex flex-wrap items-center gap-2 rounded-md border border-line px-3 py-2 text-[13px]"
                >
                  <b className="min-w-[90px]">{t(pathKey(e.path))}</b>
                  <code className="font-mono text-[12.5px]">
                    {e.host}:{e.port}
                  </code>
                  {e.allowedUsers.map((u) => (
                    <OutlineTag key={u}>{u}</OutlineTag>
                  ))}
                  {!allowed && (
                    <ToneBadge tone="off" size="sm">
                      {t('p9.path.notAllowed')}
                    </ToneBadge>
                  )}
                  {hk.mismatch ? (
                    <ToneBadge tone="crit" size="sm">
                      {t('p10.hk.state.mismatch')}
                    </ToneBadge>
                  ) : hk.trusted ? (
                    <ToneBadge tone="ok" size="sm">
                      {t('p10.hk.state.trusted')}
                    </ToneBadge>
                  ) : (
                    <ToneBadge tone="warn" size="sm">
                      {t('p10.hk.state.untrusted')}
                    </ToneBadge>
                  )}
                  <span className="flex-1" />
                  {allowed && (
                    <Link
                      href={grantRequestHref(
                        server.id,
                        e.path,
                        users.find((u) => e.allowedUsers.includes(u)),
                      )}
                      className="text-[12.5px]"
                    >
                      {t('p10.access.requestPath')}
                    </Link>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        <p className="m-0 text-[12px] text-fg-muted">{t('p10.access.noFallback')}</p>
      </Card>
      <Card className="flex flex-col gap-2 p-4" aria-labelledby="ssh-grants-h">
        <h2 id="ssh-grants-h" className="m-0 text-[15px] font-semibold">
          {t('p10.access.myGrants')}
        </h2>
        {mine.length === 0 ? (
          <p className="m-0 text-[13px] text-fg-muted">{t('p10.grant.mineEmpty')}</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
            {mine.slice(0, 5).map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-2 text-[13px]">
                <GrantStatusBadge status={g.status} />
                <span className="font-mono">
                  {g.sshUser}@{t(pathKey(g.endpointPath))}
                </span>
                <span className="text-fg-muted">{formatDateTime(g.requestedAt, locale)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
