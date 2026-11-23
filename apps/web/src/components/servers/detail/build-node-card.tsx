'use client';

import { useState } from 'react';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { buildNodeToggleGate } from '@/lib/p4b-gates';
import { useToast } from '@/components/providers/toast';
import { Card } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { ErrorState, Notice } from '@/components/ui/states';
import { usePatchServer } from './use-patch-server';

/**
 * Server Settings → Build node (§8.1, perm policies.manage). Enabling shows the trust warning and
 * needs an explicit confirmation; builds also need the agent's own `build` capability.
 */
export function BuildNodeCard({ server }: { server: Server }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const toast = useToast();
  const patch = usePatchServer(server);
  const [confirming, setConfirming] = useState(false);
  const [ack, setAck] = useState(false);
  const on = !!server.buildNode;
  const capable = (server.capabilities ?? []).includes('build');
  const gate = buildNodeToggleGate(server, me?.permissions);
  const set = (v: boolean) =>
    patch.mutate(
      { buildNode: v },
      {
        onSuccess: () => {
          setConfirming(false);
          setAck(false);
          toast(v ? t('bn.enabled') : t('bn.disabled'), 'ok');
        },
      },
    );

  return (
    <Card
      className="flex flex-col gap-3 p-4"
      data-testid="build-node-card"
      data-enabled={on ? 'true' : 'false'}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('bn.title')}</h2>
        <ToneBadge tone={on ? 'info' : 'off'} size="sm">
          <span data-testid="build-node-state">{on ? t('bn.on') : t('bn.off')}</span>
        </ToneBadge>
      </div>
      <p className="m-0 text-[13px] text-fg-2">{t('bn.body')}</p>
      <p className="m-0 text-[12.5px]">
        {capable ? (
          <ToneBadge tone="ok" size="sm">
            {t('bn.capable')}
          </ToneBadge>
        ) : (
          <ToneBadge tone="warn" size="sm">
            {t('bn.notCapable')}
          </ToneBadge>
        )}
      </p>
      <Notice tone="warn" glyph="▲" role="note" title={t('bn.warnTitle')}>
        <span data-testid="build-node-warning">{t('bn.warn')}</span>
      </Notice>
      {confirming && !on && (
        <div
          className="flex flex-col gap-2 rounded-md border border-line p-3"
          data-testid="build-node-confirm"
        >
          <label className="flex items-start gap-2 text-[13px]">
            <input
              type="checkbox"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
              className="mt-1"
            />
            <span>{t('bn.ack')}</span>
          </label>
          <div className="flex gap-2">
            <Button
              variant="primary"
              size="sm"
              disabled={!ack || patch.isPending}
              onClick={() => set(true)}
              data-testid="build-node-confirm-button"
            >
              {patch.isPending ? t('common.saving') : t('bn.enable')}
            </Button>
            <Button size="sm" onClick={() => setConfirming(false)}>
              {t('common.cancel')}
            </Button>
          </div>
        </div>
      )}
      {patch.error && <ErrorState error={patch.error} />}
      {!confirming && (
        <div>
          <GatedButton
            size="sm"
            variant={on ? 'danger' : 'secondary'}
            perm="policies.manage"
            blockedReason={gate.allowed ? undefined : gate.reason}
            disabled={patch.isPending}
            onClick={() => (on ? set(false) : setConfirming(true))}
            data-testid="build-node-toggle"
          >
            {on ? t('bn.disable') : t('bn.enable')}
          </GatedButton>
        </div>
      )}
    </Card>
  );
}
