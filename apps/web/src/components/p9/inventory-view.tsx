'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { ApiError } from '@/lib/api/errors';
import { networkApi } from '@/lib/api/p9-endpoints';
import { INVENTORY_MAX_ROWS, P9_PERM, parseInventory } from '@/lib/p9-gates';
import { p9k } from '@/lib/p9-queries';
import { qk, useServers } from '@/lib/queries';
import { wrap } from '@/components/p3/action-dialog';
import { Card } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { ErrorState, Notice } from '@/components/ui/states';
import { MiniTable, textareaCls } from './diagnostics';
import { CardTitle } from './net-bits';

const EXAMPLE = `[
  { "hostname": "app-uat-01", "region": "sgp1", "vpcUuid": "c3d90b12-5e7a-4a0f-b6d1-0e4f8a2c7b55", "vpcName": "uat-sgp1", "privateIpv4": "10.110.0.5" },
  { "hostname": "dev-01", "region": "sgp1", "vpcUuid": "9e7a6b54-1c2d-4e3f-8a9b-0c1d2e3f4a5b", "vpcName": "dev-sgp1" }
]`;

const MAX_FILE_BYTES = 1024 * 1024;

export function InventoryView() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const servers = useServers();
  const [text, setText] = useState('');
  const [fileErr, setFileErr] = useState<string | null>(null);
  const [done, setDone] = useState<number | null>(null);
  const parsed = useMemo(() => (text.trim() ? parseInventory(text) : null), [text]);
  const all = servers.data?.items ?? [];
  const match = (r: { serverId?: string; hostname?: string }) =>
    all.find((s) =>
      r.serverId ? s.id === r.serverId : s.hostname === r.hostname || s.name === r.hostname,
    );
  const unresolved = (parsed?.rows ?? []).filter((r) => !match(r));
  const m = useMutation<unknown, ApiError>({
    mutationFn: wrap(() => networkApi.importInventory(parsed!.rows)),
    onSuccess: () => {
      setDone(parsed?.rows.length ?? 0);
      setText('');
      void qc.invalidateQueries({ queryKey: p9k.topology });
      void qc.invalidateQueries({ queryKey: qk.servers, exact: true });
    },
  });
  const ok = !!parsed && !parsed.fatal && parsed.issues.length === 0 && parsed.rows.length > 0;

  return (
    <div className="flex flex-col gap-4">
      <Notice tone="info" glyph="◆" role="note">
        {t('p9.inv.note')}
      </Notice>
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card className="flex flex-col gap-3 p-4" aria-labelledby="inv-h">
          <CardTitle
            id="inv-h"
            actions={
              <Button size="sm" variant="ghost" onClick={() => setText(EXAMPLE)}>
                {t('p9.inv.example')}
              </Button>
            }
          >
            {t('p9.inv.title')}
          </CardTitle>
          <label className="flex flex-col gap-1 text-[12.5px] text-fg-3">
            {t('p9.inv.upload')}
            <input
              type="file"
              accept="application/json,.json"
              className="text-[13px]"
              data-testid="inventory-file"
              onChange={async (e) => {
                setFileErr(null);
                const f = e.target.files?.[0];
                if (!f) return;
                if (f.size > MAX_FILE_BYTES) {
                  setFileErr(t('p9.inv.err.fileTooBig'));
                  return;
                }
                setText(await f.text());
                e.target.value = '';
              }}
            />
          </label>
          {fileErr && (
            <span role="alert" className="text-[12px] text-crit">
              {fileErr}
            </span>
          )}
          <Field
            label={t('p9.inv.paste')}
            hint={t('p9.inv.pasteHint', { max: INVENTORY_MAX_ROWS })}
            error={parsed?.fatal ? t(parsed.fatal, { max: INVENTORY_MAX_ROWS }) : undefined}
          >
            {(p) => (
              <textarea
                {...p}
                rows={12}
                value={text}
                onChange={(e) => {
                  setText(e.target.value);
                  setDone(null);
                  m.reset();
                }}
                spellCheck={false}
                className={textareaCls}
                placeholder={EXAMPLE}
                data-testid="inventory-json"
              />
            )}
          </Field>
          {done !== null && (
            <Notice tone="ok" glyph="●" role="status">
              <span data-testid="inventory-done">{t('p9.inv.done', { n: done })}</span>{' '}
              <Link href="/network">{t('p9.nav.topology')} →</Link>
            </Notice>
          )}
          {m.error && <ErrorState error={m.error} />}
          <div>
            <GatedButton
              variant="primary"
              perm={P9_PERM.serversManage}
              disabled={!ok || unresolved.length > 0 || m.isPending}
              onClick={() => m.mutate()}
              data-testid="inventory-import"
            >
              {m.isPending
                ? t('common.saving')
                : t('p9.inv.import', { n: parsed?.rows.length ?? 0 })}
            </GatedButton>
          </div>
        </Card>
        <Card
          className="flex flex-col gap-3 p-4"
          aria-labelledby="inv-prev-h"
          data-testid="inventory-preview"
        >
          <CardTitle id="inv-prev-h">{t('p9.inv.preview')}</CardTitle>
          {!parsed ? (
            <p className="m-0 text-[13px] text-fg-muted">{t('p9.inv.previewEmpty')}</p>
          ) : (
            <>
              <div className="flex flex-wrap gap-2 text-[12.5px]" role="status">
                <ToneBadge tone={parsed.rows.length ? 'ok' : 'off'} size="sm">
                  {t('p9.inv.validRows', { n: parsed.rows.length })}
                </ToneBadge>
                <ToneBadge tone={parsed.issues.length ? 'crit' : 'ok'} size="sm">
                  <span data-testid="inventory-issue-count">
                    {t('p9.inv.issues', { n: parsed.issues.length })}
                  </span>
                </ToneBadge>
                {unresolved.length > 0 && (
                  <ToneBadge tone="warn" size="sm">
                    {t('p9.inv.unresolved', { n: unresolved.length })}
                  </ToneBadge>
                )}
              </div>
              {parsed.issues.length > 0 && (
                <MiniTable
                  testId="inventory-issues"
                  caption={t('p9.inv.issuesCaption')}
                  head={[t('p9.col.row'), t('p9.col.field'), t('p9.col.problem')]}
                  rows={parsed.issues.map((i) => [
                    i.row,
                    <span key="f" className="font-mono">
                      {i.field}
                    </span>,
                    i.message,
                  ])}
                />
              )}
              {parsed.rows.length > 0 && (
                <MiniTable
                  caption={t('p9.inv.rowsCaption')}
                  head={[
                    t('p9.col.server'),
                    t('net.field.region'),
                    t('p9.card.vpc'),
                    t('net.field.privateIpv4'),
                  ]}
                  rows={parsed.rows.map((r) => {
                    const s = match(r);
                    return [
                      s ? (
                        <span key="s" className="font-mono">
                          {s.name}
                        </span>
                      ) : (
                        <ToneBadge key="s" tone="warn" size="sm">
                          {t('p9.inv.noMatch', { ref: r.serverId ?? r.hostname ?? '?' })}
                        </ToneBadge>
                      ),
                      <span key="r" className="font-mono">
                        {r.region ?? '—'}
                      </span>,
                      <span key="v" className="font-mono">
                        {r.vpcName ?? r.vpcUuid ?? '—'}
                      </span>,
                      <span key="p" className="font-mono">
                        {r.privateIpv4 ?? '—'}
                      </span>,
                    ];
                  })}
                />
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
