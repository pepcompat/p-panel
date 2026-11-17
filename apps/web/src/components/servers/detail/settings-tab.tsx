'use client';

import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ENVIRONMENTS, type Environment, type Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { envLabelKey, isLive } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { qk } from '@/lib/queries';
import { useToast } from '@/components/providers/toast';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Field, Input } from '@/components/ui/form';
import { Segmented } from '@/components/ui/segmented';
import { ErrorState, Notice } from '@/components/ui/states';
import { usePatchServer } from './use-patch-server';
import { RevokeDialog } from './revoke-dialog';

export function SettingsTab({ server }: { server: Server }) {
  const { t, locale } = useI18n();
  const toast = useToast();
  const qc = useQueryClient();
  const patch = usePatchServer(server);
  const [name, setName] = useState(server.name);
  const [env, setEnv] = useState<Environment>(server.environment);
  const [tags, setTags] = useState(server.tags.join(', '));
  const [revokeOpen, setRevokeOpen] = useState(false);

  useEffect(() => {
    setName(server.name);
    setEnv(server.environment);
    setTags(server.tags.join(', '));
  }, [server.name, server.environment, server.tags]);

  const tagList = tags
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const dirty = name !== server.name || env !== server.environment || tagList.join(',') !== server.tags.join(',');
  const fe = patch.error?.fieldErrors ?? {};
  const conflict = patch.error?.status === 409;

  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,380px),1fr))] items-start gap-4">
      <Card className="flex flex-col gap-3.5 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('settings.identity')}</h2>
        <form
          noValidate
          className="flex flex-col gap-3.5"
          onSubmit={(e) => {
            e.preventDefault();
            const body: Record<string, unknown> = {};
            if (name !== server.name) body.name = name.trim();
            if (env !== server.environment) body.environment = env;
            if (tagList.join(',') !== server.tags.join(',')) body.tags = tagList;
            patch.mutate(body, { onSuccess: () => toast(t('settings.saved'), 'ok') });
          }}
        >
          <Field label={t('settings.name')} hint={t('enroll.nameHint')} error={fe.name}>
            {(p) => <Input {...p} value={name} onChange={(e) => setName(e.target.value.toLowerCase())} className="font-mono text-[13px]" maxLength={63} />}
          </Field>
          <div className="flex flex-col gap-1">
            <span className="text-[12.5px] text-fg-3">{t('settings.environment')}</span>
            <Segmented<Environment>
              label={t('settings.environment')}
              value={env}
              onChange={setEnv}
              className="self-start"
              options={ENVIRONMENTS.map((e) => ({ value: e, label: t(envLabelKey(e)) }))}
            />
            <span className="text-[12px] text-fg-muted">{t('env.note')}</span>
          </div>
          <Field label={t('settings.tags')} hint={t('enroll.tagsHint')} error={fe.tags}>
            {(p) => <Input {...p} value={tags} onChange={(e) => setTags(e.target.value)} />}
          </Field>
          {conflict && (
            <Notice
              tone="crit"
              glyph="✕"
              role="alert"
              action={
                <Button
                  size="sm"
                  onClick={() => {
                    patch.reset();
                    void qc.invalidateQueries({ queryKey: qk.server(server.id) });
                  }}
                >
                  {t('common.reload')}
                </Button>
              }
            >
              {t('net.conflict')}
            </Notice>
          )}
          {patch.error && !conflict && Object.keys(fe).length === 0 && <ErrorState error={patch.error} />}
          <div className="flex gap-2">
            <GatedButton type="submit" variant="primary" perm="servers.operate" action="edit" allowedActions={server.allowedActions} disabled={!dirty || patch.isPending || !name.trim()}>
              {patch.isPending ? t('common.saving') : t('settings.save')}
            </GatedButton>
          </div>
        </form>
      </Card>
      <Card className="flex flex-col gap-2.5 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('settings.agentCert')}</h2>
        <span className="font-mono text-[12.5px] text-fg-3">
          {server.certificate ? t('sd.certExpires', { serial: server.certificate.serial, date: formatDateTime(server.certificate.notAfter, locale) }) : t('sd.noCert')}
        </span>
        <div className="flex flex-wrap gap-2">
          <GatedButton perm="servers.operate" action="rotate_cert" allowedActions={server.allowedActions} blockedReason={isLive(server) ? { key: 'perm.proposed' } : { key: 'perm.offline' }}>
            {t('settings.rotate')} <span className="font-mono text-[10.5px] text-warn">{t('settings.privileged')}</span>
          </GatedButton>
          <GatedButton variant="secondary" className="border-crit text-crit" perm="servers.revoke" action="revoke" allowedActions={server.allowedActions} onClick={() => setRevokeOpen(true)}>
            {t('settings.revoke')} <span className="font-mono text-[10.5px]">{t('settings.destructive')}</span>
          </GatedButton>
        </div>
      </Card>
      <RevokeDialog server={server} open={revokeOpen} onOpenChange={setRevokeOpen} />
    </div>
  );
}
