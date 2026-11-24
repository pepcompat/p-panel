'use client';

import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import { sshCredentialsApi } from '@/lib/api/p10-endpoints';
import {
  PRIVATE_KEY_MAX_BYTES,
  SSH_USER_RE,
  type CredentialDeployment,
  type SshCredential,
} from '@/lib/api/p10-types';
import { p10k, useCredentials } from '@/lib/p10-queries';
import { useServers } from '@/lib/queries';
import { formatDateTime } from '@/lib/time';
import { ActionDialog, wrap } from '@/components/p3/action-dialog';
import { StepUpField } from '@/components/p3/bits';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { CopyButton } from '@/components/ui/copy-button';
import { Dialog } from '@/components/ui/dialog';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { OutlineTag } from '@/components/ui/badge';
import { CardSkeletonGrid } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { CredentialStatusBadge, DeploymentStatusBadge, Fingerprint, SectionTitle } from './bits';

const MANAGE = 'credentials.manage' as const;
const nameOk = (n: string) => /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/.test(n.trim());

function GenerateDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [name, setName] = useState('');
  return (
    <ActionDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setName('');
        onOpenChange(o);
      }}
      title={t('p10.cred.generate.title')}
      body={t('p10.cred.generate.body')}
      confirmLabel={t('p10.cred.generate.confirm')}
      needsStepUp
      onConfirm={async (token) => {
        if (!nameOk(name)) throw toApiError(new Error(t('p10.cred.err.name')));
        await sshCredentialsApi.create({ name: name.trim(), mode: 'generate' }, token!);
        setName('');
        await qc.invalidateQueries({ queryKey: p10k.credentials });
      }}
    >
      <Field
        label={t('p10.cred.name')}
        hint={t('p10.cred.nameHint')}
        error={name && !nameOk(name) ? t('p10.cred.err.name') : undefined}
      >
        {(p) => (
          <Input
            {...p}
            value={name}
            maxLength={63}
            onChange={(e) => setName(e.target.value)}
            className="font-mono"
            placeholder="ops-ed25519"
            autoComplete="off"
          />
        )}
      </Field>
    </ActionDialog>
  );
}

/**
 * Import a private key. The textarea is uncontrolled: its value is read once on submit, the field is
 * cleared before the request leaves, and the key is never put in React state, the query cache, a
 * mutation's variables or any storage. Nothing renders it back.
 */
export function ImportKeyDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const keyRef = useRef<HTMLTextAreaElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const [name, setName] = useState('');
  const [hasKey, setHasKey] = useState(false);
  const [otp, setOtp] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [tooBig, setTooBig] = useState(false);
  const [cleared, setCleared] = useState(false);

  const reset = () => {
    if (keyRef.current) keyRef.current.value = '';
    if (passRef.current) passRef.current.value = '';
    setName('');
    setHasKey(false);
    setOtp('');
    setError(null);
    setTooBig(false);
    setCleared(false);
  };

  const submit = async () => {
    const keyEl = keyRef.current;
    const passEl = passRef.current;
    if (!keyEl || pending) return;
    let privateKey = keyEl.value;
    let passphrase = passEl?.value ?? '';
    // clear the fields before anything is sent: one POST, never kept afterwards
    keyEl.value = '';
    if (passEl) passEl.value = '';
    setHasKey(false);
    setCleared(true);
    setError(null);
    const big = new TextEncoder().encode(privateKey).length > PRIVATE_KEY_MAX_BYTES;
    setTooBig(big);
    if (big) {
      privateKey = '';
      passphrase = '';
      return;
    }
    setPending(true);
    try {
      const { stepUpToken } = await authApi.stepUp(otp);
      await sshCredentialsApi.create(
        {
          name: name.trim(),
          mode: 'import',
          privateKey,
          ...(passphrase ? { passphrase } : {}),
        },
        stepUpToken,
      );
      privateKey = '';
      passphrase = '';
      await qc.invalidateQueries({ queryKey: p10k.credentials });
      reset();
      onOpenChange(false);
    } catch (e) {
      setError(toApiError(e));
    } finally {
      privateKey = '';
      passphrase = '';
      setPending(false);
    }
  };

  const ready = nameOk(name) && hasKey && !!me?.mfaEnabled && /^\d{6}$/.test(otp) && !pending;
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
      closeLabel={t('common.close')}
      title={t('p10.cred.import.title')}
      description={t('p10.cred.import.body')}
      className="max-w-[560px]"
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            disabled={!ready}
            onClick={() => void submit()}
            data-testid="import-submit"
          >
            {pending ? t('common.saving') : t('p10.cred.import.confirm')}
          </Button>
        </>
      }
    >
      <form
        noValidate
        autoComplete="off"
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) void submit();
        }}
      >
        <Field
          label={t('p10.cred.name')}
          error={name && !nameOk(name) ? t('p10.cred.err.name') : undefined}
        >
          {(p) => (
            <Input
              {...p}
              value={name}
              maxLength={63}
              onChange={(e) => setName(e.target.value)}
              className="font-mono"
              autoComplete="off"
            />
          )}
        </Field>
        <Field
          label={t('p10.cred.import.key')}
          hint={t('p10.cred.import.keyHint')}
          error={tooBig ? t('p10.cred.import.tooBig') : undefined}
        >
          {(p) => (
            <textarea
              {...p}
              ref={keyRef}
              data-testid="private-key-input"
              rows={7}
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              data-lpignore="true"
              data-1p-ignore="true"
              onInput={(e) => setHasKey(e.currentTarget.value.trim().length > 0)}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[12px] text-fg placeholder:text-fg-subtle"
            />
          )}
        </Field>
        <Field label={t('p10.cred.import.passphrase')} hint={t('p10.cred.import.passphraseHint')}>
          {(p) => (
            <Input
              {...p}
              ref={passRef}
              type="password"
              autoComplete="new-password"
              data-lpignore="true"
            />
          )}
        </Field>
        <StepUpField value={otp} onChange={setOtp} />
        {cleared && !error && pending && (
          <span role="status" className="text-[12px] text-fg-muted">
            {t('p10.cred.import.sending')}
          </span>
        )}
        {error && (
          <>
            <ErrorState error={error} />
            <span role="status" className="text-[12px] text-fg-muted" data-testid="key-cleared">
              {t('p10.cred.import.clearedRetry')}
            </span>
          </>
        )}
      </form>
    </Dialog>
  );
}

function DeployDialog({
  cred,
  onOpenChange,
}: {
  cred: SshCredential | null;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const servers = useServers();
  const [serverId, setServerId] = useState('');
  const [sshUser, setSshUser] = useState('');
  const m = useMutation<unknown, ApiError>({
    mutationFn: wrap(() =>
      sshCredentialsApi.deploy(cred!.id, { serverId, sshUser: sshUser.trim() }),
    ),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: p10k.credentials });
      setServerId('');
      setSshUser('');
      onOpenChange(false);
    },
  });
  const userErr =
    sshUser && (!SSH_USER_RE.test(sshUser) || sshUser === 'root')
      ? sshUser === 'root'
        ? t('p10.err.root')
        : t('p10.err.sshUser')
      : undefined;
  const fe = m.error?.fieldErrors ?? {};
  return (
    <Dialog
      open={!!cred}
      onOpenChange={(o) => {
        if (!o) m.reset();
        onOpenChange(o);
      }}
      closeLabel={t('common.close')}
      title={t('p10.cred.deploy.title', { name: cred?.name ?? '' })}
      description={t('p10.cred.deploy.body')}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            disabled={!serverId || !sshUser || !!userErr || m.isPending}
            onClick={() => m.mutate()}
          >
            {m.isPending ? t('common.saving') : t('p10.cred.deploy.confirm')}
          </Button>
        </>
      }
    >
      <Field label={t('p10.server')} error={fe.serverId}>
        {(p) => (
          <Select {...p} value={serverId} onChange={(e) => setServerId(e.target.value)}>
            <option value="">{t('p10.pickServer')}</option>
            {(servers.data?.items ?? [])
              .filter((s) => s.status !== 'revoked')
              .map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} · {s.environment}
                </option>
              ))}
          </Select>
        )}
      </Field>
      <Field label={t('p10.sshUser')} hint={t('p10.sshUserHint')} error={userErr ?? fe.sshUser}>
        {(p) => (
          <Input
            {...p}
            value={sshUser}
            onChange={(e) => setSshUser(e.target.value.trim().toLowerCase())}
            className="font-mono"
            placeholder="ops"
            autoComplete="off"
          />
        )}
      </Field>
      {m.error && Object.keys(fe).length === 0 && <ErrorState error={m.error} />}
    </Dialog>
  );
}

function DeploymentRow({ cred, d }: { cred: SshCredential; d: CredentialDeployment }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const busy = d.status === 'pending' || d.status === 'removing';
  return (
    <li
      className="flex flex-wrap items-center gap-2 border-t border-line-subtle py-1.5 text-[12.5px] first:border-0"
      data-testid="deployment-row"
    >
      <span className="min-w-[120px] font-mono">{d.serverName}</span>
      <OutlineTag>{d.sshUser}</OutlineTag>
      <DeploymentStatusBadge status={d.status} />
      {d.lastError && <span className="font-mono text-[11.5px] text-crit">{d.lastError}</span>}
      <span className="flex-1" />
      <GatedButton
        size="xs"
        perm={MANAGE}
        disabled={busy || !d.id}
        onClick={() => setOpen(true)}
        aria-label={t('p10.cred.removeDeployment.aria', { server: d.serverName, user: d.sshUser })}
      >
        {t('p10.cred.removeDeployment')}
      </GatedButton>
      <ActionDialog
        open={open}
        onOpenChange={setOpen}
        danger
        needsStepUp={false}
        title={t('p10.cred.removeDeployment.title')}
        body={t('p10.cred.removeDeployment.body', {
          name: cred.name,
          server: d.serverName,
          user: d.sshUser,
        })}
        confirmLabel={t('p10.cred.removeDeployment')}
        onConfirm={async () => {
          await sshCredentialsApi.removeDeployment(cred.id, d.id!);
          await qc.invalidateQueries({ queryKey: p10k.credentials });
        }}
      />
    </li>
  );
}

function CredentialCard({
  cred,
  onDeploy,
  predecessor,
}: {
  cred: SshCredential;
  onDeploy: (c: SshCredential) => void;
  predecessor: string | null;
}) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<'rotate' | 'revoke' | null>(null);
  const active = cred.status === 'active';
  const deployments = cred.deployments.filter((d) => d.status !== 'removed');
  const installed = deployments.filter((d) => d.status === 'installed').length;
  return (
    <article
      aria-labelledby={`cred-${cred.id}`}
      data-testid="credential-card"
      className="flex flex-col gap-2.5 rounded-lg border border-line bg-surface p-4"
    >
      <div className="flex flex-wrap items-center gap-2">
        <h3 id={`cred-${cred.id}`} className="m-0 flex-1 font-mono text-[14px] font-medium">
          {cred.name}
        </h3>
        <CredentialStatusBadge status={cred.status} />
      </div>
      <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-fg-muted">
        <OutlineTag>{cred.algorithm}</OutlineTag>
        <OutlineTag>{t(`p10.cred.kind.${cred.kind}`)}</OutlineTag>
        <span>
          {t('p10.cred.created', {
            when: formatDateTime(cred.createdAt, locale),
            who: cred.createdByLabel ?? t('common.unknown'),
          })}
        </span>
      </div>
      <dl className="m-0 grid grid-cols-[96px_minmax(0,1fr)] gap-x-2 gap-y-1 text-[12.5px]">
        <dt className="text-fg-muted">{t('p10.fingerprint')}</dt>
        <dd className="m-0 min-w-0">
          <Fingerprint value={cred.fingerprintSha256} />
        </dd>
        {predecessor && (
          <>
            <dt className="text-fg-muted">{t('p10.cred.rotatedFrom')}</dt>
            <dd className="m-0 font-mono">{predecessor}</dd>
          </>
        )}
        {cred.revokedAt && (
          <>
            <dt className="text-fg-muted">{t('p10.cred.revokedAt')}</dt>
            <dd className="m-0">{formatDateTime(cred.revokedAt, locale)}</dd>
          </>
        )}
      </dl>
      <details className="text-[12.5px]">
        <summary className="cursor-pointer text-fg-3">{t('p10.cred.publicKey')}</summary>
        <div className="mt-1.5 flex items-start gap-2">
          <code className="min-w-0 flex-1 rounded bg-chip px-2 py-1.5 font-mono text-[11px] break-all">
            {cred.publicKey}
          </code>
          <CopyButton
            text={cred.publicKey}
            ariaLabel={t('p10.cred.copyPublic', { name: cred.name })}
          />
        </div>
      </details>
      <div>
        <div className="text-[12px] text-fg-muted">
          {t('p10.cred.deployments', { n: deployments.length, installed })}
        </div>
        {deployments.length === 0 ? (
          <p className="m-0 text-[12.5px] text-fg-subtle">{t('p10.cred.noDeployments')}</p>
        ) : (
          <ul className="m-0 list-none p-0">
            {deployments.map((d) => (
              <DeploymentRow key={d.id ?? `${d.serverId}-${d.sshUser}`} cred={cred} d={d} />
            ))}
          </ul>
        )}
      </div>
      <div className="mt-auto flex flex-wrap gap-1.5 border-t border-line-subtle pt-2.5">
        <GatedButton
          size="sm"
          perm={MANAGE}
          disabled={!active}
          onClick={() => onDeploy(cred)}
          aria-label={t('p10.cred.deploy.aria', { name: cred.name })}
        >
          {t('p10.cred.deploy')}
        </GatedButton>
        <GatedButton
          size="sm"
          perm={MANAGE}
          disabled={!active}
          onClick={() => setDialog('rotate')}
          aria-label={t('p10.cred.rotate.aria', { name: cred.name })}
        >
          {t('p10.cred.rotate')}
        </GatedButton>
        <GatedButton
          size="sm"
          variant="danger"
          perm={MANAGE}
          disabled={cred.status === 'revoked'}
          onClick={() => setDialog('revoke')}
          aria-label={t('p10.cred.revoke.aria', { name: cred.name })}
        >
          {t('p10.cred.revoke')}
        </GatedButton>
      </div>
      <ActionDialog
        open={dialog === 'rotate'}
        onOpenChange={(o) => setDialog(o ? 'rotate' : null)}
        title={t('p10.cred.rotate.title', { name: cred.name })}
        body={t('p10.cred.rotate.body', { n: installed })}
        confirmLabel={t('p10.cred.rotate.confirm')}
        needsStepUp
        onConfirm={async (token) => {
          await sshCredentialsApi.rotate(cred.id, token!);
          await qc.invalidateQueries({ queryKey: p10k.credentials });
        }}
      />
      <ActionDialog
        open={dialog === 'revoke'}
        onOpenChange={(o) => setDialog(o ? 'revoke' : null)}
        danger
        title={t('p10.cred.revoke.title', { name: cred.name })}
        body={t('p10.cred.revoke.body', { n: deployments.length })}
        confirmLabel={t('p10.cred.revoke.confirm')}
        needsStepUp
        onConfirm={async (token) => {
          await sshCredentialsApi.revoke(cred.id, token!);
          await Promise.all([
            qc.invalidateQueries({ queryKey: p10k.credentials }),
            qc.invalidateQueries({ queryKey: p10k.sessions }),
          ]);
        }}
      />
    </article>
  );
}

export function CredentialsView() {
  const { t } = useI18n();
  const q = useCredentials();
  const [dialog, setDialog] = useState<'generate' | 'import' | null>(null);
  const [deployFor, setDeployFor] = useState<SshCredential | null>(null);
  const forbidden = isApiError(q.error) && q.error.status === 403;
  const byId = new Map((q.data ?? []).map((c) => [c.id, c.name]));
  return (
    <div className="flex flex-col gap-4">
      <Card className="flex flex-col gap-2.5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <SectionTitle>{t('p10.cred.title')}</SectionTitle>
          <span className="flex-1" />
          <GatedButton variant="primary" perm={MANAGE} onClick={() => setDialog('generate')}>
            {t('p10.cred.generate')}
          </GatedButton>
          <GatedButton perm={MANAGE} onClick={() => setDialog('import')}>
            {t('p10.cred.import')}
          </GatedButton>
        </div>
        <Notice tone="info" glyph="◆" role="note">
          {t('p10.cred.vaultNote')}
        </Notice>
      </Card>
      {forbidden ? (
        <ForbiddenState
          perm="fleet.read"
          requestId={isApiError(q.error) ? q.error.requestId : null}
        />
      ) : q.isPending ? (
        <CardSkeletonGrid label={t('common.loading')} count={3} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : q.data.length === 0 ? (
        <EmptyState title={t('p10.cred.empty')} body={t('p10.cred.emptyBody')} />
      ) : (
        <ul className="m-0 grid list-none grid-cols-[repeat(auto-fill,minmax(min(100%,400px),1fr))] gap-3 p-0">
          {q.data.map((c) => (
            <li key={c.id}>
              <CredentialCard
                cred={c}
                onDeploy={setDeployFor}
                predecessor={
                  c.rotatedFromId ? (byId.get(c.rotatedFromId) ?? c.rotatedFromId) : null
                }
              />
            </li>
          ))}
        </ul>
      )}
      <GenerateDialog
        open={dialog === 'generate'}
        onOpenChange={(o) => setDialog(o ? 'generate' : null)}
      />
      <ImportKeyDialog
        open={dialog === 'import'}
        onOpenChange={(o) => setDialog(o ? 'import' : null)}
      />
      <DeployDialog cred={deployFor} onOpenChange={(o) => !o && setDeployFor(null)} />
    </div>
  );
}
