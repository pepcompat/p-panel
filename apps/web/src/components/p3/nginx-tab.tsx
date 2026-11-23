'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { applicationsApi, authApi, revisionsApi } from '@/lib/api/endpoints';
import type { ApiError } from '@/lib/api/errors';
import type {
  Application,
  NginxFileContent,
  NginxRevision,
  Postcheck,
  RevisionStatus,
} from '@/lib/api/p3-types';
import { unifiedDiff } from '@/lib/diff';
import { approvalExpired, revisionGate, type RevisionAction } from '@/lib/p3-gates';
import { p3k, useJob, useNginxFiles, useRevisions } from '@/lib/p3-queries';
import { evaluateGate } from '@/lib/permissions';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/providers/toast';
import { Card, CardHeader } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { DiffViewer } from './diff-viewer';
import { ActionDialog, wrap } from './action-dialog';
import { RevisionStatusBadge, Sha, StepUpField } from './bits';
import type { MessageKey } from '@/i18n/en';

const OPEN: RevisionStatus[] = [
  'draft',
  'validating',
  'valid',
  'awaiting_approval',
  'approved',
  'applying',
  'reverting',
];
const REVERTED_CODES = ['POSTCHECK_FAILED_REVERTED', 'RELOAD_FAILED_REVERTED', 'NGINX_TEST_FAILED'];

function useInvalidateApp(appId: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: p3k.revisions(appId) });
    void qc.invalidateQueries({ queryKey: p3k.app(appId) });
    void qc.invalidateQueries({ queryKey: ['applications'], exact: false });
  };
}

function defaultPostcheck(app: Application): Postcheck {
  const host = app.domains.find((d) => /^[A-Za-z0-9.-]+$/.test(d)) ?? '';
  return { hostHeader: host, path: '/', scheme: 'http', expectStatus: [200] };
}

// ---------- current files ----------

function CurrentFiles({
  app,
  files,
  pendingJob,
}: {
  app: Application;
  files: NginxFileContent[] | null;
  pendingJob: string | null;
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title={t('nginx.files.title')}
        actions={<span className="text-[12px] text-fg-muted">{t('nginx.files.readOnly')}</span>}
      />
      {pendingJob !== null ? (
        <div
          role="status"
          className="flex items-center gap-2 px-4 py-3 text-[13px]"
          data-testid="files-pending"
        >
          <span aria-hidden="true" className="animate-pulse text-info">
            ◌
          </span>
          {t('nginx.files.pending', { job: pendingJob.slice(0, 8) || '…' })}
        </div>
      ) : !files ? null : files.length === 0 ? (
        <p className="m-0 px-4 py-3 text-[13px] text-fg-muted">{t('nginx.files.none')}</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {files.map((f) => {
            const known = app.nginxFiles.find((n) => n.path === f.path)?.lastKnownSha256;
            const changed = !!known && !!f.sha256 && known !== f.sha256;
            return (
              <li key={f.path} className="border-t border-line-subtle first:border-0">
                <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-[13px]">
                  <span className="flex-1 font-mono text-[12.5px] break-all">
                    {f.path}
                    {f.isSymlink && (
                      <span className="block text-[12px] text-fg-muted" data-testid="symlink">
                        {t('nginx.files.symlink', { target: f.resolvedPath ?? '?' })}
                      </span>
                    )}
                  </span>
                  {f.truncated && (
                    <ToneBadge tone="warn" size="sm">
                      {t('nginx.files.truncatedBadge')}
                    </ToneBadge>
                  )}
                  {!f.exists && (
                    <ToneBadge tone="off" size="sm">
                      {t('nginx.files.missing')}
                    </ToneBadge>
                  )}
                  {changed && (
                    <ToneBadge tone="crit" glyph="≠" size="sm">
                      {t('flag.drift')}
                    </ToneBadge>
                  )}
                  <Sha value={f.sha256} />
                  <Button
                    size="xs"
                    variant="chip"
                    aria-expanded={open === f.path}
                    onClick={() => setOpen(open === f.path ? null : f.path)}
                  >
                    {open === f.path ? t('nginx.files.hide') : t('nginx.files.show')}
                  </Button>
                </div>
                {open === f.path && (
                  <pre className="m-0 max-h-[360px] overflow-auto border-t border-line-subtle bg-surface-2 px-4 py-2 font-mono text-[12px] leading-[1.6]">
                    {f.content ?? ''}
                  </pre>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

// ---------- editor ----------

function PostcheckEditor({
  value,
  onChange,
}: {
  value: Postcheck[];
  onChange: (v: Postcheck[]) => void;
}) {
  const { t } = useI18n();
  const set = (i: number, patch: Partial<Postcheck>) =>
    onChange(value.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  return (
    <fieldset className="m-0 flex flex-col gap-2 border-0 p-0">
      <legend className="mb-1 text-[13px] font-semibold">{t('nginx.postcheck.title')}</legend>
      <p className="m-0 text-[12px] text-fg-muted">{t('nginx.postcheck.hint')}</p>
      {value.map((p, i) => (
        <div
          key={i}
          className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_90px_110px_auto] items-end gap-2"
          data-testid="postcheck-row"
        >
          <Field label={t('nginx.postcheck.host')}>
            {(f) => (
              <Input
                {...f}
                value={p.hostHeader}
                onChange={(e) => set(i, { hostHeader: e.target.value.trim() })}
                className="font-mono text-[13px]"
              />
            )}
          </Field>
          <Field label={t('nginx.postcheck.path')}>
            {(f) => (
              <Input
                {...f}
                value={p.path}
                onChange={(e) => set(i, { path: e.target.value.trim() || '/' })}
                className="font-mono text-[13px]"
              />
            )}
          </Field>
          <Field label={t('nginx.postcheck.scheme')}>
            {(f) => (
              <Select
                {...f}
                value={p.scheme}
                onChange={(e) => set(i, { scheme: e.target.value as Postcheck['scheme'] })}
              >
                <option value="http">http</option>
                <option value="https">https</option>
              </Select>
            )}
          </Field>
          <Field label={t('nginx.postcheck.status')}>
            {(f) => (
              <Input
                {...f}
                value={p.expectStatus.join(',')}
                inputMode="numeric"
                onChange={(e) =>
                  set(i, {
                    expectStatus: e.target.value
                      .split(',')
                      .map((x) => Number(x.trim()))
                      .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599),
                  })
                }
                className="font-mono text-[13px]"
              />
            )}
          </Field>
          <Button
            size="sm"
            variant="ghost"
            aria-label={t('nginx.postcheck.remove', { n: i + 1 })}
            onClick={() => onChange(value.filter((_, j) => j !== i))}
          >
            ✕
          </Button>
        </div>
      ))}
      <Button
        size="sm"
        className="self-start"
        disabled={value.length >= 10}
        onClick={() =>
          onChange([...value, { hostHeader: '', path: '/', scheme: 'http', expectStatus: [200] }])
        }
      >
        + {t('nginx.postcheck.add')}
      </Button>
    </fieldset>
  );
}

function DraftEditor({
  app,
  files,
  openRevision,
  onCreated,
}: {
  app: Application;
  files: NginxFileContent[];
  openRevision: NginxRevision | undefined;
  onCreated: (r: NginxRevision) => void;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const invalidate = useInvalidateApp(app.id);
  const [path, setPath] = useState(files[0]?.path ?? '');
  const original = (f: NginxFileContent) => f.content ?? '';
  const target = (f: NginxFileContent) => (f.isSymlink && f.resolvedPath ? f.resolvedPath : f.path);
  const [drafts, setDrafts] = useState<Record<string, string>>(() =>
    Object.fromEntries(files.map((f) => [f.path, original(f)])),
  );
  const currentFile = files.find((f) => f.path === path);
  const unreadable = !!currentFile && (currentFile.content === null || !!currentFile.truncated);
  const [postchecks, setPostchecks] = useState<Postcheck[]>(() => [defaultPostcheck(app)]);
  const changed = files.filter((f) => (drafts[f.path] ?? original(f)) !== original(f));
  const preview = changed.map((f) => ({
    path: target(f),
    diff: unifiedDiff(target(f), f.exists ? original(f) : null, drafts[f.path] ?? ''),
  }));
  const owned = app.ownershipMode === 'adopted' || app.ownershipMode === 'managed';

  const m = useMutation<NginxRevision, ApiError>({
    mutationFn: wrap(() =>
      applicationsApi.createRevision(app.id, {
        files: changed.map((f) => ({ path: target(f), content: drafts[f.path] ?? '' })),
        postchecks: postchecks.filter((p) => p.hostHeader),
      }),
    ),
    onSuccess: (r) => {
      invalidate();
      onCreated(r);
    },
  });

  const blockedReason: { key: MessageKey } | undefined = !owned
    ? { key: 'rev.reason.ownership' }
    : app.flags.driftDetected
      ? { key: 'rev.reason.drift' }
      : openRevision
        ? { key: 'rev.reason.openExists' }
        : undefined;
  const editable = evaluateGate({
    permissions: me?.permissions,
    perm: 'nginx.write',
    action: 'create_revision',
    allowedActions: app.allowedActions,
    blockedReason,
  }).allowed;

  return (
    <Card className="flex flex-col gap-3 p-4" aria-labelledby="draft-title">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="draft-title" className="m-0 flex-1 text-[15px] font-semibold">
          {t('nginx.editor.title')}
        </h2>
        {files.length > 1 && (
          <Select
            aria-label={t('nginx.editor.file')}
            value={path}
            onChange={(e) => setPath(e.target.value)}
            className="w-auto max-w-full font-mono text-[12.5px]"
          >
            {files.map((f) => (
              <option key={f.path} value={f.path}>
                {f.path}
              </option>
            ))}
          </Select>
        )}
      </div>
      {!owned && (
        <Notice tone="info" glyph="◆" role="note">
          {t('nginx.editor.needsOwnership')}
        </Notice>
      )}
      <label htmlFor="nginx-editor" className="font-mono text-[12px] text-fg-muted">
        {currentFile ? target(currentFile) : path}
        {currentFile?.isSymlink && (
          <span className="ml-2 font-sans">
            {t('nginx.files.editsReal', { link: currentFile.path })}
          </span>
        )}
      </label>
      {unreadable && (
        <Notice tone="warn" glyph="▲" role="note">
          {t('nginx.files.truncated')}
        </Notice>
      )}
      <textarea
        id="nginx-editor"
        data-testid="nginx-editor"
        value={drafts[path] ?? ''}
        onChange={(e) => setDrafts((d) => ({ ...d, [path]: e.target.value }))}
        readOnly={!editable || unreadable}
        spellCheck={false}
        rows={16}
        className={cn(
          'w-full resize-y rounded-md border border-line-strong bg-surface p-2.5 font-mono text-[12.5px] leading-[1.6] text-fg',
          !editable && 'bg-chip text-fg-muted',
        )}
      />
      <div className="flex flex-col gap-1.5">
        <h3 className="m-0 text-[13px] font-semibold">{t('nginx.editor.preview')}</h3>
        <DiffViewer files={preview} emptyLabel={t('nginx.editor.noChanges')} />
      </div>
      <PostcheckEditor value={postchecks} onChange={setPostchecks} />
      <div className="flex flex-wrap items-center gap-2">
        <GatedButton
          variant="primary"
          perm="nginx.write"
          action="create_revision"
          allowedActions={app.allowedActions}
          blockedReason={blockedReason}
          disabled={!changed.length || m.isPending}
          onClick={() => m.mutate()}
        >
          {m.isPending ? t('common.saving') : t('nginx.editor.create')}
        </GatedButton>
        {changed.length > 0 && editable && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setDrafts(Object.fromEntries(files.map((f) => [f.path, original(f)])))}
          >
            {t('nginx.editor.reset')}
          </Button>
        )}
        <span className="text-[12px] text-fg-muted">{t('nginx.editor.draftNote')}</span>
      </div>
      {m.error && <ErrorState error={m.error} />}
    </Card>
  );
}

// ---------- revision actions ----------

function JobLine({ serverId, jobId }: { serverId: string; jobId: string | null }) {
  const { t } = useI18n();
  const q = useJob(serverId, jobId);
  if (!jobId) return null;
  return (
    <span className="font-mono text-[12px] text-fg-muted" data-testid="job-line">
      {t('nginx.job', { job: jobId.slice(0, 8), status: q.data?.status ?? '…' })}
    </span>
  );
}

function ApprovalPanel({ rev, app }: { rev: NginxRevision; app: Application }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const invalidate = useInvalidateApp(app.id);
  const toast = useToast();
  const [otp, setOtp] = useState('');
  const gate = revisionGate('approve', {
    rev,
    app,
    permissions: me?.permissions,
    userId: me?.user.id,
  });
  const isCreator = rev.createdBy === me?.user.id;
  const m = useMutation<NginxRevision, ApiError>({
    mutationFn: wrap(async () => {
      const token = (await authApi.stepUp(otp)).stepUpToken;
      return revisionsApi.approve(rev.id, rev.planHash, token);
    }),
    onSuccess: () => {
      setOtp('');
      invalidate();
      toast(t('approval.done'), 'ok');
    },
  });
  if (!rev.approval.required)
    return <p className="m-0 text-[12.5px] text-fg-muted">{t('approval.notRequired')}</p>;
  const expired = approvalExpired(rev);
  return (
    <section
      className="flex flex-col gap-2 rounded-md border border-line p-3"
      aria-labelledby={`appr-${rev.id}`}
      data-testid="approval-panel"
    >
      <h3 id={`appr-${rev.id}`} className="m-0 text-[13.5px] font-semibold">
        {t('approval.title')}
      </h3>
      <dl className="m-0 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
        <dt className="text-fg-muted">{t('approval.planHash')}</dt>
        <dd className="m-0 font-mono text-[12px] break-all" data-testid="plan-hash">
          {rev.planHash}
        </dd>
        <dt className="text-fg-muted">{t('approval.rule')}</dt>
        <dd className="m-0">{t('approval.ruleBody')}</dd>
        {rev.approval.approvedBy && (
          <>
            <dt className="text-fg-muted">{t('approval.approvedBy')}</dt>
            <dd className="m-0">
              {rev.approval.approvedByLabel ?? rev.approval.approvedBy.slice(0, 8)} ·{' '}
              {rev.approval.approvedAt && formatDateTime(rev.approval.approvedAt, locale)}
            </dd>
            <dt className="text-fg-muted">{t('approval.expires')}</dt>
            <dd className={cn('m-0', expired && 'text-crit')}>
              {rev.approval.expiresAt
                ? formatDateTime(rev.approval.expiresAt, locale)
                : t('common.dash')}
              {expired && ` · ${t('approval.expired')}`}
            </dd>
          </>
        )}
      </dl>
      {rev.status === 'awaiting_approval' &&
        (isCreator ? (
          <Notice tone="warn" glyph="◐" role="status">
            <span data-testid="waiting-approver">{t('approval.waiting')}</span>
          </Notice>
        ) : gate.allowed ? (
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[220px] flex-1">
              <StepUpField value={otp} onChange={setOtp} hint={t('approval.stepUpHint')} />
            </div>
            <Button
              variant="primary"
              disabled={!/^\d{6}$/.test(otp) || !me?.mfaEnabled || m.isPending}
              onClick={() => m.mutate()}
            >
              {m.isPending
                ? t('common.saving')
                : t('approval.approve', { hash: rev.planHash.slice(0, 12) })}
            </Button>
          </div>
        ) : (
          <GatedButton perm="approvals.decide" blockedReason={gate.reason}>
            {t('approval.approve', { hash: rev.planHash.slice(0, 12) })}
          </GatedButton>
        ))}
      {m.error && <ErrorState error={m.error} />}
    </section>
  );
}

/** Distinct rendering per agent error code (docs/AGENT_PROTOCOL.md §Nginx). */
function ErrorDetail({ rev }: { rev: NginxRevision }) {
  const { t } = useI18n();
  const code = rev.result?.errorCode ?? 'APPLY_FAILED';
  const d = rev.result?.details;
  const restored = d?.restored === true || REVERTED_CODES.includes(code);
  const known = [
    'PATH_NOT_ALLOWED',
    'DRIFT_DETECTED',
    'NGINX_TEST_FAILED',
    'RELOAD_FAILED_REVERTED',
    'POSTCHECK_FAILED_REVERTED',
    'BACKUP_NOT_FOUND',
  ];
  const body = known.includes(code)
    ? t(`rev.err.${code}` as MessageKey)
    : (rev.result?.message ?? t('rev.failed.generic'));
  return (
    <Notice tone="crit" glyph="✕" role="alert" title={t('rev.failed.title', { code })}>
      <span data-testid="apply-failed" data-code={code}>
        {body}
      </span>
      {restored && code !== 'NGINX_TEST_FAILED' && (
        <span className="mt-1 block font-medium text-ok" data-testid="originals-restored">
          ● {t('rev.failed.restored')}
        </span>
      )}
      {code === 'DRIFT_DETECTED' && d?.files && d.files.length > 0 && (
        <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 text-[12px]">
          {d.files.map((f) => (
            <li key={f.path} className="flex flex-wrap items-center gap-1">
              <span className="font-mono break-all">{f.path}</span>
              <span className="text-fg-muted">{t('rev.err.expected')}</span>
              <Sha value={f.expected} />
              <span className="text-fg-muted">{t('rev.err.actual')}</span>
              <Sha value={f.actual} />
            </li>
          ))}
        </ul>
      )}
      {d?.nginxTestOutput && (
        <pre className="m-0 mt-1 overflow-x-auto rounded bg-surface px-2 py-1 font-mono text-[12px] whitespace-pre-wrap">
          {d.nginxTestOutput}
        </pre>
      )}
    </Notice>
  );
}

function RevisionDetail({
  rev,
  app,
  onUseDrift,
}: {
  rev: NginxRevision;
  app: Application;
  onUseDrift: () => void;
}) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const invalidate = useInvalidateApp(app.id);
  const toast = useToast();
  const [dialog, setDialog] = useState<'apply' | 'revert' | 'cancel' | null>(null);
  const prod = app.environment === 'production';
  const gate = (a: RevisionAction) =>
    revisionGate(a, { rev, app, permissions: me?.permissions, userId: me?.user.id });
  const validate = useMutation<unknown, ApiError>({
    mutationFn: wrap(() => revisionsApi.validate(rev.id)),
    onSuccess: invalidate,
  });
  const busyJob =
    rev.status === 'validating'
      ? (rev.validation?.jobId ?? null)
      : rev.status === 'applying'
        ? rev.applyJobId
        : rev.status === 'reverting'
          ? rev.revertJobId
          : null;
  const steps: Array<[string, boolean, boolean]> = [
    [t('rev.step.draft'), true, false],
    [t('rev.step.validate'), !!rev.validation?.valid, rev.validation?.valid === false],
    ...(rev.approval.required
      ? ([[t('rev.step.approve'), !!rev.approval.approvedBy, false]] as Array<
          [string, boolean, boolean]
        >)
      : []),
    [
      t('rev.step.apply'),
      ['applied', 'reverting', 'reverted', 'superseded'].includes(rev.status),
      rev.status === 'apply_failed' || rev.status === 'requires_manual_recovery',
    ],
  ];
  const errCode = rev.result?.errorCode;
  const applyGate = gate('apply');

  return (
    <div className="flex flex-col gap-3" data-testid="revision-detail" data-status={rev.status}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="m-0 font-mono text-[14px] font-semibold">
          {t('rev.title', { id: rev.id.slice(0, 8) })}
        </h3>
        <RevisionStatusBadge status={rev.status} />
        <span className="text-[12px] text-fg-muted">
          {t('rev.createdBy', {
            who:
              rev.createdBy === me?.user.id
                ? t('rev.you')
                : (rev.createdByLabel ?? rev.createdBy.slice(0, 8)),
            time: formatDateTime(rev.createdAt, locale),
          })}
        </span>
        <JobLine serverId={rev.serverId} jobId={busyJob} />
      </div>
      <ol
        className="m-0 flex list-none flex-wrap gap-1.5 p-0 text-[12px]"
        aria-label={t('rev.steps')}
      >
        {steps.map(([label, done, failed], i) => (
          <li
            key={label}
            className={cn(
              'rounded px-2 py-0.5',
              failed ? 'bg-crit-bg text-crit' : done ? 'bg-ok-bg text-ok' : 'bg-chip text-fg-muted',
            )}
          >
            <span aria-hidden="true">{failed ? '✕' : done ? '✓' : `${i + 1}.`} </span>
            {label}
            <span className="sr-only">
              {failed ? ` (${t('rev.stepFailed')})` : done ? ` (${t('rev.stepDone')})` : ''}
            </span>
          </li>
        ))}
      </ol>

      {(rev.status === 'invalid' || rev.validation?.valid === false) && (
        <Notice tone="crit" glyph="✕" role="alert" title={t('rev.blocked.invalidTitle')}>
          <span data-testid="apply-blocked">{t('rev.blocked.invalidBody')}</span>
        </Notice>
      )}
      {rev.status === 'drift_blocked' && (
        <Notice
          tone="crit"
          glyph="≠"
          role="alert"
          title={t('rev.blocked.driftTitle')}
          action={
            app.flags.driftDetected ? (
              <Button size="sm" onClick={onUseDrift}>
                {t('drift.ackOpen')}
              </Button>
            ) : undefined
          }
        >
          {app.flags.driftDetected ? t('rev.blocked.driftBody') : t('rev.blocked.driftAcked')}
        </Notice>
      )}
      {rev.status === 'requires_manual_recovery' || errCode === 'REVERT_FAILED_MANUAL_RECOVERY' ? (
        <div
          role="alert"
          data-testid="manual-recovery"
          className="flex flex-col gap-1.5 rounded-lg border-2 border-crit bg-crit-bg px-3.5 py-3 text-[13.5px]"
        >
          <b className="text-crit">
            <span aria-hidden="true">✕ </span>
            {t('rev.manual.title')}
          </b>
          <span>{t('rev.failed.manual')}</span>
          {rev.result?.details?.backupDir && (
            <span>
              {t('rev.manual.backupDir')}{' '}
              <code className="font-mono text-[12px] select-all">
                {rev.result.details.backupDir}
              </code>
            </span>
          )}
          {(rev.result?.details?.problems ?? []).length > 0 && (
            <ul className="m-0 list-disc pl-5 font-mono text-[12px]">
              {rev.result!.details!.problems!.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
        </div>
      ) : (
        (rev.status === 'apply_failed' ||
          (rev.status === 'drift_blocked' && !!rev.result?.details?.files?.length)) && (
          <ErrorDetail rev={rev} />
        )
      )}
      {rev.status === 'applied' && (
        <Notice tone="ok" glyph="●" role="status">
          <span data-testid="applied">{t('rev.applied')}</span>
          {(rev.result?.reloadMethod || rev.result?.backupId) && (
            <span className="mt-0.5 block font-mono text-[12px] text-fg-muted">
              {[
                rev.result.reloadMethod && `reload: ${rev.result.reloadMethod}`,
                rev.result.backupId && `backup: ${rev.result.backupId}`,
              ]
                .filter(Boolean)
                .join(' · ')}
            </span>
          )}
        </Notice>
      )}
      {rev.status === 'reverted' && (
        <Notice tone="neutral" role="status">
          {t('rev.reverted')}
        </Notice>
      )}

      <DiffViewer files={rev.files} />

      {rev.postchecks.length > 0 && (
        <div className="flex flex-col gap-1 text-[12.5px]">
          <b className="text-[13px]">{t('nginx.postcheck.title')}</b>
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0 font-mono text-[12px]">
            {rev.postchecks.map((p, i) => {
              const res = (rev.result?.postchecks ?? rev.result?.details?.postchecks)?.find(
                (r) => r.hostHeader === p.hostHeader && r.path === p.path,
              );
              return (
                <li key={i} className="flex flex-wrap items-center gap-2">
                  {p.scheme}://{p.hostHeader}
                  {p.path} → {p.expectStatus.join('|')}
                  {res && (
                    <ToneBadge tone={res.ok ? 'ok' : 'crit'} size="sm">
                      {res.status ?? '—'}
                    </ToneBadge>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {rev.validation?.nginxTestOutput && (
        <div className="flex flex-col gap-1">
          <b className="text-[13px]">
            <code>nginx -t</code> {t('rev.output')}
          </b>
          <pre
            data-testid="nginx-test-output"
            className={cn(
              'm-0 overflow-x-auto rounded-md px-3 py-2 font-mono text-[12px] leading-[1.6] whitespace-pre-wrap',
              rev.validation.valid ? 'bg-ok-bg' : 'bg-crit-bg',
            )}
          >
            {rev.validation.nginxTestOutput}
          </pre>
        </div>
      )}

      <ApprovalPanel rev={rev} app={app} />

      <div className="flex flex-wrap items-center gap-2" data-testid="revision-actions">
        <GatedButton
          perm="nginx.write"
          blockedReason={gate('validate').allowed ? undefined : gate('validate').reason}
          disabled={validate.isPending}
          onClick={() => validate.mutate()}
        >
          {rev.status === 'validating' ? t('rev.validating') : t('rev.validate')}
        </GatedButton>
        <GatedButton
          variant="primary"
          perm="nginx.write"
          blockedReason={applyGate.allowed ? undefined : applyGate.reason}
          onClick={() => setDialog('apply')}
        >
          {rev.status === 'applying' ? t('rev.applying') : t('rev.apply')}
        </GatedButton>
        <GatedButton
          perm="nginx.write"
          blockedReason={gate('revert').allowed ? undefined : gate('revert').reason}
          onClick={() => setDialog('revert')}
        >
          {rev.status === 'reverting' ? t('rev.reverting') : t('rev.revert')}
        </GatedButton>
        {gate('cancel').allowed && (
          <Button variant="ghost" size="sm" onClick={() => setDialog('cancel')}>
            {t('rev.cancel')}
          </Button>
        )}
      </div>
      {!applyGate.allowed &&
        applyGate.reason &&
        rev.status !== 'applied' &&
        !['reverted', 'superseded', 'cancelled'].includes(rev.status) && (
          <span className="text-[12px] text-fg-muted" data-testid="apply-reason">
            {t(applyGate.reason.key, applyGate.reason.vars)}
          </span>
        )}
      {validate.error && <ErrorState error={validate.error} />}

      {dialog === 'apply' && (
        <ActionDialog
          open
          onOpenChange={(o) => !o && setDialog(null)}
          title={t('rev.applyDialog.title')}
          body={t('rev.applyDialog.body')}
          confirmLabel={t('rev.apply')}
          needsStepUp={prod}
          onConfirm={async (tok) => {
            await revisionsApi.apply(rev.id, tok);
            invalidate();
          }}
        />
      )}
      {dialog === 'revert' && (
        <ActionDialog
          open
          danger
          onOpenChange={(o) => !o && setDialog(null)}
          title={t('rev.revertDialog.title')}
          body={t('rev.revertDialog.body')}
          confirmLabel={t('rev.revert')}
          needsStepUp={prod}
          onConfirm={async (tok) => {
            await revisionsApi.revert(rev.id, tok);
            invalidate();
          }}
        />
      )}
      {dialog === 'cancel' && (
        <ActionDialog
          open
          onOpenChange={(o) => !o && setDialog(null)}
          title={t('rev.cancelDialog.title')}
          body={t('rev.cancelDialog.body')}
          confirmLabel={t('rev.cancel')}
          needsStepUp={false}
          onConfirm={async () => {
            await revisionsApi.cancel(rev.id);
            invalidate();
            toast(t('rev.cancelled'), 'ok');
          }}
        />
      )}
    </div>
  );
}

function DriftAckDialog({
  app,
  open,
  onOpenChange,
}: {
  app: Application;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useI18n();
  const invalidate = useInvalidateApp(app.id);
  const qc = useQueryClient();
  return (
    <ActionDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('drift.ackTitle', { name: app.name })}
      body={t('drift.ackBody')}
      confirmLabel={t('drift.ackConfirm')}
      needsStepUp={false}
      onConfirm={async () => {
        const updated = await applicationsApi.acknowledgeDrift(app.id);
        qc.setQueryData(p3k.app(app.id), updated);
        void qc.invalidateQueries({ queryKey: p3k.files(app.id) });
        invalidate();
      }}
    />
  );
}

// ---------- tab ----------

export function NginxTab({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const allowed = can('nginx.read');
  const files = useNginxFiles(app.id, allowed);
  const revs = useRevisions(app.id, allowed);
  const [selected, setSelected] = useState<string | null>(null);
  const [driftOpen, setDriftOpen] = useState(false);
  const items = useMemo(() => revs.data?.items ?? [], [revs.data]);
  const openRevision = items.find((r) => OPEN.includes(r.status));
  const current = items.find((r) => r.id === selected) ?? items[0];
  useEffect(() => {
    if (selected && !items.some((r) => r.id === selected)) setSelected(null);
  }, [items, selected]);
  // Host files change after apply/revert: re-read them so the editor starts from the new baseline.
  const qc = useQueryClient();
  const settled = items
    .filter((r) => r.status === 'applied' || r.status === 'reverted')
    .map((r) => `${r.id}:${r.status}`)
    .join(',');
  useEffect(() => {
    if (settled) void qc.invalidateQueries({ queryKey: p3k.files(app.id) });
  }, [settled, qc, app.id]);

  if (!allowed)
    return (
      <Notice tone="neutral" role="alert" title={t('state.forbidden.title')}>
        {t('state.forbidden.body', { perm: 'nginx.read' })}
      </Notice>
    );

  const fileData = files.data?.state === 'ready' ? files.data.files : null;
  const pendingJob =
    files.data?.state === 'pending' ? files.data.jobId : files.isPending ? '' : null;

  return (
    <div className="flex flex-col gap-4">
      <Notice tone="info" glyph="◆" role="note">
        {t('nginx.flow')}
      </Notice>
      {app.flags.driftDetected && (
        <Notice
          tone="crit"
          glyph="≠"
          role="alert"
          title={t('drift.title')}
          action={
            <GatedButton
              size="sm"
              perm="nginx.write"
              action="acknowledge_drift"
              allowedActions={app.allowedActions}
              onClick={() => setDriftOpen(true)}
            >
              {t('drift.ackOpen')}
            </GatedButton>
          }
        >
          {t('drift.body')}
          {app.driftFiles.length > 0 && (
            <ul
              className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 text-[12px]"
              data-testid="drift-files"
            >
              {app.driftFiles.map((f) => (
                <li key={f.path} className="flex flex-wrap items-center gap-1">
                  <span className="font-mono break-all">{f.path}</span>
                  <Sha value={f.lastKnownSha256} />
                  <span aria-hidden="true">→</span>
                  <span className="sr-only">{t('diff.to')}</span>
                  {f.currentSha256 === 'unknown' ? (
                    <span>{t('drift.unknown')}</span>
                  ) : (
                    <Sha value={f.currentSha256} />
                  )}
                </li>
              ))}
            </ul>
          )}
        </Notice>
      )}
      {files.isError && <ErrorState error={files.error} onRetry={() => void files.refetch()} />}
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-4">
          <CurrentFiles app={app} files={fileData} pendingJob={pendingJob} />
          {fileData && (
            <DraftEditor
              key={fileData.map((f) => f.sha256).join('|')}
              app={app}
              files={fileData}
              openRevision={openRevision}
              onCreated={(r) => setSelected(r.id)}
            />
          )}
        </div>
        <Card className="flex flex-col gap-3 p-4" aria-labelledby="revs-title">
          <h2 id="revs-title" className="m-0 text-[15px] font-semibold">
            {t('rev.timeline')}
          </h2>
          {revs.isPending ? (
            <TableSkeleton label={t('common.loading')} rows={3} />
          ) : revs.isError ? (
            <ErrorState error={revs.error} onRetry={() => void revs.refetch()} />
          ) : items.length === 0 ? (
            <EmptyState title={t('rev.empty')} body={t('rev.emptyBody')} />
          ) : (
            <>
              <ol className="m-0 flex list-none flex-col gap-1 p-0" aria-label={t('rev.timeline')}>
                {items.map((r) => (
                  <li key={r.id}>
                    <button
                      type="button"
                      aria-pressed={r.id === current?.id}
                      onClick={() => setSelected(r.id)}
                      className={cn(
                        'flex w-full flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-left text-[12.5px]',
                        r.id === current?.id
                          ? 'border-accent-strong bg-info-bg'
                          : 'border-line bg-surface hover:bg-surface-hover',
                      )}
                    >
                      <span className="font-mono">{r.id.slice(0, 8)}</span>
                      <RevisionStatusBadge status={r.status} />
                      <span className="text-fg-muted">{formatDateTime(r.createdAt, locale)}</span>
                      <span className="ml-auto text-fg-muted">
                        {r.createdByLabel ?? r.createdBy.slice(0, 8)}
                      </span>
                    </button>
                  </li>
                ))}
              </ol>
              {current && (
                <RevisionDetail
                  key={current.id}
                  rev={current}
                  app={app}
                  onUseDrift={() => setDriftOpen(true)}
                />
              )}
            </>
          )}
        </Card>
      </div>
      {driftOpen && <DriftAckDialog app={app} open={driftOpen} onOpenChange={setDriftOpen} />}
    </div>
  );
}
