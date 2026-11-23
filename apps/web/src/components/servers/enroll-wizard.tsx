'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ENVIRONMENTS, type EnrollmentCreated, type Environment } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { enrollmentsApi } from '@/lib/api/endpoints';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { qk } from '@/lib/queries';
import { envLabelKey } from '@/lib/servers';
import { formatClock, formatDuration } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { Button } from '@/components/ui/button';
import { CopyButton } from '@/components/ui/copy-button';
import { Field, Input, Select } from '@/components/ui/form';
import { Segmented } from '@/components/ui/segmented';
import { Notice } from '@/components/ui/states';
import { EnvBadge } from '@/components/ui/badge';
import { envBadgeKey } from '@/lib/servers';

const TTL_OPTIONS = [5, 10, 15, 30, 60];

function TokenView({
  result,
  onDone,
  onAnother,
}: {
  result: EnrollmentCreated;
  onDone: () => void;
  onAnother: () => void;
}) {
  const { t, locale } = useI18n();
  const now = useNow(1000);
  const remaining = new Date(result.expiresAt).getTime() - now;
  const expired = remaining <= 0;
  const steps: Array<[string, string, string]> = [
    ['●', 'text-ok', t('enroll.step.token')],
    ['◆', 'text-info', t('enroll.step.install')],
    ['○', 'text-fg-muted', t('enroll.step.connect')],
    ['○', 'text-fg-muted', t('enroll.step.appear')],
  ];
  return (
    <div className="flex flex-col gap-3.5">
      {expired ? (
        <Notice tone="crit" glyph="✕" role="alert">
          {t('enroll.expired')}
        </Notice>
      ) : (
        <Notice tone="warn" glyph="▲" role="alert" title={t('enroll.tokenTitle')}>
          {t('enroll.tokenWarn')}{' '}
          <span className="font-mono">
            {t('enroll.expires', {
              time: formatClock(new Date(result.expiresAt), locale),
              remaining: formatDuration(remaining),
            })}
          </span>
        </Notice>
      )}
      <div>
        <div className="mb-1 text-[12.5px] text-fg-3">{t('enroll.installCommand')}</div>
        <pre
          aria-label={t('enroll.installCommand')}
          className={`m-0 rounded-md bg-terminal p-3 font-mono text-[12px] leading-[1.7] break-all whitespace-pre-wrap text-terminal-fg ${expired ? 'opacity-40' : ''}`}
        >
          {result.installCommand}
        </pre>
      </div>
      <CopyButton
        text={result.installCommand}
        label={t('enroll.copyCommand')}
        variant="secondary"
        size="md"
        disabled={expired}
      />
      <ol className="m-0 flex list-none flex-col gap-1.5 p-0 text-[13px]">
        {steps.map(([g, c, label]) => (
          <li key={label} className="flex gap-2">
            <span aria-hidden="true" className={`w-3.5 font-bold ${c}`}>
              {g}
            </span>
            <span>{label}</span>
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={onDone}>
          {t('enroll.done')}
        </Button>
        <Button onClick={onAnother}>{t('enroll.another')}</Button>
      </div>
    </div>
  );
}

export function EnrollWizard({
  onClose,
  defaultEnv = 'production',
}: {
  onClose?: () => void;
  defaultEnv?: Environment;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const [env, setEnv] = useState<Environment>(defaultEnv);
  const [tags, setTags] = useState('');
  const [ttl, setTtl] = useState(15);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  // The token lives only in component state and is dropped on close — never persisted or logged.
  const [result, setResult] = useState<EnrollmentCreated | null>(null);

  if (result) {
    return (
      <TokenView
        result={result}
        onDone={() => {
          setResult(null);
          onClose?.();
        }}
        onAnother={() => {
          setResult(null);
          setName('');
          setTags('');
        }}
      />
    );
  }

  const fe = error?.fieldErrors ?? {};
  const tagList = tags
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return (
    <form
      noValidate
      className="flex flex-col gap-3.5"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          const res = await enrollmentsApi.create({
            name: name.trim(),
            environment: env,
            tags: tagList.length ? tagList : undefined,
            ttlMinutes: ttl,
          });
          setResult(res);
          void qc.invalidateQueries({ queryKey: qk.servers });
        } catch (err) {
          setError(toApiError(err));
        } finally {
          setBusy(false);
        }
      }}
    >
      <Field label={t('enroll.name')} hint={t('enroll.nameHint')} error={fe.name}>
        {(p) => (
          <Input
            {...p}
            value={name}
            onChange={(e) => setName(e.target.value.toLowerCase())}
            placeholder="app-prod-04"
            className="font-mono text-[13px]"
            autoComplete="off"
            pattern="[a-z0-9][a-z0-9-]*"
            maxLength={63}
          />
        )}
      </Field>
      <div className="flex flex-col gap-1">
        <span className="text-[12.5px] text-fg-3" id="enroll-env-label">
          {t('enroll.environment')}
        </span>
        <Segmented<Environment>
          label={t('enroll.environment')}
          value={env}
          onChange={setEnv}
          options={ENVIRONMENTS.map((e) => ({ value: e, label: t(envLabelKey(e)) }))}
          className="self-start"
        />
        {fe.environment && <span className="text-[12px] text-crit">{fe.environment}</span>}
      </div>
      <Field label={t('enroll.tags')} hint={t('enroll.tagsHint')} error={fe.tags}>
        {(p) => (
          <Input
            {...p}
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="web"
            autoComplete="off"
          />
        )}
      </Field>
      <Field label={t('enroll.ttl')} error={fe.ttlMinutes}>
        {(p) => (
          <Select {...p} value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
            {TTL_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {t('enroll.ttlMinutes', { n })}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <div className="flex flex-wrap gap-2">
        <EnvBadge env={env} label={t(envBadgeKey(env))} />
        {tagList.map((tag) => (
          <span key={tag} className="rounded bg-chip-2 px-2.5 py-0.5 text-[12px]">
            tag: {tag}
          </span>
        ))}
      </div>
      {env === 'production' && (
        <p className="m-0 text-[12px] text-fg-muted">{t('enroll.prodWarn')}</p>
      )}
      <p className="m-0 text-[12px] text-fg-muted">{t('env.note')}</p>
      {error && Object.keys(fe).length === 0 && (
        <div
          role="alert"
          className="rounded-md border border-crit bg-crit-bg px-3 py-2 text-[13px]"
        >
          {error.message}
          {error.requestId && (
            <div className="font-mono text-[11.5px] text-fg-muted">
              {t('common.requestId')}: {error.requestId}
            </div>
          )}
        </div>
      )}
      <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
        {busy ? t('enroll.creating') : t('enroll.submit')}
      </Button>
    </form>
  );
}
