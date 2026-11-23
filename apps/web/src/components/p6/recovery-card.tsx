'use client';

import Link from 'next/link';
import { useI18n } from '@/i18n/provider';
import { useRepositories } from '@/lib/p6-queries';
import { formatDateTime } from '@/lib/time';
import { Card } from '@/components/ui/card';
import { ErrorState } from '@/components/ui/states';

const STEPS = [
  'sec.recovery.s1',
  'sec.recovery.s2',
  'sec.recovery.s3',
  'sec.recovery.s4',
  'sec.recovery.s5',
] as const;

/** Settings → Security: recovery runbook summary + repository recovery-export status (P6.06). */
export function RecoveryCard() {
  const { t, locale } = useI18n();
  const repos = useRepositories();
  return (
    <Card className="flex flex-col gap-2.5 p-4" id="recovery-runbook" data-testid="recovery-card">
      <h2 className="m-0 text-[15px] font-semibold">{t('sec.recovery.title')}</h2>
      <p className="m-0 text-[13px] text-fg-3">{t('sec.recovery.body')}</p>
      <h3 className="m-0 text-[13.5px] font-semibold">{t('sec.recovery.runbook')}</h3>
      <ol className="m-0 flex flex-col gap-1 pl-5 text-[13px]">
        {STEPS.map((k) => (
          <li key={k}>{t(k)}</li>
        ))}
      </ol>
      <p className="m-0 font-mono text-[12px] text-fg-muted">{t('sec.recovery.doc')}</p>
      <h3 className="m-0 text-[13.5px] font-semibold">{t('sec.recovery.export')}</h3>
      {repos.isError && <ErrorState error={repos.error} />}
      <ul
        className="m-0 flex list-none flex-col gap-0.5 p-0 text-[13px]"
        data-testid="recovery-export-status"
      >
        {(repos.data ?? []).map((r) => (
          <li key={r.id} className={r.lastRecoveryExportAt === null ? 'text-warn' : undefined}>
            <span aria-hidden="true">
              {r.lastRecoveryExportAt ? '● ' : r.lastRecoveryExportAt === null ? '▲ ' : '◆ '}
            </span>
            {r.lastRecoveryExportAt
              ? t('sec.recovery.exportAt', {
                  repo: r.name,
                  date: formatDateTime(r.lastRecoveryExportAt, locale),
                })
              : r.lastRecoveryExportAt === null
                ? t('sec.recovery.exportNever', { repo: r.name })
                : t('sec.recovery.exportUnknown', { repo: r.name })}
          </li>
        ))}
      </ul>
      <Link href="/backups?tab=repositories" className="self-start text-[13px]">
        {t('sec.recovery.manage')}
      </Link>
    </Card>
  );
}
