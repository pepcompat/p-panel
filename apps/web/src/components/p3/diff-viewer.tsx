'use client';

import { useI18n } from '@/i18n/provider';
import { diffStats, parseUnifiedDiff, type DiffLine } from '@/lib/diff';
import { cn } from '@/lib/utils';
import { Sha } from './bits';

export interface DiffFile {
  path: string;
  diff: string;
  beforeSha256?: string | null;
  afterSha256?: string | null;
}

const rowClass: Record<DiffLine['type'], string> = {
  add: 'bg-ok-bg',
  del: 'bg-crit-bg',
  ctx: '',
  hunk: 'bg-info-bg text-info',
  meta: 'text-fg-muted',
};
const markClass: Record<DiffLine['type'], string> = {
  add: 'text-ok font-bold',
  del: 'text-crit font-bold',
  ctx: 'text-fg-subtle',
  hunk: '',
  meta: '',
};

/**
 * Unified diff viewer. Added/removed lines are coloured AND carry a visible "+"/"−" marker plus a
 * screen-reader label, so meaning never depends on colour. Rendered as a table with line numbers.
 */
export function DiffViewer({ files, emptyLabel }: { files: DiffFile[]; emptyLabel?: string }) {
  const { t } = useI18n();
  if (!files.length || files.every((f) => !f.diff.trim()))
    return (
      <p className="m-0 px-4 py-3 text-[13px] text-fg-muted" data-testid="diff-empty">
        {emptyLabel ?? t('diff.noChanges')}
      </p>
    );
  return (
    <div className="flex flex-col gap-3" data-testid="diff-viewer">
      {files.map((f) => {
        const stats = diffStats(f.diff);
        const rows = parseUnifiedDiff(f.diff).filter((r) => r.type !== 'meta');
        return (
          <figure key={f.path} className="m-0 overflow-hidden rounded-md border border-line">
            <figcaption className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line-soft bg-surface-2 px-3 py-2 text-[12.5px]">
              <span className="font-mono font-medium break-all">{f.path}</span>
              <span className="font-mono text-ok" aria-label={t('diff.added', { n: stats.added })}>
                +{stats.added}
              </span>
              <span
                className="font-mono text-crit"
                aria-label={t('diff.removed', { n: stats.removed })}
              >
                −{stats.removed}
              </span>
              {(f.beforeSha256 !== undefined || f.afterSha256 !== undefined) && (
                <span className="ml-auto flex items-center gap-1 text-fg-muted">
                  {f.beforeSha256 === null ? (
                    <span className="text-[12px]">{t('diff.newFile')}</span>
                  ) : (
                    <Sha value={f.beforeSha256} />
                  )}
                  <span aria-hidden="true">→</span>
                  <span className="sr-only">{t('diff.to')}</span>
                  <Sha value={f.afterSha256} />
                </span>
              )}
            </figcaption>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse font-mono text-[12.5px] leading-[1.7]">
                <caption className="sr-only">{t('diff.caption', { path: f.path })}</caption>
                <thead className="sr-only">
                  <tr>
                    <th scope="col">{t('diff.col.old')}</th>
                    <th scope="col">{t('diff.col.new')}</th>
                    <th scope="col">{t('diff.col.change')}</th>
                    <th scope="col">{t('diff.col.line')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={i} className={rowClass[r.type]} data-diff={r.type}>
                      {r.type === 'hunk' ? (
                        <td colSpan={4} className="px-3 text-[12px] whitespace-pre">
                          {r.text}
                        </td>
                      ) : (
                        <>
                          <td className="w-[44px] pr-2 text-right text-fg-subtle select-none">
                            {r.oldNo ?? ''}
                          </td>
                          <td className="w-[44px] pr-2 text-right text-fg-subtle select-none">
                            {r.newNo ?? ''}
                          </td>
                          <td className={cn('w-[18px] text-center select-none', markClass[r.type])}>
                            <span aria-hidden="true">
                              {r.type === 'add' ? '+' : r.type === 'del' ? '−' : ' '}
                            </span>
                            <span className="sr-only">
                              {r.type === 'add'
                                ? t('diff.lineAdded')
                                : r.type === 'del'
                                  ? t('diff.lineRemoved')
                                  : t('diff.lineUnchanged')}
                            </span>
                          </td>
                          <td className="pr-3 whitespace-pre">{r.text || ' '}</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </figure>
        );
      })}
    </div>
  );
}
