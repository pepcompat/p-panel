'use client';

import type { ReactNode } from 'react';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import type {
  AppFlags,
  Confidence,
  OwnershipMode,
  RevisionStatus,
  ScanStatus,
} from '@/lib/api/p3-types';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Field, Input } from '@/components/ui/form';
import { Notice } from '@/components/ui/states';
import type { MessageKey } from '@/i18n/en';

const OWN: Record<OwnershipMode, { tone: Tone; glyph: string }> = {
  discovered: { tone: 'off', glyph: '○' },
  observed: { tone: 'info', glyph: '◐' },
  adopted: { tone: 'stale', glyph: '◑' },
  managed: { tone: 'ok', glyph: '●' },
};

export const ownKey = (m: OwnershipMode) => `own.mode.${m}` as MessageKey;

export function OwnershipBadge({ mode }: { mode: OwnershipMode }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={OWN[mode].tone} glyph={OWN[mode].glyph} className="font-medium">
      {t(ownKey(mode))}
    </ToneBadge>
  );
}

export function FlagBadges({ flags, compact }: { flags: AppFlags; compact?: boolean }) {
  const { t } = useI18n();
  const items: Array<[boolean, Tone, string, MessageKey]> = [
    [flags.manualReview, 'warn', '▲', 'flag.manualReview'],
    [flags.conflict, 'crit', '✕', 'flag.conflict'],
    [flags.unsupported, 'info', '◆', 'flag.unsupported'],
    [flags.driftDetected, 'crit', '≠', 'flag.drift'],
  ];
  const on = items.filter(([v]) => v);
  if (!on.length)
    return compact ? <span className="text-[12px] text-fg-subtle">{t('common.none')}</span> : null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {on.map(([, tone, glyph, key]) => (
        <ToneBadge key={key} tone={tone} glyph={glyph} size="sm">
          {t(key)}
        </ToneBadge>
      ))}
    </span>
  );
}

export function ConfidenceBadge({ c }: { c: Confidence }) {
  const { t } = useI18n();
  const tone: Tone = c === 'high' ? 'ok' : c === 'medium' ? 'warn' : 'crit';
  return (
    <ToneBadge tone={tone} glyph={c === 'high' ? '●' : c === 'medium' ? '◐' : '○'} size="sm">
      {t('finding.confidence', { level: t(`finding.conf.${c}` as MessageKey) })}
    </ToneBadge>
  );
}

const SCAN_TONE: Record<ScanStatus, Tone> = {
  running: 'info',
  completed: 'ok',
  failed: 'crit',
  expired: 'off',
};
export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={SCAN_TONE[status]} glyph={status === 'running' ? '◌' : undefined}>
      {t(`scan.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

export const REV_TONE: Record<RevisionStatus, Tone> = {
  draft: 'off',
  validating: 'info',
  valid: 'ok',
  invalid: 'crit',
  awaiting_approval: 'warn',
  approved: 'ok',
  applying: 'info',
  applied: 'ok',
  apply_failed: 'crit',
  reverting: 'info',
  reverted: 'off',
  drift_blocked: 'crit',
  requires_manual_recovery: 'crit',
  superseded: 'off',
  cancelled: 'off',
};
export function RevisionStatusBadge({ status }: { status: RevisionStatus }) {
  const { t } = useI18n();
  const busy = status === 'validating' || status === 'applying' || status === 'reverting';
  return (
    <ToneBadge tone={REV_TONE[status]} glyph={busy ? '◌' : undefined}>
      {t(`rev.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

/** Short checksum with the full value available to copy/select and to screen readers. */
export function Sha({ value }: { value: string | null | undefined }) {
  const { t } = useI18n();
  if (!value)
    return <span className="font-mono text-[12px] text-fg-subtle">{t('common.dash')}</span>;
  return (
    <span className="font-mono text-[12px]" title={value}>
      <span aria-hidden="true">{value.slice(0, 12)}…</span>
      <span className="sr-only">{value}</span>
    </span>
  );
}

/** 6-digit step-up field (X-Step-Up). Shows the 2FA setup link when the user has no TOTP. */
export function StepUpField({
  value,
  onChange,
  hint,
}: {
  value: string;
  onChange: (v: string) => void;
  hint?: ReactNode;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  if (!me?.mfaEnabled)
    return (
      <Notice tone="crit" glyph="✕" role="alert">
        {t('stepUp.mfaMissing')} <a href="/setup/2fa">{t('security.setup')}</a>
      </Notice>
    );
  return (
    <Field label={t('stepUp.label')} hint={hint ?? t('stepUp.hint')}>
      {(p) => (
        <Input
          {...p}
          value={value}
          onChange={(e) => onChange(e.target.value.replace(/\D/g, '').slice(0, 6))}
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="000000"
          className="font-mono text-[15px] tracking-[.2em]"
        />
      )}
    </Field>
  );
}

export function SectionTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <h2 className="m-0 flex-1 text-[15px] font-semibold">{children}</h2>
      {actions}
    </div>
  );
}
