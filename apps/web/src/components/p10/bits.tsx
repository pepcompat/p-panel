'use client';

import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import type {
  CredentialStatus,
  DeploymentStatus,
  GrantStatus,
  HostKeyStatus,
  SessionStatus,
} from '@/lib/api/p10-types';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { CopyButton } from '@/components/ui/copy-button';
import { cn } from '@/lib/utils';

const CRED_TONE: Record<CredentialStatus, Tone> = { active: 'ok', rotated: 'off', revoked: 'crit' };
export function CredentialStatusBadge({ status }: { status: CredentialStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={CRED_TONE[status]} size="sm">
      {t(`p10.cred.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

const DEP_TONE: Record<DeploymentStatus, Tone> = {
  pending: 'info',
  installed: 'ok',
  removing: 'info',
  removed: 'off',
  failed: 'crit',
};
export function DeploymentStatusBadge({ status }: { status: DeploymentStatus }) {
  const { t } = useI18n();
  const busy = status === 'pending' || status === 'removing';
  return (
    <ToneBadge tone={DEP_TONE[status]} glyph={busy ? '◌' : undefined} size="sm">
      {t(`p10.dep.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

const HK_TONE: Record<HostKeyStatus, Tone> = {
  pending: 'warn',
  trusted: 'ok',
  rejected: 'crit',
  superseded: 'off',
};
export function HostKeyStatusBadge({ status }: { status: HostKeyStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={HK_TONE[status]} size="sm">
      {t(`p10.hk.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

const GRANT_TONE: Record<GrantStatus, Tone> = {
  awaiting_approval: 'warn',
  active: 'ok',
  expired: 'off',
  revoked: 'crit',
  rejected: 'crit',
};
export function GrantStatusBadge({ status }: { status: GrantStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={GRANT_TONE[status]} size="sm">
      {t(`p10.grant.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

const SESSION_TONE: Record<SessionStatus, Tone> = {
  pending: 'info',
  open: 'ok',
  closed: 'off',
  failed: 'crit',
};
export function SessionStatusBadge({ status }: { status: SessionStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={SESSION_TONE[status]} size="sm">
      {t(`p10.session.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

/** Agent facts (independent mTLS channel) vs the key the host presented. */
export function AgentMatch({ value }: { value: boolean | null }) {
  const { t } = useI18n();
  if (value === true)
    return (
      <ToneBadge tone="ok" glyph="✓" size="sm">
        <span data-testid="agent-match" data-match="true">
          {t('p10.hk.agent.match')}
        </span>
      </ToneBadge>
    );
  if (value === false)
    return (
      <ToneBadge tone="crit" glyph="✕" size="sm">
        <span data-testid="agent-match" data-match="false">
          {t('p10.hk.agent.mismatch')}
        </span>
      </ToneBadge>
    );
  return (
    <ToneBadge tone="off" size="sm">
      <span data-testid="agent-match" data-match="unknown">
        {t('p10.hk.agent.unknown')}
      </span>
    </ToneBadge>
  );
}

/** Full SHA256 fingerprint, selectable and copyable (public data). */
export function Fingerprint({ value, label }: { value: string | null; label?: string }) {
  const { t } = useI18n();
  if (!value) return <span className="text-fg-subtle">{t('common.dash')}</span>;
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <code className="font-mono text-[11.5px] break-all select-all" data-testid="fingerprint">
        {value}
      </code>
      <CopyButton text={value} ariaLabel={label ?? t('p10.copyFingerprint')} />
    </span>
  );
}

/** Accessible tab strip (roving tabindex, arrows / Home / End) that drives `tabpanel`s by id. */
export function TabStrip<V extends string>({
  label,
  idPrefix,
  tabs,
  value,
  onChange,
  className,
}: {
  label: string;
  idPrefix: string;
  tabs: Array<{ value: V; label: ReactNode; extra?: ReactNode }>;
  value: V;
  onChange: (v: V) => void;
  className?: string;
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    let n = -1;
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') n = 0;
    else if (e.key === 'End') n = tabs.length - 1;
    if (n < 0) return;
    e.preventDefault();
    onChange(tabs[n]!.value);
    refs.current[n]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label={label}
      className={cn('flex gap-0.5 overflow-x-auto border-b border-line', className)}
    >
      {tabs.map((tb, i) => {
        const on = tb.value === value;
        return (
          <button
            key={tb.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            id={`${idPrefix}-tab-${tb.value}`}
            role="tab"
            type="button"
            aria-selected={on}
            aria-controls={`${idPrefix}-panel-${tb.value}`}
            tabIndex={on ? 0 : -1}
            onClick={() => onChange(tb.value)}
            onKeyDown={(e) => onKey(e, i)}
            className={cn(
              'flex min-h-10 shrink-0 items-center gap-1.5 border-0 border-b-2 bg-transparent px-3 text-[13px] whitespace-nowrap focus-visible:-outline-offset-2',
              on
                ? 'border-accent-strong font-medium text-fg'
                : 'border-transparent text-fg-muted hover:text-fg',
            )}
          >
            {tb.label}
            {tb.extra}
          </button>
        );
      })}
    </div>
  );
}

export function SectionTitle({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <h2 id={id} className="m-0 text-[15px] font-semibold">
      {children}
    </h2>
  );
}
