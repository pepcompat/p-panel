import type { MessageKey } from '@/i18n/en';

type TFn = (key: MessageKey, vars?: Record<string, string | number>) => string;

export function relativeTime(iso: string | null | undefined, t: TFn, now: number = Date.now()): string {
  if (!iso) return t('time.never');
  const sec = Math.round((now - new Date(iso).getTime()) / 1000);
  if (!Number.isFinite(sec)) return t('common.unknown');
  if (sec < 2) return t('time.justNow');
  if (sec < 60) return t('time.secondsAgo', { n: sec });
  if (sec < 3600) return t('time.minutesAgo', { n: Math.floor(sec / 60) });
  if (sec < 86400) return t('time.hoursAgo', { n: Math.floor(sec / 3600) });
  return t('time.daysAgo', { n: Math.floor(sec / 86400) });
}

/** Local time with explicit zone, e.g. "14:32:08 ICT (UTC+7)". Stored values stay UTC ISO-8601. */
export function formatClock(d: Date | number, locale: string): string {
  const date = typeof d === 'number' ? new Date(d) : d;
  const time = date.toLocaleTimeString(locale === 'th' ? 'th-TH' : 'en-GB', { hour12: false });
  const off = -date.getTimezoneOffset() / 60;
  const tz = `UTC${off >= 0 ? '+' : ''}${off}`;
  return `${time} (${tz})`;
}

export function formatDateTime(iso: string, locale: string): string {
  const d = new Date(iso);
  return d.toLocaleString(locale === 'th' ? 'th-TH' : 'en-GB', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
