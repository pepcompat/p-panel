import { en, type MessageKey } from './en';
import { th } from './th';

export const LOCALES = ['en', 'th'] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = 'en';
export const LANG_STORAGE_KEY = 'ppanel.lang';

export type Dictionary = Partial<Record<MessageKey, string>>;
export const dictionaries: Record<Locale, Dictionary> = { en, th };

export type Vars = Record<string, string | number>;

function interpolate(s: string, vars?: Vars) {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

/** Look up a key in `dict`, falling back to English, then to the key itself. */
export function translate(dict: Dictionary, key: MessageKey, vars?: Vars): string {
  const raw = dict[key] ?? en[key] ?? key;
  return interpolate(raw, vars);
}

/** Keys present in English but absent (or empty) in `dict`. */
export function missingKeys(dict: Dictionary, base: Record<string, string> = en): string[] {
  return Object.keys(base).filter((k) => !dict[k as MessageKey]);
}

/** Keys present in `dict` that English does not define (typos / stale keys). */
export function extraKeys(
  dict: Record<string, string | undefined>,
  base: Record<string, string> = en,
): string[] {
  return Object.keys(dict).filter((k) => !(k in base));
}

export function isLocale(v: unknown): v is Locale {
  return typeof v === 'string' && (LOCALES as readonly string[]).includes(v);
}
