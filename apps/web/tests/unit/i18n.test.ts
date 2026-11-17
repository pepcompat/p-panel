import { describe, expect, it } from 'vitest';
import { en } from '@/i18n/en';
import { th } from '@/i18n/th';
import { extraKeys, missingKeys, translate } from '@/i18n/core';

describe('i18n', () => {
  it('falls back to English when a key is missing in the active locale', () => {
    expect(translate({}, 'servers.title')).toBe(en['servers.title']);
    expect(translate({ 'login.title': 'เข้าสู่ระบบ' }, 'login.continue')).toBe('Continue');
    expect(translate(th, 'login.title')).toBe('เข้าสู่ระบบ');
  });

  it('interpolates {placeholders} and leaves unknown ones intact', () => {
    expect(translate({}, 'top.fleetOnline', { online: 6, total: 8 })).toBe('6/8 online');
    expect(translate({}, 'common.page', { page: 2 })).toBe('Page 2 of {pages}');
  });

  it('reports missing th keys (fails if any key is untranslated)', () => {
    const missing = missingKeys(th);
    if (missing.length) console.warn(`[i18n] th is missing ${missing.length} key(s):\n  ${missing.join('\n  ')}`);
    expect(missing).toEqual([]);
  });

  it('missingKeys detects gaps', () => {
    expect(missingKeys({ 'login.title': 'x' }, { 'login.title': 'a', 'login.email': 'b' })).toEqual(['login.email']);
  });

  it('th has no keys that English does not define', () => {
    expect(extraKeys(th)).toEqual([]);
  });

  it('keeps placeholders consistent between en and th', () => {
    const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join(',');
    const mismatched = (Object.keys(en) as Array<keyof typeof en>).filter((k) => th[k] && ph(en[k]) !== ph(th[k]!));
    expect(mismatched).toEqual([]);
  });
});
