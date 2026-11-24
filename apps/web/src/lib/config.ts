export const API_BASE = (
  process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:4000/api/v1'
).replace(/\/+$/, '');
export const API_MOCK = process.env.NEXT_PUBLIC_API_MOCK === '1';
export const CLIENT_VERSION = '0.8.0-rc.1';

/**
 * Optional client-side hint of the Center's PPANEL_GIT_HOST_ALLOWLIST (comma-separated hosts). The
 * Center enforces the real list; the UI only uses it to warn early. Mock mode has a demo list.
 */
export const GIT_HOST_ALLOWLIST: readonly string[] = (
  process.env.NEXT_PUBLIC_GIT_HOST_ALLOWLIST ??
  (API_MOCK ? 'github.com,gitlab.com,git.example.lab' : '')
)
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);
