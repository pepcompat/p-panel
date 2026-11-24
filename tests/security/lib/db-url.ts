/** Isolated database for the security suite (never `ppanel_test`, never a lab/prod database). */
const base =
  process.env.TEST_DATABASE_BASE ?? 'postgresql://ppanel:ppanel_dev_only@127.0.0.1:55432';
export const SECURITY_DATABASE_URL =
  process.env.SECURITY_DATABASE_URL ?? `${base}/ppanel_security?schema=public`;
