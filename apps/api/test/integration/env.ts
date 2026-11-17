const base = process.env.TEST_DATABASE_BASE ?? 'postgresql://ppanel:ppanel_dev_only@127.0.0.1:55432';
export const TEST_DB_NAME = 'ppanel_test';
export const ADMIN_DATABASE_URL = `${base}/ppanel?schema=public`;
export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? `${base}/${TEST_DB_NAME}?schema=public`;
