import 'reflect-metadata';
import { loadConfig } from './config/config';
import { createApp } from './create-app';
import { logger } from './common/logger';

async function main(): Promise<void> {
  const config = loadConfig();
  const app = await createApp(config);
  await app.listen(config.API_PORT, config.API_HOST);
  logger.emit('info', 'pPanel Center API listening', { port: config.API_PORT, host: config.API_HOST, env: config.NODE_ENV });
}

main().catch((err: unknown) => {
  logger.emit('fatal', 'failed to start Center API', { err });
  process.exit(1);
});
