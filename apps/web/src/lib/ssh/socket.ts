import { API_MOCK } from '@/lib/config';
import type { SocketFactory, SshSocketLike } from './connection';

/** Mock mode (NEXT_PUBLIC_API_MOCK=1) can opt into the browser WebSocket so e2e can route it. */
export const MOCK_REAL_WS_KEY = 'ppanel.mock.realWs';

function mockWantsRealWs(): boolean {
  try {
    return window.sessionStorage.getItem(MOCK_REAL_WS_KEY) === '1';
  } catch {
    return false;
  }
}

const browserSocket: SocketFactory = (url) => new WebSocket(url) as unknown as SshSocketLike;

/**
 * The browser WebSocket in real mode; in mock mode an in-process fake gateway (src/mocks/mock-ssh-socket.ts),
 * loaded lazily so mock code never ships in the real bundle path.
 */
export async function resolveSocketFactory(): Promise<SocketFactory> {
  if (!API_MOCK || mockWantsRealWs()) return browserSocket;
  const m = await import('@/mocks/mock-ssh-socket');
  return (url) => new m.MockSshSocket(url);
}
