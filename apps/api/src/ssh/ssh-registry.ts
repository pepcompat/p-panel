import { Injectable } from '@nestjs/common';
import type { SshEndReason } from '@ppanel/shared-contracts';

/** A live WebSocket ↔ SSH bridge in this process. */
export interface LiveSshSession {
  sessionId: string;
  userId: string;
  serverId: string;
  grantId: string;
  credentialFingerprint: string;
  /** idempotent; resolves once the SSH connection is gone and the row is closed */
  close(reason: SshEndReason, wsCode: number, message?: string): Promise<void>;
}

/**
 * In-process registry of live sessions so revocations (grant, credential), the expiry sweeper,
 * terminate and shutdown can close them. A single Center process owns its sockets.
 */
@Injectable()
export class SshSessionRegistry {
  private readonly live = new Map<string, LiveSshSession>();

  add(s: LiveSshSession): void {
    this.live.set(s.sessionId, s);
  }

  remove(sessionId: string): void {
    this.live.delete(sessionId);
  }

  get(sessionId: string): LiveSshSession | undefined {
    return this.live.get(sessionId);
  }

  get size(): number {
    return this.live.size;
  }

  async closeWhere(
    pred: (s: LiveSshSession) => boolean,
    reason: SshEndReason,
    wsCode: number,
    message?: string,
  ): Promise<number> {
    const hit = [...this.live.values()].filter(pred);
    await Promise.all(hit.map((s) => s.close(reason, wsCode, message)));
    return hit.length;
  }
}
