import { Injectable } from '@nestjs/common';

/** In-process wake-up for long-polling agents. DB polling remains the source of truth (multi-instance safe). */
@Injectable()
export class JobNotifier {
  private readonly waiters = new Map<string, Set<() => void>>();

  notify(serverId: string): void {
    const set = this.waiters.get(serverId);
    if (!set) return;
    this.waiters.delete(serverId);
    for (const fn of set) fn();
  }

  wait(serverId: string, ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      let set = this.waiters.get(serverId);
      if (!set) this.waiters.set(serverId, (set = new Set()));
      const done = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', done);
        this.waiters.get(serverId)?.delete(done);
        resolve();
      };
      const timer = setTimeout(done, Math.max(0, ms));
      signal?.addEventListener('abort', done, { once: true });
      set.add(done);
    });
  }
}
