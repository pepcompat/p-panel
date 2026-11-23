import { Injectable } from '@nestjs/common';
import type { Job as JobRow } from '@prisma/client';
import { logger } from '../common/logger';

/** A job that reached a terminal state (succeeded | failed | expired | cancelled). */
export type FinishedJob = Pick<
  JobRow,
  'id' | 'serverId' | 'type' | 'status' | 'params' | 'result' | 'error' | 'actorId'
>;
export type JobFinishedHandler = (job: FinishedJob) => Promise<void>;

/**
 * Post-commit job completion hooks (P3: scan ingest, revision state machine).
 * Handlers MUST be idempotent per jobId: they can run more than once (agent replay, reconcile sweep).
 * A handler failure never fails the agent's result call; the reconcile sweep retries it.
 */
@Injectable()
export class JobHooks {
  private readonly handlers = new Map<string, JobFinishedHandler[]>();
  private readonly reconcilers: Array<() => Promise<unknown>> = [];

  /** Periodic repair: re-dispatch terminal jobs whose workflow object is still in an in-flight state. */
  registerReconciler(fn: () => Promise<unknown>): void {
    this.reconcilers.push(fn);
  }

  async reconcileAll(): Promise<void> {
    for (const fn of this.reconcilers) {
      try {
        await fn();
      } catch (err) {
        logger.emit('error', 'job reconcile failed', { err });
      }
    }
  }

  /** Several workflows may observe the same job type (e.g. `nginx.apply`: revisions, deployments, routing). */
  register(type: string, handler: JobFinishedHandler): void {
    const list = this.handlers.get(type) ?? [];
    list.push(handler);
    this.handlers.set(type, list);
  }

  has(type: string): boolean {
    return this.handlers.has(type);
  }

  async dispatch(job: FinishedJob): Promise<void> {
    for (const h of this.handlers.get(job.type) ?? []) {
      try {
        await h(job);
      } catch (err) {
        logger.emit('error', 'job finished hook failed', { jobId: job.id, type: job.type, err });
      }
    }
  }
}
