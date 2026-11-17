export interface AuditEvent {
  id: string;
  actorId: string | null;
  actorType: 'user' | 'agent' | 'system' | 'anonymous';
  action: string;
  targetType: string | null;
  targetId: string | null;
  result: 'success' | 'failure' | 'denied';
  requestId: string | null;
  diffHash: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

/** snake_case filter fields accepted by GET /audit-events (`field[op]=value`). */
export const AUDIT_FILTER_FIELDS = [
  'action',
  'actor_id',
  'actor_type',
  'target_id',
  'target_type',
  'result',
  'request_id',
  'created_at',
] as const;
