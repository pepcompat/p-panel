/**
 * P3 read models. Source of truth: `@ppanel/shared-contracts` (discovery.ts, owned by the API agent).
 * This file re-exports those types and adds the few optional, web-requested display fields
 * (marked "web-requested"); the UI never depends on them being present.
 */
import type {
  AdoptionReview,
  Application as SharedApplication,
  DiscoveryFinding as SharedFinding,
  DiscoveryScan as SharedScan,
  NginxFilesRead,
  NginxRevision as SharedRevision,
} from '@ppanel/shared-contracts';

export type {
  DiscoverySource,
  DiscoveryScanStatus as ScanStatus,
  FindingConfidence as Confidence,
  FindingKind,
  OwnershipMode,
  ApplicationKind as AppKind,
  NginxRevisionStatus as RevisionStatus,
} from '@ppanel/shared-contracts';
import type {
  NginxRevisionStatus,
  OwnershipMode as OM,
  FindingKind as FK,
} from '@ppanel/shared-contracts';

export type DiscoveryScan = SharedScan;
export type ScanSummary = NonNullable<SharedScan['summary']>;
export type DriftEntry = SharedScan['drift'][number];
export type DiscoveryFinding = SharedFinding;

/** Display order of finding groups. */
export const FINDING_KINDS: FK[] = [
  'nginx_server',
  'upstream',
  'php_fpm_pool',
  'listener',
  'container',
  'systemd_unit',
];
export const OWNERSHIP_ORDER: OM[] = ['discovered', 'observed', 'adopted', 'managed'];
export type ImportMode = Extract<OM, 'discovered' | 'observed'>;

export type Application = SharedApplication & {
  /** web-requested: display name of the server. */
  serverName?: string;
};
export type AppFlags = SharedApplication['flags'];

export type OwnershipChange = AdoptionReview & {
  /** web-requested */
  actorLabel?: string | null;
};

export type NginxFileContent = NginxFilesRead['files'][number] & { sizeBytes?: number };
export type NginxFilesResponse =
  { state: 'ready'; files: NginxFileContent[] } | { state: 'pending'; jobId: string };

export const REVISION_BUSY: NginxRevisionStatus[] = ['validating', 'applying', 'reverting'];

export type Postcheck = SharedRevision['postchecks'][number];

export type NginxRevision = Omit<SharedRevision, 'result' | 'approval'> & {
  approval: SharedRevision['approval'] & {
    /** web-requested */
    approvedByLabel?: string | null;
  };
  /** Last job outcome (agent result or error), see RevisionResult. */
  result: RevisionResult | null;
  /** web-requested */
  createdByLabel?: string | null;
};
export type RevisionFile = SharedRevision['files'][number];

export interface PostcheckResult {
  hostHeader: string;
  path: string;
  status: number | null;
  ok: boolean;
  error?: string;
}

/** Agent nginx.* job result / error, flattened by the Center onto the revision. */
export interface RevisionResult {
  errorCode?: string;
  message?: string;
  applied?: boolean;
  reverted?: boolean;
  reloadMethod?: 'systemctl' | 'nginx -s reload' | string;
  backupId?: string;
  nginxTestOutput?: string;
  postchecks?: PostcheckResult[];
  details?: {
    files?: Array<{ path: string; expected?: string | null; actual?: string | null }>;
    nginxTestOutput?: string;
    postchecks?: PostcheckResult[];
    restored?: boolean;
    backupDir?: string;
    problems?: string[];
    [k: string]: unknown;
  };
  [k: string]: unknown;
}
