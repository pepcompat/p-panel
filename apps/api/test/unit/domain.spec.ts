import { JOB_TYPES } from '@ppanel/shared-contracts';
import { describe, expect, it } from 'vitest';
import { bindingCovers } from '../../src/auth/authz.service';
import { resourceKeyFor } from '../../src/jobs/jobs.service';
import { normalizeSerial } from '../../src/pki/ca.service';
import { deriveStatus } from '../../src/servers/server-view';

const b = (scopeType: string, scopeId: string | null = null) => ({
  id: '1',
  userId: 'u',
  roleKey: 'viewer',
  scopeType,
  scopeId,
});

describe('RBAC scope coverage (global ⊇ environment ⊇ server)', () => {
  it('global covers everything incl. unscoped resources', () => {
    expect(bindingCovers(b('global'), undefined)).toBe(true);
    expect(bindingCovers(b('global'), { environment: 'production', serverId: 's1' })).toBe(true);
  });
  it('environment covers servers in that environment only', () => {
    expect(bindingCovers(b('environment', 'uat'), { environment: 'uat', serverId: 's1' })).toBe(
      true,
    );
    expect(
      bindingCovers(b('environment', 'uat'), { environment: 'production', serverId: 's1' }),
    ).toBe(false);
    expect(bindingCovers(b('environment', 'uat'), undefined)).toBe(false);
  });
  it('server covers only that server', () => {
    expect(bindingCovers(b('server', 's1'), { environment: 'uat', serverId: 's1' })).toBe(true);
    expect(bindingCovers(b('server', 's1'), { environment: 'uat', serverId: 's2' })).toBe(false);
  });
});

describe('server status derivation', () => {
  const now = 1_000_000_000;
  it('online → stale (>45s) → offline (>120s); revoked/enrolling sticky', () => {
    expect(deriveStatus('online', new Date(now - 10_000), now)).toBe('online');
    expect(deriveStatus('degraded', new Date(now - 10_000), now)).toBe('degraded');
    expect(deriveStatus('online', new Date(now - 46_000), now)).toBe('stale');
    expect(deriveStatus('online', new Date(now - 121_000), now)).toBe('offline');
    expect(deriveStatus('online', null, now)).toBe('offline');
    expect(deriveStatus('revoked', new Date(now), now)).toBe('revoked');
    expect(deriveStatus('enrolling', null, now)).toBe('enrolling');
  });
});

describe('jobs', () => {
  it('JOB_TYPES classify mutating jobs and validate params strictly', () => {
    expect(JOB_TYPES['service.restart'].mutating).toBe(true);
    expect(JOB_TYPES['inventory.collect'].mutating).toBe(false);
    expect(JOB_TYPES['service.restart'].params.safeParse({ unit: 'nginx.service' }).success).toBe(
      true,
    );
    expect(
      JOB_TYPES['service.restart'].params.safeParse({ unit: '../../etc/passwd' }).success,
    ).toBe(false);
    expect(
      JOB_TYPES['service.restart'].params.safeParse({ unit: 'nginx.service', extra: 1 }).success,
    ).toBe(false);
    expect(
      JOB_TYPES['service.restart'].params.safeParse({ unit: 'php8.3-fpm.service' }).success,
    ).toBe(true);
    expect(JOB_TYPES['service.restart'].params.safeParse({ unit: 'a..b.service' }).success).toBe(
      false,
    );
    expect(JOB_TYPES['service.restart'].params.safeParse({ unit: '-x.service' }).success).toBe(
      false,
    );
    expect(JOB_TYPES['service.restart'].params.safeParse({ unit: '.service' }).success).toBe(false);
    expect(
      JOB_TYPES['discovery.scan'].params.safeParse({ sources: ['nginx', 'nginx'] }).success,
    ).toBe(false);
    expect(
      JOB_TYPES['discovery.scan'].params.safeParse({ sources: ['nginx', 'docker'] }).success,
    ).toBe(true);
  });
  it('resource lock keys', () => {
    expect(resourceKeyFor('service.restart', { unit: 'nginx.service' })).toBe('unit:nginx.service');
    expect(resourceKeyFor('inventory.collect', {})).toBeNull();
  });
});

describe('certificate serial normalisation', () => {
  it('matches Node getPeerCertificate() formatting', () => {
    expect(normalizeSerial('00:1A:2b')).toBe('1a2b');
    expect(normalizeSerial('1A2B')).toBe('1a2b');
  });
});
