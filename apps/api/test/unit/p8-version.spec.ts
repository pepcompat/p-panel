import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/config';
import {
  compareSemver,
  deriveMinAgentVersion,
  isAgentOutdated,
  parseSemver,
  resolveBuildInfo,
} from '../../src/version/build-info';

const base = {
  DATABASE_URL: 'postgresql://x:y@127.0.0.1:5432/z',
  PPANEL_MASTER_KEY: Buffer.alloc(32, 1).toString('base64'),
  JWT_ACCESS_SECRET: 'x'.repeat(40),
};

describe('P8 version policy', () => {
  it('SemVer precedence incl. prereleases', () => {
    const order = [
      '0.1.0-dev',
      '0.1.0',
      '0.7.0-rc.1',
      '0.7.0-rc.2',
      '0.7.0-rc.10',
      '0.7.0',
      '0.8.0-rc.1',
      '0.8.0',
      '1.0.0',
    ];
    for (let i = 1; i < order.length; i++)
      expect(compareSemver(parseSemver(order[i - 1])!, parseSemver(order[i])!)).toBeLessThan(0);
    expect(compareSemver(parseSemver('v0.8.0')!, parseSemver('0.8.0+build.5')!)).toBe(0);
    expect(parseSemver('dev')).toBeNull();
    expect(parseSemver('0.8')).toBeNull();
  });

  it('minAgentVersion = N-1 minor', () => {
    expect(deriveMinAgentVersion('0.8.0-rc.1')).toBe('0.7.0');
    expect(deriveMinAgentVersion('1.4.2')).toBe('1.3.0');
    expect(deriveMinAgentVersion('2.0.1')).toBe('2.0.0');
    expect(deriveMinAgentVersion('garbage')).toBe('0.0.0');
  });

  it('isAgentOutdated only judges parseable versions', () => {
    expect(isAgentOutdated('0.6.9', '0.7.0')).toBe(true);
    expect(isAgentOutdated('0.7.0', '0.7.0')).toBe(false);
    expect(isAgentOutdated('0.9.0', '0.7.0')).toBe(false); // newer agents: protocol major decides
    expect(isAgentOutdated(null, '0.7.0')).toBe(false);
    expect(isAgentOutdated('dev', '0.7.0')).toBe(false);
  });

  it('config: production derives the minimum, dev/test default to 0.0.0, env overrides', () => {
    expect(
      loadConfig({ ...base, NODE_ENV: 'production', PPANEL_VERSION: '0.8.0-rc.1' }).minAgentVersion,
    ).toBe('0.7.0');
    expect(loadConfig({ ...base, NODE_ENV: 'test', PPANEL_VERSION: '0.8.0' }).minAgentVersion).toBe(
      '0.0.0',
    );
    expect(
      loadConfig({
        ...base,
        NODE_ENV: 'production',
        PPANEL_VERSION: '0.8.0',
        PPANEL_MIN_AGENT_VERSION: '0.5.0',
      }).minAgentVersion,
    ).toBe('0.5.0');
    expect(() => loadConfig({ ...base, PPANEL_MIN_AGENT_VERSION: 'latest' })).toThrow(/SemVer/);
    // compose passes empty strings for unset optional values
    const c = loadConfig({
      ...base,
      NODE_ENV: 'production',
      PPANEL_VERSION: '0.8.0',
      PPANEL_MIN_AGENT_VERSION: '',
      PPANEL_AGENT_DOWNLOAD_BASE: '',
    });
    expect(c.minAgentVersion).toBe('0.7.0');
    expect(c.PPANEL_AGENT_DOWNLOAD_BASE).toBeUndefined();
  });

  it('build info: env wins, buildDate normalised to ISO UTC, invalid date → null', () => {
    expect(
      resolveBuildInfo({
        PPANEL_VERSION: '1.2.3',
        PPANEL_COMMIT: 'deadbee',
        PPANEL_BUILD_DATE: '2026-11-24T10:00:00Z',
      }),
    ).toEqual({
      version: '1.2.3',
      commit: 'deadbee',
      buildDate: '2026-11-24T10:00:00.000Z',
    });
    expect(
      resolveBuildInfo({ PPANEL_VERSION: '1.2.3', PPANEL_BUILD_DATE: 'yesterday' }).buildDate,
    ).toBeNull();
    // source checkout: falls back to the root VERSION file
    expect(parseSemver(resolveBuildInfo({}).version)).not.toBeNull();
  });
});

describe('P8 enrollment install command', () => {
  it('pins the release of this Center, honours a mirror, falls back to latest for dev builds', async () => {
    const { agentInstallCommand } = await import('../../src/enrollments/enrollments.service');
    const rel = loadConfig({ ...base, PPANEL_VERSION: '0.8.0-rc.1' });
    expect(agentInstallCommand(rel, 'https://center.example', 'ppe_x')).toBe(
      'curl -fsSLO https://github.com/pepcompat/ppanel/releases/download/v0.8.0-rc.1/install-agent.sh && sudo bash install-agent.sh --center-url https://center.example --token ppe_x --version 0.8.0-rc.1',
    );
    const mirror = loadConfig({
      ...base,
      PPANEL_VERSION: '0.8.0',
      PPANEL_AGENT_DOWNLOAD_BASE: 'https://dl.example/ppanel/',
    });
    expect(agentInstallCommand(mirror, 'https://c', 't')).toMatch(
      /^curl -fsSLO https:\/\/dl\.example\/ppanel\/install-agent\.sh /,
    );
    const dev = loadConfig({ ...base, PPANEL_VERSION: '0.0.0-dev' });
    expect(agentInstallCommand(dev, 'https://c', 't')).toBe(
      'curl -fsSLO https://github.com/pepcompat/ppanel/releases/latest/download/install-agent.sh && sudo bash install-agent.sh --center-url https://c --token t',
    );
    expect(() => loadConfig({ ...base, PPANEL_AGENT_DOWNLOAD_BASE: 'http://dl.example' })).toThrow(
      /https/,
    );
  });
});
