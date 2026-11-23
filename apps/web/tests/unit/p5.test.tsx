import { describe, expect, it, vi, afterEach } from 'vitest';
import { screen } from '@testing-library/react';
import { api } from '@/lib/api';
import { logsApi, toLogQuery } from '@/lib/api/p5-endpoints';
import { parseRetryAfter } from '@/lib/api/client';
import { formatMetric, nullRuns, seriesToPath, summarize, yDomain } from '@/lib/charts';
import { TailBuffer, parseTailData, type TailLine } from '@/lib/log-tail';
import { canAckIncident, validateLogRange, validateRule, webhookUrlHints } from '@/lib/p5-gates';
import { TAIL_BUFFER_MAX, type Incident, type MetricSeries } from '@/lib/api/p5-types';
import { MetricChart } from '@/components/p5/metric-chart';
import { fleetState } from '@/components/p5/monitoring-view';
import { meWithRole, renderWith } from './test-utils';

afterEach(() => vi.restoreAllMocks());

const x = (t: number) => t;
const y = (v: number) => 100 - v;

describe('charts: series → path with gaps', () => {
  it('breaks the path at null points instead of drawing 0', () => {
    const r = seriesToPath(
      [
        [0, 10],
        [1, 20],
        [2, null],
        [3, null],
        [4, 30],
        [5, 40],
      ],
      x,
      y,
    );
    expect(r.segments).toHaveLength(2);
    expect(r.d).toBe('M0,90L1,80M4,70L5,60');
    expect(r.gapRuns).toBe(1);
    expect(r.nullPoints).toBe(2);
    // A null mapped to 0 would produce y=100 — it must never appear.
    expect(r.d).not.toContain(',100');
  });

  it('handles leading / trailing gaps and an all-null series', () => {
    expect(
      seriesToPath(
        [
          [0, null],
          [1, 5],
          [2, null],
        ],
        x,
        y,
      ).d,
    ).toBe('M1,95');
    const empty = seriesToPath(
      [
        [0, null],
        [1, null],
      ],
      x,
      y,
    );
    expect(empty.d).toBe('');
    expect(empty.segments).toHaveLength(0);
    expect(empty.gapRuns).toBe(1);
  });

  it('reports null runs and a summary that ignores gaps', () => {
    const pts: Array<[number, number | null]> = [
      [0, null],
      [60, 4],
      [120, null],
      [180, null],
      [240, 8],
    ];
    expect(nullRuns(pts)).toEqual([
      [0, 0],
      [120, 180],
    ]);
    const s = summarize(pts);
    expect(s).toMatchObject({ min: 4, max: 8, last: 8, lastAt: 240, samples: 2, gapRuns: 2 });
  });

  it('uses a 0–100 domain for percent and a nice max for bytes', () => {
    expect(yDomain([[0, 3]], 'percent')).toEqual([0, 100]);
    expect(yDomain([[0, 1500]], 'bytes_per_second')[1]).toBe(2048);
  });
});

describe('charts: unit formatting', () => {
  it('formats percent, bytes, bytes/s, bool and missing values', () => {
    expect(formatMetric(38.24, 'percent')).toBe('38%');
    expect(formatMetric(4.25, 'percent')).toBe('4.3%');
    expect(formatMetric(512, 'bytes')).toBe('512 B');
    expect(formatMetric(1536, 'bytes')).toBe('1.5 KiB');
    expect(formatMetric(250 * 1024 * 1024, 'bytes')).toBe('250 MiB');
    expect(formatMetric(2.5 * 1024 * 1024, 'bytes_per_second')).toBe('2.5 MiB/s');
    expect(formatMetric(1, 'bool')).toBe('up');
    expect(formatMetric(0, 'bool')).toBe('down');
    expect(formatMetric(null, 'percent', 'No data')).toBe('No data');
    expect(formatMetric(undefined, 'bytes')).toBe('—');
  });
});

describe('live tail buffer', () => {
  const line = (i: number): TailLine => ({
    id: String(i),
    ts: new Date(i * 1000).toISOString(),
    serverId: 's1',
    appId: null,
    source: 'nginx_access',
    level: 'info',
    line: `l${i}`,
  });

  it(`caps at ${TAIL_BUFFER_MAX} lines and counts dropped ones`, () => {
    const b = new TailBuffer();
    b.push(Array.from({ length: 1500 }, (_, i) => line(i)));
    b.push(Array.from({ length: 900 }, (_, i) => line(1500 + i)));
    expect(b.size).toBe(TAIL_BUFFER_MAX);
    expect(b.dropped).toBe(400);
    expect(b.snapshot()[0]!.line).toBe('l400');
    expect(b.lastId).toBe('2399');
  });

  it('parses SSE payloads as data only and skips malformed events', () => {
    expect(parseTailData('not json', '1')).toEqual([]);
    expect(parseTailData('{"ts":"x"}', '1')).toEqual([]);
    const [l] = parseTailData(
      JSON.stringify({
        ts: '2026-11-23T03:00:00Z',
        serverId: 's1',
        source: 'nginx_access',
        level: 'warn',
        line: '<b>hi</b> api_key=[REDACTED]',
      }),
      '2026-11-23T03:00:00Z',
    );
    expect(l!.line).toBe('<b>hi</b> api_key=[REDACTED]');
    expect(l!.id).toBe('2026-11-23T03:00:00Z');
  });
});

describe('logs: typed params only (no LogQL built client-side)', () => {
  it('whitelists fields and passes the text filter as a plain substring', () => {
    const q = toLogQuery({
      serverId: '01934f2a-0000-7000-8000-000000000001',
      source: 'nginx_access',
      level: 'warn',
      q: '  {app="x"} |= "boom"  ',
      from: '2026-11-23T00:00:00.000Z',
      to: '2026-11-23T01:00:00.000Z',
      limit: 5000,
      direction: 'backward',
      // @ts-expect-error — not part of the typed params, must be dropped
      query: '{server_id=~".+"}',
      logql: 'sum(rate({job="x"}[5m]))',
    });
    expect(Object.keys(q).sort()).toEqual(
      ['direction', 'from', 'level', 'limit', 'q', 'serverId', 'source', 'to'].sort(),
    );
    expect(q.q).toBe('{app="x"} |= "boom"');
    expect(q.limit).toBe(1000);
  });

  it('drops unknown enums and caps q at 200 chars', () => {
    const q = toLogQuery({
      // @ts-expect-error invalid enum
      source: 'kernel"} |~ ".*',
      // @ts-expect-error invalid enum
      level: 'critical',
      q: 'a'.repeat(300),
      from: 'f',
      to: 't',
    });
    expect(q.source).toBeUndefined();
    expect(q.level).toBeUndefined();
    expect(String(q.q)).toHaveLength(200);
  });

  it('logsApi.query sends only the typed query keys', async () => {
    const spy = vi.spyOn(api, 'request').mockResolvedValue({
      data: [],
      meta: { requestId: 'r1', retention: { days: 7 } } as never,
      paginate: { hasMore: false, nextCursor: null } as never,
      status: 200,
      requestId: 'r1',
      headers: new Headers(),
    });
    const r = await logsApi.query({
      appId: 'app-1',
      q: 'error',
      from: 'a',
      to: 'b',
      cursor: 'c1',
    });
    const [method, path, opts] = spy.mock.calls[0]!;
    expect(method).toBe('GET');
    expect(path).toBe('/logs/query');
    expect(Object.keys(opts!.query!).sort()).toEqual(['appId', 'cursor', 'from', 'q', 'to']);
    expect(JSON.stringify(opts)).not.toMatch(/logql|\|=|\{server_id/);
    expect(r.retentionDays).toBe(7);
    expect(r.hasMore).toBe(false);
  });

  it('tail URL carries the token and Last-Event-ID resume point', () => {
    const u = new URL(logsApi.tailUrl('tok', { serverId: 'srv-1', level: 'warn' }, 'ts-1'));
    expect(u.pathname.endsWith('/logs/tail')).toBe(true);
    expect(Object.fromEntries(u.searchParams)).toEqual({
      token: 'tok',
      serverId: 'srv-1',
      level: 'warn',
      lastEventId: 'ts-1',
    });
  });

  it('validates the time range (≤ 7 days, ordered)', () => {
    const now = Date.now();
    expect(validateLogRange(now - 3600e3, now)).toBeNull();
    expect(validateLogRange(now, now - 1)).toBe('logs.err.order');
    expect(validateLogRange(now - 8 * 864e5, now)).toBe('logs.err.span');
  });
});

describe('rate limit + gates', () => {
  it('parses Retry-After seconds and dates', () => {
    expect(parseRetryAfter('3')).toBe(3);
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter(new Date(10_000).toUTCString(), 0)).toBe(10);
  });

  const inc = (over: Partial<Incident> = {}): Incident => ({
    id: 'i1',
    ruleId: 'r1',
    ruleName: 'disk-high',
    kind: 'metric_threshold',
    target: { type: 'server', id: 's1', name: 'app-prod-01' },
    serverId: 's1',
    environment: 'production',
    severity: 'critical',
    status: 'firing',
    startedAt: new Date().toISOString(),
    acknowledgedAt: null,
    acknowledgedBy: null,
    resolvedAt: null,
    lastValue: 91,
    timeline: [],
    ...over,
  });

  it('acknowledge needs servers.operate in the target scope', () => {
    expect(canAckIncident(meWithRole('viewer'), inc())).toBe(false);
    expect(canAckIncident(meWithRole('deployer'), inc())).toBe(false);
    expect(canAckIncident(meWithRole('ops_admin'), inc())).toBe(true);
    expect(canAckIncident(meWithRole('ops_admin'), inc({ status: 'resolved' }))).toBe(false);
    const scoped = meWithRole('ops_admin');
    scoped.bindings = [
      { id: 'b', userId: 'u1', roleKey: 'ops_admin', scopeType: 'environment', scopeId: 'uat' },
    ];
    expect(canAckIncident(scoped, inc())).toBe(false);
    expect(
      canAckIncident(
        scoped,
        inc({
          target: { type: 'server', id: 's2', name: 'x' },
          serverId: 's2',
          environment: 'uat',
        }),
      ),
    ).toBe(true);
    // The Center's per-incident allowedActions wins when present.
    expect(canAckIncident(meWithRole('viewer'), inc({ allowedActions: ['acknowledge'] }))).toBe(
      true,
    );
  });

  it('hints webhook URLs (https, private addresses, credentials)', () => {
    const levels = (u: string) => webhookUrlHints(u).map((h) => `${h.level}:${h.key}`);
    expect(levels('https://hooks.example.com/x')).toEqual(['ok:ch.hint.ok']);
    expect(levels('http://hooks.example.com/x')).toContain('warn:ch.hint.http');
    expect(levels('https://169.254.169.254/latest')).toContain('warn:ch.hint.private');
    expect(levels('https://10.0.0.5/hook')).toContain('warn:ch.hint.private');
    expect(levels('https://user:pw@hooks.example.com')).toContain('error:ch.hint.userinfo');
    expect(levels('ftp://x')).toEqual(['error:ch.hint.invalidUrl']);
  });

  it('validates threshold rules', () => {
    const base = {
      name: 'cpu-high',
      enabled: true,
      scopeType: 'global' as const,
      scopeId: null,
      kind: 'metric_threshold' as const,
      severity: 'warning' as const,
      forSec: 60,
      channelIds: [],
    };
    expect(validateRule({ ...base, params: { metric: 'cpu', op: 'gt', value: 85 } })).toEqual({});
    expect(validateRule({ ...base, params: { metric: 'cpu', op: 'gt', value: 150 } }).value).toBe(
      'rule.err.pct',
    );
    expect(
      validateRule({ ...base, scopeType: 'server', params: { metric: 'disk', op: 'gt', value: 9 } })
        .scopeId,
    ).toBe('rule.err.scope');
  });
});

describe('fleet + chart states (D4-A)', () => {
  it('offline, stale and never-reported are distinct', () => {
    const sample = { cpuPct: 10, memPct: 20, diskPct: 30, sampledAt: new Date().toISOString() };
    expect(fleetState({ status: 'offline', sample, stale: true })).toBe('offline');
    expect(fleetState({ status: 'stale', sample, stale: true })).toBe('stale');
    expect(fleetState({ status: 'online', sample: null, stale: false })).toBe('no_metrics');
    expect(fleetState({ status: 'online', sample, stale: false })).toBe('ok');
  });

  const series = (over: Partial<MetricSeries> = {}): MetricSeries => ({
    scope: 'server',
    id: 's1',
    range: '1h',
    step: 60,
    from: 1000,
    to: 1180,
    metric: 'cpu',
    unit: 'percent',
    points: [
      [1000, 10],
      [1060, 20],
      [1120, null],
      [1180, 30],
    ],
    gaps: [[1120, 1180]],
    lastSampleAt: new Date(1180_000).toISOString(),
    stale: false,
    ...over,
  });

  it('renders gaps (data attributes + summary) and a stale marker', () => {
    renderWith(<MetricChart series={series({ stale: true })} title="CPU" range="1h" />);
    const fig = screen.getByTestId('metric-chart');
    expect(fig).toHaveAttribute('data-gaps', '1');
    expect(fig).toHaveAttribute('data-segments', '2');
    expect(fig).toHaveAttribute('data-null-points', '1');
    expect(fig).toHaveAttribute('data-stale', 'true');
    expect(screen.getAllByTestId('chart-gap')).toHaveLength(1);
    expect(screen.getByTestId('stale-marker')).toBeInTheDocument();
    expect(screen.getByTestId('chart-summary').textContent).toMatch(/1 gap\(s\)/);
    expect(screen.getByTestId('series-path').getAttribute('d')).toMatch(/^M.*M/);
  });

  it('shows "no metrics reported" instead of a flat 0 line', () => {
    renderWith(
      <MetricChart
        series={series({
          points: [
            [1, null],
            [2, null],
          ],
          lastSampleAt: null,
        })}
        title="CPU"
        range="1h"
      />,
    );
    expect(screen.getByTestId('metric-chart')).toHaveAttribute('data-never', 'true');
    expect(screen.getByTestId('chart-never')).toHaveTextContent('No metrics reported yet');
    expect(screen.queryByTestId('series-path')).toBeNull();
  });
});
