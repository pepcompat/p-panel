/**
 * P5 pure logic: shared redaction golden vectors (P5-T03), PromQL/LogQL templates + escaping
 * (P5-T02 injection), null gaps, timestamps, SSRF guard, byte budget, label checks, schemas.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  agentLogBatchSchema,
  createAlertRuleSchema,
  createChannelSchema,
  heartbeatSchema,
  logsQuerySchema,
  metricsSeriesQuerySchema,
  REDACTED,
  REDACTION_PATTERNS,
  redactLine,
  validateAlertRule,
} from '@ppanel/shared-contracts';
import { ByteBucket } from '../../src/observability/byte-bucket';
import { maskUrl } from '../../src/observability/channels.service';
import { containerBelongs, truncateLine } from '../../src/observability/log-ingest.service';
import { renderText } from '../../src/observability/notifier.service';
import {
  appPromQL,
  buildLogQL,
  escapeQuoted,
  fillGrid,
  gapsOf,
  isoToNs,
  nsToIso,
  renderFamily,
  serverPromQL,
} from '../../src/observability/query-templates';
import {
  checkWebhookUrl,
  isPrivateAddress,
  resolveWebhookTarget,
  type WebhookPolicy,
} from '../../src/observability/ssrf';

const SID = '01900000-0000-7000-8000-000000000001';
const SID2 = '01900000-0000-7000-8000-000000000002';
const AID = '01900000-0000-7000-8000-0000000000aa';

describe('P5-T03 redaction golden file (shared-contracts/testdata/redaction-golden.json)', () => {
  const golden = JSON.parse(
    readFileSync(
      path.resolve(
        __dirname,
        '../../../../packages/shared-contracts/testdata/redaction-golden.json',
      ),
      'utf8',
    ),
  ) as { cases: Array<{ in: string; out: string }> };

  it('has vectors and every pattern is RE2-compatible (no lookbehind / backreference)', () => {
    expect(golden.cases.length).toBeGreaterThanOrEqual(10);
    for (const p of REDACTION_PATTERNS) {
      expect(p.source).not.toMatch(/\(\?<[=!]/);
      expect(p.source).not.toMatch(/\\[1-9]/);
    }
  });

  for (const c of golden.cases)
    it(`redacts ${JSON.stringify(c.in).slice(0, 60)}`, () => {
      expect(redactLine(c.in)).toBe(c.out);
    });

  it('redacts known secret values (≥ 6 chars, longest first) after the patterns', () => {
    const line = 'db connect user=app pw is Sup3rS3cretValue and shortv';
    expect(redactLine(line, ['Sup3rS3cretValue', 'short'])).toBe(
      `db connect user=app pw is ${REDACTED} and shortv`,
    );
    expect(redactLine('x=AAAABBBB', ['AAAA', 'AAAABBBB'])).toBe(`x=${REDACTED}`);
  });
});

describe('PromQL templates (P5.02)', () => {
  it('builds fixed server/app queries with only the validated id', () => {
    expect(serverPromQL('cpu', SID, 15)).toBe(`max(ppanel_server_cpu_percent{server_id="${SID}"})`);
    expect(serverPromQL('net_rx', SID, 300)).toBe(
      `max(rate(ppanel_server_net_rx_bytes_total{server_id="${SID}"}[600s]))`,
    );
    expect(appPromQL('up', AID)).toBe(`min(ppanel_container_up{app_id="${AID}"})`);
  });
  it('refuses anything that is not a uuid', () => {
    expect(() => serverPromQL('cpu', `${SID}"} or vector(1) #`, 15)).toThrow();
  });
  it('fills missing points with null (never 0) and reports gaps', () => {
    const pts = fillGrid(0, 60, 15, [
      [0, '1'],
      [15, '2'],
      [60, 'NaN'],
    ]);
    expect(pts).toEqual([
      [0, 1],
      [15, 2],
      [30, null],
      [45, null],
      [60, null],
    ]);
    expect(gapsOf(pts)).toEqual([[30, 60]]);
    expect(gapsOf(fillGrid(0, 30, 15, [[15, '0']]))).toEqual([
      [0, 0],
      [30, 30],
    ]);
  });
  it('series query schema: metric per scope, strict params, step bounds', () => {
    expect(
      metricsSeriesQuerySchema.safeParse({ scope: 'server', id: SID, metric: 'disk' }).success,
    ).toBe(true);
    expect(
      metricsSeriesQuerySchema.safeParse({ scope: 'app', id: AID, metric: 'disk' }).success,
    ).toBe(false);
    expect(
      metricsSeriesQuerySchema.safeParse({ scope: 'server', id: SID, metric: 'cpu', query: 'up' })
        .success,
    ).toBe(false);
    expect(
      metricsSeriesQuerySchema.safeParse({
        scope: 'server',
        id: SID,
        metric: 'cpu',
        range: '7d',
        step: '15',
      }).success,
    ).toBe(false);
  });
});

describe('LogQL builder (P5-T02 injection)', () => {
  it('always carries the server_id matcher of allowed ids', () => {
    expect(buildLogQL({ serverIds: [SID] })).toBe(`{server_id="${SID}"}`);
    expect(buildLogQL({ serverIds: [SID, SID2], source: 'container', level: 'warn' })).toBe(
      `{server_id=~"${SID}|${SID2}", source="container", level=~"warn|error|fatal"}`,
    );
    expect(() => buildLogQL({ serverIds: [] })).toThrow();
    expect(() => buildLogQL({ serverIds: ['.*'] })).toThrow();
  });
  it('escapes q into a single line-filter string literal', () => {
    const evil = `"} |= "" or {server_id=~".+`;
    const q = buildLogQL({ serverIds: [SID], q: evil });
    expect(q).toBe(`{server_id="${SID}"} |= "\\"} |= \\"\\" or {server_id=~\\".+"`);
    // exactly one unescaped selector close + one filter literal
    expect(q.replace(/\\./g, '').match(/"/g)!.length).toBe(4);
    expect(escapeQuoted('a\\b\n')).toBe('a\\\\b\\n');
  });
  it('rejects control characters and over-long q at the schema', () => {
    expect(logsQuerySchema.safeParse({ serverId: SID, q: 'a\u0000b' }).success).toBe(false);
    expect(logsQuerySchema.safeParse({ serverId: SID, q: 'x'.repeat(201) }).success).toBe(false);
    expect(logsQuerySchema.safeParse({ serverId: SID, query: '{}' }).success).toBe(false);
    expect(logsQuerySchema.safeParse({ serverId: SID, limit: '1001' }).success).toBe(false);
  });
});

describe('timestamps, exposition, truncation', () => {
  it('converts ISO with ns precision both ways', () => {
    const ns = isoToNs('2026-11-23T10:00:00.123456789Z');
    expect(ns).toBe(1_795_428_000_123_456_789n);
    expect(nsToIso(ns)).toBe('2026-11-23T10:00:00.123456789Z');
    expect(isoToNs('2026-11-23T17:00:00+07:00')).toBe(1_795_428_000_000_000_000n);
  });
  it('renders exposition with escaped labels and no duplicate series', () => {
    const out = renderFamily('m', 'gauge', 'h', [
      { labels: { a: 'x"y\\z' }, value: 1 },
      { labels: { a: 'x"y\\z' }, value: 2 },
      { labels: { a: 'b' }, value: Number.NaN },
    ]);
    expect(out.split('\n')).toEqual(['# HELP m h', '# TYPE m gauge', 'm{a="x\\"y\\\\z"} 1']);
  });
  it('truncates lines to 16 KiB incl. the marker on a char boundary', () => {
    const t = truncateLine('é'.repeat(20_000));
    expect(Buffer.byteLength(t)).toBeLessThanOrEqual(16_384);
    expect(t.endsWith(' …[truncated]')).toBe(true);
    expect(truncateLine('short')).toBe('short');
  });
});

describe('label spoofing check', () => {
  const app = { id: AID, name: 'web', kind: 'container', serverId: SID, currentDeploymentId: null };
  it('accepts known names of the app and the ownership shape, refuses others', () => {
    const known = new Map([
      ['ppanel-web-1a2b3c4d', AID],
      ['ppanel-web-api-00112233', 'other-app'],
    ]);
    expect(containerBelongs('ppanel-web-1a2b3c4d', app, known)).toBe(true);
    expect(containerBelongs('ppanel-web-deadbeef', app, known)).toBe(true);
    expect(containerBelongs('ppanel-web-db-deadbeef', app, known)).toBe(true);
    expect(containerBelongs('ppanel-web-api-00112233', app, known)).toBe(false);
    expect(containerBelongs('ppanel-other-deadbeef', app, known)).toBe(false);
    expect(containerBelongs('evil', app, known)).toBe(false);
  });
});

describe('SSRF guard (webhook channels)', () => {
  const strict: WebhookPolicy = { production: false, httpAllowlist: [], privateAllowlist: [] };
  it('classifies private / loopback / link-local / mapped addresses', () => {
    for (const ip of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '::1',
      '::',
      'fe80::1',
      'fd00::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '64:ff9b::a00:1',
    ])
      expect(isPrivateAddress(ip), ip).toBe(true);
    for (const ip of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111'])
      expect(isPrivateAddress(ip), ip).toBe(false);
  });
  it('http needs the http allowlist and is never allowed in production', () => {
    expect(() => checkWebhookUrl('http://hooks.example.com/x', strict)).toThrow();
    expect(() =>
      checkWebhookUrl('http://hooks.example.com/x', {
        ...strict,
        httpAllowlist: ['hooks.example.com'],
      }),
    ).not.toThrow();
    expect(() =>
      checkWebhookUrl('http://hooks.example.com/x', {
        production: true,
        httpAllowlist: ['hooks.example.com'],
        privateAllowlist: [],
      }),
    ).toThrow();
    expect(() => checkWebhookUrl('https://user:pw@hooks.example.com/', strict)).toThrow();
    expect(() => checkWebhookUrl('ftp://hooks.example.com/', strict)).toThrow();
  });
  it('blocks metadata / loopback / 10.x unless allowlisted (metadata always blocked)', async () => {
    const rejects = async (url: string, policy: WebhookPolicy, reason: string) => {
      await expect(resolveWebhookTarget(url, policy)).rejects.toMatchObject({
        code: 'WEBHOOK_URL_NOT_ALLOWED',
        details: { reason },
      });
    };
    await rejects('https://169.254.169.254/latest/meta-data', strict, 'metadata_address');
    await rejects('https://127.0.0.1:8443/hook', strict, 'private_address');
    await rejects('https://10.0.0.5/hook', strict, 'private_address');
    const allow = { ...strict, privateAllowlist: ['127.0.0.1', '10.0.0.5', '169.254.169.254'] };
    await expect(resolveWebhookTarget('https://127.0.0.1:8443/hook', allow)).resolves.toMatchObject(
      {
        address: '127.0.0.1',
      },
    );
    await expect(resolveWebhookTarget('https://10.0.0.5/hook', allow)).resolves.toBeTruthy();
    await rejects('https://169.254.169.254/', allow, 'metadata_address');
  });
  it('resolves DNS and rejects if ANY answer is private (rebinding-style mixed answers)', async () => {
    const resolver = async () => [
      { address: '93.184.215.14', family: 4 },
      { address: '10.0.0.7', family: 4 },
    ];
    await expect(
      resolveWebhookTarget('https://hooks.example.com/x', strict, resolver),
    ).rejects.toMatchObject({ details: { reason: 'private_address' } });
    const ok = await resolveWebhookTarget('https://hooks.example.com/x', strict, async () => [
      { address: '93.184.215.14', family: 4 },
    ]);
    expect(ok.address).toBe('93.184.215.14');
    await expect(
      resolveWebhookTarget('https://metadata.internal/', strict, async () => [
        { address: '169.254.169.254', family: 4 },
      ]),
    ).rejects.toMatchObject({ details: { reason: 'metadata_address' } });
  });
});

describe('ByteBucket (per-server ingest budget)', () => {
  it('allows the burst, then asks to retry after the deficit / rate', () => {
    let now = 0;
    const b = new ByteBucket(1000, 5000, () => now);
    expect(b.take('s', 5000).ok).toBe(true);
    const r = b.take('s', 2500);
    expect(r).toEqual({ ok: false, retryAfterSec: 3 });
    now = 3000;
    expect(b.take('s', 2500).ok).toBe(true);
    expect(b.take('other', 5000).ok).toBe(true); // per key
  });
});

describe('P5 schemas', () => {
  it('heartbeat extension: containers optional (absent ≠ empty), log shipping', () => {
    const base = { seq: 1, sentAt: '2026-11-23T10:00:00Z', agentVersion: '0.2.0', metrics: {} };
    expect(heartbeatSchema.parse(base).containers).toBeUndefined();
    expect(heartbeatSchema.parse({ ...base, containers: null }).containers).toEqual([]);
    const r = heartbeatSchema.parse({
      ...base,
      metrics: { netRxBytes: 10, memTotalBytes: 2048 },
      containers: [
        {
          name: 'ppanel-web-1a2b3c4d',
          app: 'web',
          state: 'running',
          health: 'healthy',
          restartCount: 0,
          cpuPct: 1.5,
          memBytes: 1000,
        },
      ],
      logShipping: { bufferedBytes: 10, bufferCapBytes: 1024, droppedEntries: 3 },
    });
    expect(r.metrics.netRxBytes).toBe(10);
    expect(r.containers?.[0]?.app).toBe('web');
    expect(r.logShipping?.droppedEntries).toBe(3);
    expect(
      heartbeatSchema.safeParse({
        ...base,
        containers: [{ name: 'nginx', app: 'x', state: 'running' }],
      }).success,
    ).toBe(false);
  });
  it('log batch: ≤ 5000 entries, enums, ns timestamps', () => {
    const entry = { ts: '2026-11-23T10:00:00.123456789Z', source: 'agent', line: 'hello' };
    expect(
      agentLogBatchSchema.safeParse({
        batchId: SID,
        seq: 1,
        sentAt: '2026-11-23T10:00:00Z',
        entries: [entry],
      }).success,
    ).toBe(true);
    expect(
      agentLogBatchSchema.safeParse({
        batchId: SID,
        seq: 1,
        sentAt: '2026-11-23T10:00:00Z',
        entries: Array(5001).fill(entry),
      }).success,
    ).toBe(false);
    expect(
      agentLogBatchSchema.safeParse({
        batchId: SID,
        seq: 1,
        sentAt: '2026-11-23T10:00:00Z',
        entries: [{ ...entry, source: 'journald' }],
      }).success,
    ).toBe(false);
  });
  it('alert rules: kind params + scope rules', () => {
    const ok = createAlertRuleSchema.safeParse({
      name: 'cpu high',
      scopeType: 'environment',
      scopeId: 'production',
      kind: 'metric_threshold',
      params: { metric: 'cpu', op: 'gt', value: 90 },
    });
    expect(ok.success && ok.data.forSec).toBe(60);
    expect(
      createAlertRuleSchema.safeParse({
        name: 'x',
        scopeType: 'app',
        scopeId: AID,
        kind: 'metric_threshold',
        params: { metric: 'cpu', op: 'gt', value: 90 },
      }).success,
    ).toBe(false);
    expect(
      createAlertRuleSchema.safeParse({
        name: 'x',
        scopeType: 'global',
        kind: 'metric_threshold',
        params: { metric: 'cpu', op: 'eq', value: 90 },
      }).success,
    ).toBe(false);
    expect(
      createAlertRuleSchema.safeParse({
        name: 'x',
        scopeType: 'environment',
        scopeId: 'staging',
        kind: 'server_offline',
      }).success,
    ).toBe(false);
    expect(
      validateAlertRule({
        kind: 'server_offline',
        scopeType: 'server',
        scopeId: 'nope',
        params: {},
      }),
    ).toHaveLength(1);
  });
  it('channels: telegram token / chat id formats, webhook secret length', () => {
    expect(
      createChannelSchema.safeParse({
        type: 'telegram',
        name: 't',
        config: { botToken: '123456:ABCdefGHIjklMNOpqrSTUvwxYZ012345', chatId: '-100123' },
      }).success,
    ).toBe(true);
    expect(
      createChannelSchema.safeParse({
        type: 'webhook',
        name: 'w',
        config: { url: 'https://x.example.com', signingSecret: 'short' },
      }).success,
    ).toBe(false);
  });
});

describe('notification content', () => {
  it('masks webhook URL paths (they often embed tokens)', () => {
    expect(maskUrl('https://hooks.slack.com/services/T000/B000/XXXX')).toBe(
      'https://hooks.slack.com/…',
    );
    expect(maskUrl('https://example.com')).toBe('https://example.com/');
  });
  it('renders rule, target, severity, value and link only', () => {
    const { subject, text } = renderText({
      event: 'fired',
      channelName: 'ops',
      incident: {
        id: SID,
        ruleId: SID2,
        ruleName: 'Server offline',
        kind: 'server_offline',
        severity: 'critical',
        status: 'firing',
        target: { type: 'server', id: SID, name: 'node-a' },
        environment: 'production',
        startedAt: '2026-11-23T10:00:00.000Z',
        resolvedAt: null,
        lastValue: 130,
        url: `https://panel.example.com/incidents/${SID}`,
      },
    });
    expect(subject).toBe('[pPanel] FIRING CRITICAL: Server offline on node-a');
    expect(text).toContain('Value: 130');
    expect(text).toContain(`/incidents/${SID}`);
  });
});
