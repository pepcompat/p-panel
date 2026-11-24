/**
 * P7.01 SSRF (threat TB8-E): notification webhooks, registry digest resolution, git URLs, Telegram,
 * health-check paths.
 */
import {
  bearer,
  bootApp,
  login,
  resetDb,
  type TestApp,
} from '../../../apps/api/test/integration/helpers';
import { startFake } from '../../../apps/api/test/integration/p5-fixtures';
import { gitHostAllowed, gitHostOf } from '../../../apps/api/src/deploy/builds.service';
import { RegistryClient } from '../../../apps/api/src/deploy/registry.client';
import { checkApiBase, DoClient } from '../../../apps/api/src/network/do-client';
import { NotifierService } from '../../../apps/api/src/observability/notifier.service';
import {
  checkWebhookUrl,
  isPrivateAddress,
  resolveWebhookTarget,
} from '../../../apps/api/src/observability/ssrf';
import {
  buildConfigSchema,
  containerHealthcheckSchema,
  JOB_TYPES,
  telegramChannelConfigSchema,
} from '../../../packages/shared-contracts/src';

const POLICY = { production: true, httpAllowlist: [], privateAllowlist: [] };

describe('webhook URL guard', () => {
  const BAD = [
    'https://169.254.169.254/latest/meta-data',
    'https://2130706433/', // decimal 127.0.0.1
    'https://0x7f000001/',
    'https://0177.0.0.1/',
    'https://127.1/',
    'https://[::1]/',
    'https://[::ffff:127.0.0.1]/',
    'https://[::ffff:7f00:1]/',
    'https://[::127.0.0.1]/', // IPv4-compatible (deprecated)
    'https://[2002:7f00:1::1]/', // 6to4 → 127.0.0.1
    'https://[2002:a00:1::1]/', // 6to4 → 10.0.0.1
    'https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/', // Teredo
    'https://[fe80::1]/',
    'https://[fec0::1]/',
    'https://[fd00:ec2::254]/',
    'https://[64:ff9b::a9fe:a9fe]/', // NAT64 → 169.254.169.254
    'https://user:pass@hooks.example.test/',
    'https://hooks.example.test@169.254.169.254/',
    'http://hooks.example.test/', // http in production
    'file:///etc/passwd',
    'gopher://127.0.0.1:6379/_x',
  ];
  for (const u of BAD)
    it(`rejects ${u}`, async () => {
      await expect(resolveWebhookTarget(u, POLICY, async () => [])).rejects.toMatchObject({
        status: 422,
      });
    });

  it('rejects host names that resolve to loopback / private / metadata (incl. `localhost.`)', async () => {
    const answers: Record<string, string[]> = {
      'localhost.': ['127.0.0.1'],
      'internal.example.test': ['10.1.2.3'],
      'mixed.example.test': ['93.184.216.34', '192.168.1.1'],
      'meta.example.test': ['169.254.169.254'],
      'v6.example.test': ['::1'],
    };
    for (const host of Object.keys(answers)) {
      await expect(
        resolveWebhookTarget(`https://${host}/x`, POLICY, async (h) =>
          (answers[h] ?? []).map((a) => ({ address: a, family: a.includes(':') ? 6 : 4 })),
        ),
      ).rejects.toMatchObject({ status: 422 });
    }
  });

  it('cloud metadata is refused even when the host is private-allowlisted', async () => {
    const p = { production: false, httpAllowlist: ['meta.lab'], privateAllowlist: ['meta.lab'] };
    await expect(
      resolveWebhookTarget('http://meta.lab/', p, async () => [
        { address: '169.254.169.254', family: 4 },
      ]),
    ).rejects.toMatchObject({ status: 422 });
    expect(() =>
      checkWebhookUrl('http://169.254.169.254/', {
        ...p,
        httpAllowlist: ['169.254.169.254'],
        privateAllowlist: ['169.254.169.254'],
      }),
    ).toThrow();
  });

  it('public addresses pass', () => {
    for (const ip of ['93.184.216.34', '2606:4700::1111', '8.8.8.8'])
      expect(isPrivateAddress(ip)).toBe(false);
  });
});

describe('webhook delivery: DNS rebinding is pinned, redirects are not followed', () => {
  let t: TestApp;
  let target: Awaited<ReturnType<typeof startFake>>;
  let other: Awaited<ReturnType<typeof startFake>>;
  let status = 200;
  let location = '';

  beforeAll(async () => {
    other = await startFake((_r, res) => res.writeHead(200).end('{}'));
    target = await startFake((_r, res) => {
      res.writeHead(status, location ? { Location: location } : {}).end('{}');
    });
    const host = `rebind.example.test:${target.port}`;
    t = await bootApp({ PPANEL_WEBHOOK_HTTP_ALLOWLIST: host, PPANEL_WEBHOOK_ALLOWLIST: host });
  });
  afterAll(async () => {
    await t.close();
    await target.close();
    await other.close();
  });

  async function channelRow(owner: string) {
    const r = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'webhook',
        name: 'rebind',
        config: {
          url: `http://rebind.example.test:${target.port}/hook`,
          signingSecret: 'rebind-signing-secret-0123',
        },
      });
    expect(r.status).toBe(201);
    const id = r.body.data.channel?.id ?? r.body.data.id;
    return t.prisma.notificationChannel.findUniqueOrThrow({ where: { id } });
  }

  it('connects to the address that was validated, even if DNS changes afterwards', async () => {
    await resetDb(t.prisma);
    const owner = await login(t, 'superadmin');
    const row = await channelRow(owner);
    const notifier = t.app.get(NotifierService);
    let calls = 0;
    notifier.resolver = async () => {
      calls++;
      // first answer: the (allowlisted) receiver; any later lookup would go to an unroutable host
      return [{ address: calls === 1 ? '127.0.0.1' : '10.255.255.1', family: 4 }];
    };
    const before = target.requests.length;
    status = 200;
    location = '';
    const res = await notifier.send(row, {
      event: 'test',
      channelName: 'rebind',
      incident: null as never,
    });
    expect(res.ok).toBe(true);
    expect(calls).toBe(1);
    expect(target.requests.length).toBe(before + 1);
  });

  it('a 3xx answer is a failed delivery; the Location is never fetched', async () => {
    await resetDb(t.prisma);
    const owner = await login(t, 'superadmin');
    const row = await channelRow(owner);
    const notifier = t.app.get(NotifierService);
    notifier.resolver = async () => [{ address: '127.0.0.1', family: 4 }];
    status = 302;
    location = `http://127.0.0.1:${other.port}/stolen`;
    const res = await notifier.send(row, {
      event: 'test',
      channelName: 'x',
      incident: null as never,
    });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(302);
    expect(other.requests.length).toBe(0);
  });
});

describe('registry resolution (SEC-P7-01)', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await bootApp({ PPANEL_REGISTRY_ALLOWLIST: 'registry.example.test' });
  });
  afterAll(async () => t.close());

  it('refs with user@host, IPv6 literals, trailing dots or schemes never parse', async () => {
    const reg = t.app.get(RegistryClient);
    for (const ref of [
      'user@registry.example.test/x:1',
      '[::1]:5000/x:1',
      'localhost.:5000/x:1',
      'http://registry.example.test/x:1',
      'registry.example.test/../x:1',
      'registry.example.test/x:1#frag',
    ])
      await expect(reg.resolveDigest(ref)).rejects.toMatchObject({ status: 422 });
  });

  it('a host not on the allowlist is refused before any connection', async () => {
    const reg = t.app.get(RegistryClient);
    for (const ref of ['evil.example.test/x:1', '2130706433/x:1', '127.0.0.1:4000/x:1'])
      await expect(reg.resolveDigest(ref)).rejects.toMatchObject({
        status: 422,
        code: 'REGISTRY_NOT_ALLOWED',
      });
  });

  it('a registry-auth (user-supplied) host may not point at internal addresses', async () => {
    const reg = t.app.get(RegistryClient);
    reg.resolver = async (h) =>
      h === 'internal.example.test'
        ? [{ address: '10.0.0.5', family: 4 }]
        : h === 'meta.example.test'
          ? [{ address: '169.254.169.254', family: 4 }]
          : h === 'localhost'
            ? [{ address: '127.0.0.1', family: 4 }]
            : [];
    const cases = [
      '127.0.0.1:4000',
      '2130706433:443',
      '0x7f000001:443',
      '169.254.169.254',
      'internal.example.test:443',
      'meta.example.test',
      'localhost:5432',
    ];
    for (const host of cases) {
      const err = await reg
        .resolveDigest(`${host}/x/y:latest`, { extraAllowedHosts: [host] })
        .catch((e: unknown) => e);
      expect(err, host).toMatchObject({ status: 422, code: 'REGISTRY_NOT_ALLOWED' });
      expect((err as { details?: { reason?: string } }).details?.reason, host).toMatch(
        /private_address|metadata_address/,
      );
    }
    reg.resolver = undefined;
  });

  it('API: compose image on an internal registry-auth host is reported as not allowed (no connect)', async () => {
    await resetDb(t.prisma);
    const owner = await login(t, 'superadmin');
    const reg = t.app.get(RegistryClient);
    // a listener that records connection attempts on 127.0.0.1
    const probe = await startFake((_r, res) => res.writeHead(200).end());
    const tok = await t.http
      .post('/api/v1/deploy/compose/validate')
      .set(bearer(owner))
      .send({ yaml: `services:\n  web:\n    image: 127.0.0.1:${probe.port}/x:latest\n` });
    expect(tok.status).toBeLessThan(500);
    expect(probe.requests.length).toBe(0);
    await probe.close();
    void reg;
  });
});

describe('git URLs and other outbound targets', () => {
  it('git host allowlist cannot be bypassed', () => {
    const allow = ['github.com'];
    const ok = [
      'https://github.com/org/repo.git',
      'https://GITHUB.com/org/r',
      'https://github.com:443/o/r',
    ];
    const bad = [
      'https://github.com@evil.test/o/r',
      'https://user:tok@github.com/o/r',
      'https://github.com.evil.test/o/r',
      'https://evil.test/github.com/o/r',
      'https://github.com./o/r',
      'https://2130706433/o/r',
      'https://[::1]/o/r',
      'file:///etc/passwd',
    ];
    for (const u of ok) expect(gitHostAllowed(gitHostOf(u)!, allow), u).toBe(true);
    for (const u of bad) {
      const h = gitHostOf(u);
      expect(h !== null && gitHostAllowed(h, allow), u).toBe(false);
    }
    // the request schema refuses credentials / exotic schemes before the allowlist is consulted
    for (const repoUrl of [
      'https://github.com@evil.test/o/r',
      'file:///etc/passwd',
      'ssh://git@github.com/o/r',
    ])
      expect(
        buildConfigSchema.safeParse({
          repoUrl,
          buildServerId: '01a207ea-0000-7000-8000-000000000000',
          pushRepo: 'registry.example.test/x',
          dockerfile: 'Dockerfile',
        }).success,
        repoUrl,
      ).toBe(false);
  });

  it('Telegram bot token / chat id cannot inject a path, host or query into the API URL', () => {
    for (const botToken of [
      '123456:' + 'a'.repeat(30) + '/../../x',
      '123456:' + 'a'.repeat(30) + '@evil.test',
      '123456:' + 'a'.repeat(30) + '?x=1',
      '123456:' + 'a'.repeat(30) + '#',
    ])
      expect(telegramChannelConfigSchema.safeParse({ botToken, chatId: '1' }).success).toBe(false);
  });

  it('health-check paths cannot change scheme or host', () => {
    for (const path of [
      'http://169.254.169.254/',
      '@evil.test/',
      'x',
      '/\\evil',
      '/a b',
      '/%0d%0aX:1\r\n',
    ])
      expect(containerHealthcheckSchema.safeParse({ path }).success, path).toBe(false);
    // `//host` stays a path: the agent concatenates "http://127.0.0.1:<port>" + path (no URL resolution)
    expect(containerHealthcheckSchema.safeParse({ path: '//evil.test/x' }).success).toBe(true);
  });
});

describe('P9 provider API + gateway probes (no SSRF through DigitalOcean integrations)', () => {
  const ALLOW = ['https://api.digitalocean.com', 'http://lab-do-fake:8080'];
  it('api_base must be exactly an allowlisted base (no userinfo, query, other host/scheme)', () => {
    for (const base of [
      'https://api.digitalocean.com@169.254.169.254',
      'https://api.digitalocean.com.evil.test',
      'https://user:pw@api.digitalocean.com',
      'https://api.digitalocean.com/?u=http://169.254.169.254',
      'http://api.digitalocean.com',
      'http://169.254.169.254',
      'http://lab-do-fake:8081',
      'gopher://lab-do-fake:8080',
      'file:///etc/passwd',
    ])
      expect(() => checkApiBase(base, ALLOW, false), base).toThrow();
    // lab base: http refused in production
    expect(() => checkApiBase('http://lab-do-fake:8080', ALLOW, true)).toThrow();
  });

  it('the client resolves first and refuses metadata / private targets before connecting; GET only', async () => {
    const mk = (address: string, allowPrivate: boolean) =>
      new DoClient({
        apiBase: 'https://api.digitalocean.com',
        token: 'TEST_FAKE_TOKEN',
        timeoutMs: 500,
        allowPrivate,
        resolver: async () => [{ address, family: address.includes(':') ? 6 : 4 }],
      });
    for (const a of ['169.254.169.254', 'fd00:ec2::254', '100.100.100.200'])
      await expect(mk(a, true).get('/v2/account')).rejects.toMatchObject({
        code: 'PROVIDER_API_NOT_ALLOWED',
      });
    for (const a of ['127.0.0.1', '10.0.0.1', '::1', '::ffff:127.0.0.1'])
      await expect(mk(a, false).get('/v2/account')).rejects.toMatchObject({
        code: 'PROVIDER_API_NOT_ALLOWED',
      });
    for (const m of ['POST', 'DELETE', 'PUT'])
      await expect(mk('203.0.113.1', false).request(m, '/v2/droplets')).rejects.toMatchObject({
        code: 'PROVIDER_API_NOT_ALLOWED',
      });
  });

  it('http.probe params: Host/SNI only from a strict hostname, fixed resolveTo, no userinfo/port tricks', () => {
    const h = JOB_TYPES['http.probe'].params;
    for (const url of [
      'http://169.254.169.254/',
      'http://a.example@169.254.169.254/',
      'http://a.example:22/',
      'http://a.example/%0d%0aHost:x',
      'gopher://a.example/',
    ])
      expect(h.safeParse({ url, resolveTo: '10.0.0.1' }).success, url).toBe(false);
    expect(h.safeParse({ url: 'http://a.example/', resolveTo: 'a.example' }).success).toBe(false);
  });
});
