/**
 * P9 property tests for the network / gateway trust boundaries: gateway route input (rendered into
 * Nginx files by the Center), http.probe params (Host/SNI override + fixed address), network.diagnose
 * targets, inventory rows and the fail-closed path policy.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  createGatewayRouteSchema,
  dialOrder,
  HTTP_PROBE_URL_RE,
  isDiagnosePrivateAddress,
  JOB_TYPES,
  networkInventoryRowSchema,
  policyAllowsPath,
  CONNECTION_POLICIES,
} from './index';
import { NUM_RUNS } from './fuzz-helpers.fuzz.test';

const nasty = fc.oneof(
  fc.string({ unit: 'binary', maxLength: 200 }),
  fc.string({
    unit: fc.constantFrom(...'abz09.-_/:;{}$ "\'\n\r\t\0*@[]%\\#?&='.split('')),
    maxLength: 80,
  }),
  fc.domain(),
);
const SERVER = '0190a6b8-1111-7000-8000-00000000abcd';

describe('gateway route input', () => {
  it('accepted domains / health paths carry no Nginx syntax', () => {
    fc.assert(
      fc.property(nasty, nasty, (domain, healthPath) => {
        const r = createGatewayRouteSchema.safeParse({
          domain,
          healthPath,
          backends: [{ serverId: SERVER, port: 80 }],
        });
        if (!r.success) return;
        expect(r.data.domain).toMatch(/^[a-z0-9.-]{1,253}$/);
        expect(r.data.healthPath).toMatch(/^\/[A-Za-z0-9._~/?=&%-]*$/);
        for (const s of [r.data.domain, r.data.healthPath])
          expect(/[;{}$"'\s\\]/.test(s)).toBe(false);
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('backend addresses are IPv4 literals only', () => {
    fc.assert(
      fc.property(fc.oneof(nasty, fc.ipV4(), fc.ipV6()), (address) => {
        const r = createGatewayRouteSchema.safeParse({
          domain: 'shop.example.lab',
          backends: [{ serverId: SERVER, address, port: 80 }],
        });
        if (r.success) expect(r.data.backends[0]!.address).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/);
      }),
      { numRuns: NUM_RUNS },
    );
  });
});

describe('http.probe params', () => {
  it('accepted URLs have a strict host, no userinfo/port/whitespace; resolveTo is an IP literal', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          nasty,
          fc.webUrl(),
          nasty.map((s) => `http://${s}`),
        ),
        fc.oneof(nasty, fc.ipV4()),
        (url, resolveTo) => {
          const r = JOB_TYPES['http.probe'].params.safeParse({ url, resolveTo });
          if (!r.success) return;
          expect(HTTP_PROBE_URL_RE.test(r.data.url)).toBe(true);
          const u = new URL(r.data.url);
          expect(u.username + u.password + u.port).toBe('');
          expect(/\s/.test(r.data.url)).toBe(false);
          expect(r.data.resolveTo).toMatch(/^[0-9a-fA-F:.]+$/);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });
});

describe('network.diagnose / inventory', () => {
  it('tcp hosts are IP literals; private classifier never accepts loopback, link-local or metadata', () => {
    fc.assert(
      fc.property(fc.oneof(fc.ipV4(), fc.ipV6(), nasty), (host) => {
        const r = JOB_TYPES['network.diagnose'].params.safeParse({ tcp: [{ host, port: 22 }] });
        if (r.success) expect(r.data.tcp[0]!.host).toMatch(/^[0-9a-fA-F:.]+$/);
        if (isDiagnosePrivateAddress(host)) {
          expect(host.startsWith('127.')).toBe(false);
          expect(host.startsWith('169.254.')).toBe(false);
          expect(host === '::1' || host.toLowerCase().startsWith('fe80')).toBe(false);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('inventory rows: strict, ids/vpc/region charsets bounded', () => {
    fc.assert(
      fc.property(nasty, nasty, nasty, (region, vpcUuid, hostname) => {
        const r = networkInventoryRowSchema.safeParse({ hostname, region, vpcUuid });
        if (!r.success) return;
        expect(r.data.region).toMatch(/^[a-z0-9-]{1,32}$/);
        expect(r.data.vpcUuid).toMatch(/^[A-Za-z0-9-]{1,64}$/);
      }),
      { numRuns: NUM_RUNS },
    );
  });
});

describe('connection policy', () => {
  it('*_only policies never allow (or dial) the other path', () => {
    fc.assert(
      fc.property(fc.constantFrom(...CONNECTION_POLICIES), fc.boolean(), (policy, hasPrivate) => {
        const order = dialOrder(policy, hasPrivate);
        for (const p of order) expect(policyAllowsPath(policy, p)).toBe(true);
        if (policy === 'private_only') expect(order).toEqual(['private']);
        if (policy === 'public_only') expect(order).toEqual(['public']);
        expect(policyAllowsPath('private_only', 'public')).toBe(false);
        expect(policyAllowsPath('public_only', 'private')).toBe(false);
      }),
      { numRuns: 200 },
    );
  });
});
