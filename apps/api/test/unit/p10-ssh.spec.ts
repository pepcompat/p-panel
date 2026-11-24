/**
 * P10 unit: key import rejects, fingerprints, OpenSSH normalisation, grant hash, tickets,
 * host-key compare, endpoint verification, lab endpoint parsing, redaction, contracts.
 */
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  createSshCredentialSchema,
  createSshGrantSchema,
  JOB_TYPES,
  putSshEndpointsSchema,
  sshWsClientMessageSchema,
} from '@ppanel/shared-contracts';
import { utils as sshUtils } from 'ssh2';
import { describe, expect, it } from 'vitest';
import { AppError } from '../../src/common/app-error';
import { sha256Hex } from '../../src/common/crypto';
import { redact } from '../../src/common/logger';
import { parseSshLabEndpoints } from '../../src/config/config';
import { resourceKeyFor, RESTRICTED_JOB_TYPES } from '../../src/jobs/jobs.service';
import {
  agentMatchOf,
  compareHostKey,
  fingerprintOf,
  generateEd25519,
  grantHash,
  importPrivateKey,
  knownAddressesForScope,
  newTicket,
  verifyEndpointHost,
} from '../../src/ssh/ssh-keys';

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof AppError ? (e.code as string) : 'NOT_APP_ERROR';
  }
  return undefined;
};

describe('P10 key generation + import', () => {
  it('generates ed25519 with an OpenSSH fingerprint that matches ssh-keygen format', () => {
    const k = generateEd25519();
    expect(k.algorithm).toBe('ssh-ed25519');
    expect(k.publicKey).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]+=*$/);
    expect(k.fingerprintSha256).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    const blob = Buffer.from(k.publicKey.split(' ')[1]!, 'base64');
    expect(k.fingerprintSha256).toBe(
      'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, ''),
    );
    expect(k.privateOpenSsh).toContain('OPENSSH PRIVATE KEY');
  });

  it('imports unencrypted and passphrase-protected ed25519 / ecdsa-p256 / rsa-3072 keys', () => {
    const cases: Array<[string, Record<string, unknown>, string]> = [
      ['ed25519', {}, 'ssh-ed25519'],
      ['ecdsa', { bits: 256 }, 'ecdsa-sha2-nistp256'],
      ['rsa', { bits: 3072 }, 'rsa-sha2-512'],
    ];
    for (const [type, opts, alg] of cases) {
      for (const passphrase of [undefined, 'test-pass']) {
        const kp = sshUtils.generateKeyPairSync(
          type as 'ed25519',
          (passphrase ? { ...opts, passphrase, cipher: 'aes256-ctr', rounds: 4 } : opts) as never,
        );
        const k = importPrivateKey(kp.private, passphrase);
        expect(k.algorithm).toBe(alg);
        // the normalised (unencrypted, passphrase discarded) form parses back to the same key
        const again = sshUtils.parseKey(k.privateOpenSsh);
        expect(again).not.toBeInstanceOf(Error);
        const pub = sshUtils.parseKey(kp.public);
        expect(pub).not.toBeInstanceOf(Error);
        expect(
          (again as { getPublicSSH(): Buffer })
            .getPublicSSH()
            .equals((pub as { getPublicSSH(): Buffer }).getPublicSSH()),
        ).toBe(true);
        // signatures from the stored key verify against the original public key
        const sig = (again as { sign(d: Buffer): Buffer }).sign(Buffer.from('x'));
        expect(
          (pub as { verify(d: Buffer, s: Buffer): boolean }).verify(Buffer.from('x'), sig),
        ).toBe(true);
      }
    }
  });

  it('imports a PEM (PKCS#1) RSA-4096 key', () => {
    const pem = generateKeyPairSync('rsa', { modulusLength: 4096 })
      .privateKey.export({ type: 'pkcs1', format: 'pem' })
      .toString();
    expect(importPrivateKey(pem).algorithm).toBe('rsa-sha2-512');
  });

  it('rejects encrypted-without-passphrase and wrong passphrase with SSH_KEY_ENCRYPTED', () => {
    const kp = sshUtils.generateKeyPairSync('ed25519', {
      passphrase: 'right',
      cipher: 'aes256-ctr',
      rounds: 4,
    });
    expect(codeOf(() => importPrivateKey(kp.private))).toBe('SSH_KEY_ENCRYPTED');
    expect(codeOf(() => importPrivateKey(kp.private, 'wrong'))).toBe('SSH_KEY_ENCRYPTED');
  });

  it('rejects RSA < 3072, unsupported curves, public keys and garbage with SSH_KEY_UNSUPPORTED', () => {
    const rsa2048 = sshUtils.generateKeyPairSync('rsa', { bits: 2048 });
    expect(codeOf(() => importPrivateKey(rsa2048.private))).toBe('SSH_KEY_UNSUPPORTED');
    const p384 = sshUtils.generateKeyPairSync('ecdsa', { bits: 384 });
    expect(codeOf(() => importPrivateKey(p384.private))).toBe('SSH_KEY_UNSUPPORTED');
    const ed = sshUtils.generateKeyPairSync('ed25519');
    expect(codeOf(() => importPrivateKey(ed.public))).toBe('SSH_KEY_UNSUPPORTED');
    expect(
      codeOf(() =>
        importPrivateKey('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'),
      ),
    ).toBe('SSH_KEY_UNSUPPORTED');
    expect(codeOf(() => importPrivateKey('hello'))).toBe('SSH_KEY_UNSUPPORTED');
  });

  it('error messages never echo key material', () => {
    const rsa2048 = sshUtils.generateKeyPairSync('rsa', { bits: 2048 });
    try {
      importPrivateKey(rsa2048.private);
    } catch (e) {
      expect(JSON.stringify(e)).not.toContain('PRIVATE KEY');
      expect((e as Error).message).not.toContain(rsa2048.private.slice(40, 80));
    }
  });
});

describe('P10 fingerprints, grant hash, tickets', () => {
  it('fingerprintOf is stable, unpadded base64 of sha256(blob)', () => {
    const blob = Buffer.from('ssh-blob');
    expect(fingerprintOf(blob)).toBe(fingerprintOf(Buffer.from('ssh-blob')));
    expect(fingerprintOf(blob)).not.toContain('=');
  });

  it('grantHash binds user, server, ssh user, path and duration', () => {
    const g = {
      userId: 'u',
      serverId: 's',
      sshUser: 'ops',
      endpointPath: 'private',
      durationMin: 60,
    };
    const h = grantHash(g);
    expect(h).toBe(sha256Hex('u|s|ops|private|60'));
    for (const k of Object.keys(g) as Array<keyof typeof g>) {
      const changed = { ...g, [k]: k === 'durationMin' ? 61 : 'x' };
      expect(grantHash(changed)).not.toBe(h);
    }
  });

  it('tickets are 32 random bytes base64url and stored only as sha256', () => {
    const a = newTicket();
    const b = newTicket();
    expect(a.ticket).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.ticket).not.toBe(b.ticket);
    expect(a.hash).toBe(sha256Hex(a.ticket));
    expect(a.hash).not.toContain(a.ticket);
  });
});

describe('P10 host keys + endpoints', () => {
  const T = 'SHA256:' + 'A'.repeat(43);
  const U = 'SHA256:' + 'B'.repeat(43);

  it('compareHostKey: strict, never TOFU', () => {
    expect(compareHostKey(T, [])).toBe('untrusted');
    expect(compareHostKey(T, [{ fingerprintSha256: T, status: 'pending' }])).toBe('untrusted');
    expect(compareHostKey(T, [{ fingerprintSha256: T, status: 'trusted' }])).toBe('trusted');
    expect(compareHostKey(U, [{ fingerprintSha256: T, status: 'trusted' }])).toBe('mismatch');
    expect(
      compareHostKey(U, [
        { fingerprintSha256: T, status: 'trusted' },
        { fingerprintSha256: U, status: 'rejected' },
      ]),
    ).toBe('mismatch');
    expect(compareHostKey(T, [{ fingerprintSha256: T, status: 'superseded' }])).toBe('untrusted');
  });

  it('agentMatchOf compares with agent facts (null without facts)', () => {
    expect(agentMatchOf(T, null)).toBeNull();
    expect(agentMatchOf(T, { hostKeys: [] })).toBeNull();
    expect(agentMatchOf(T, { hostKeys: [{ fingerprintSha256: T }] })).toBe(true);
    expect(agentMatchOf(U, { hostKeys: [{ fingerprintSha256: T }] })).toBe(false);
  });

  it('endpoint host must be an IP literal known for that scope, or a lab host:port', () => {
    const known = knownAddressesForScope(
      [
        { family: 'ipv4', scope: 'private', address: '10.0.0.5' },
        { family: 'ipv4', scope: 'public', address: '203.0.113.9' },
      ],
      [{ privateIpv4: '10.0.0.6', publicIpv4: null }],
      'private',
    );
    expect([...known].sort()).toEqual(['10.0.0.5', '10.0.0.6']);
    const lab = [{ host: '127.0.0.1', port: 52222 }];
    const v = (host: string, port = 22) =>
      verifyEndpointHost({ path: 'private', host, port }, known, lab);
    expect(v('10.0.0.5')).toBe('verified');
    expect(v('10.0.0.6')).toBe('verified');
    expect(v('203.0.113.9')).toBe('unverified'); // public address on the private path
    expect(v('10.9.9.9')).toBe('unverified');
    expect(v('node.example.test')).toBe('unverified');
    expect(v('127.0.0.1', 52222)).toBe('lab');
    expect(v('127.0.0.1', 22)).toBe('unverified');
  });

  it('PPANEL_SSH_LAB_ENDPOINTS parsing', () => {
    expect(parseSshLabEndpoints('')).toEqual([]);
    expect(parseSshLabEndpoints('127.0.0.1:52222, [::1]:2222')).toEqual([
      { host: '127.0.0.1', port: 52222 },
      { host: '::1', port: 2222 },
    ]);
    expect(() => parseSshLabEndpoints('lab-node:22')).toThrow(/PPANEL_SSH_LAB_ENDPOINTS/);
    expect(() => parseSshLabEndpoints('127.0.0.1:70000')).toThrow();
  });
});

describe('P10 redaction + contracts', () => {
  it('privateKey, passphrase and ticket are redacted from logs', () => {
    const out = redact({
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----',
      passphrase: 'hunter2hunter2',
      ticket: 'abcdefabcdefabcdef',
      nested: { body: 'x -----BEGIN RSA PRIVATE KEY-----\nzzz\n-----END RSA PRIVATE KEY----- y' },
      name: 'ok',
    }) as Record<string, unknown>;
    expect(out.privateKey).toBe('[REDACTED]');
    expect(out.passphrase).toBe('[REDACTED]');
    expect(out.ticket).toBe('[REDACTED]');
    expect(JSON.stringify(out)).not.toContain('zzz');
    expect(out.name).toBe('ok');
  });

  it('ssh.keys.sync is a strict, mutating, Center-only job with ≤ 20 public keys', () => {
    const def = JOB_TYPES['ssh.keys.sync'];
    expect(def.mutating).toBe(true);
    expect(RESTRICTED_JOB_TYPES).toContain('ssh.keys.sync');
    const k = generateEd25519();
    const ok = {
      user: 'ops',
      keys: [{ fingerprint: k.fingerprintSha256, publicKey: k.publicKey }],
      managedBlockId: 'ppanel',
    };
    expect(def.params.safeParse(ok).success).toBe(true);
    expect(def.params.safeParse({ ...ok, user: 'Root;rm' }).success).toBe(false);
    expect(def.params.safeParse({ ...ok, extra: 1 }).success).toBe(false);
    expect(
      def.params.safeParse({
        ...ok,
        keys: [{ fingerprint: k.fingerprintSha256, publicKey: k.privateOpenSsh }],
      }).success,
    ).toBe(false);
    expect(
      def.params.safeParse({
        ...ok,
        keys: [{ fingerprint: k.fingerprintSha256, publicKey: `command="sh" ${k.publicKey}` }],
      }).success,
    ).toBe(false);
    expect(
      def.params.safeParse({
        ...ok,
        keys: [{ fingerprint: k.fingerprintSha256, publicKey: k.publicKey + '\nssh-ed25519 AAAA' }],
      }).success,
    ).toBe(false);
    expect(def.params.safeParse({ ...ok, keys: Array(21).fill(ok.keys[0]) }).success).toBe(false);
    expect(resourceKeyFor('ssh.keys.sync', ok, 's')).toBe('ssh_keys:ops');
  });

  it('request schemas', () => {
    expect(createSshCredentialSchema.safeParse({ name: 'k', mode: 'generate' }).success).toBe(true);
    expect(
      createSshCredentialSchema.safeParse({ name: 'k', mode: 'generate', privateKey: 'x' }).success,
    ).toBe(false);
    expect(createSshCredentialSchema.safeParse({ name: 'k', mode: 'import' }).success).toBe(false);
    const g = createSshGrantSchema.parse({
      serverId: '0190a0a0-0000-7000-8000-000000000001',
      sshUser: 'ops',
      endpointPath: 'private',
      reason: 'debug',
    });
    expect(g.durationMinutes).toBe(60);
    for (const d of [14, 481])
      expect(createSshGrantSchema.safeParse({ ...g, durationMinutes: d }).success).toBe(false);
    expect(createSshGrantSchema.safeParse({ ...g, reason: 'x' }).success).toBe(false);
    expect(
      putSshEndpointsSchema.safeParse([
        { path: 'private', host: 'example.com', allowedUsers: ['ops'] },
      ]).success,
    ).toBe(false);
    expect(
      putSshEndpointsSchema.safeParse([
        { path: 'private', host: '10.0.0.1', allowedUsers: ['ops'] },
        { path: 'private', host: '10.0.0.2', allowedUsers: ['ops'] },
      ]).success,
    ).toBe(false);
    for (const m of [
      { type: 'resize', cols: 0, rows: 10 },
      { type: 'resize', cols: 501, rows: 10 },
      { type: 'resize', cols: 80, rows: 201 },
      { type: 'shell', cmd: 'id' },
      { type: 'ping', x: 1 },
    ])
      expect(sshWsClientMessageSchema.safeParse(m).success).toBe(false);
    expect(
      sshWsClientMessageSchema.safeParse({ type: 'resize', cols: 500, rows: 200 }).success,
    ).toBe(true);
  });
});
