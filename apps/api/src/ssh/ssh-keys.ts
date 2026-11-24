/**
 * P10 pure helpers: SSH key generation / import / normalisation, fingerprints, grant hash, tickets,
 * endpoint address verification and host-key comparison. No I/O, no private material in errors.
 */
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import {
  ERROR_CODES,
  type SshCredentialAlgorithm,
  type SshEndpointPath,
} from '@ppanel/shared-contracts';
import { utils as sshUtils, type ParsedKey } from 'ssh2';
import { AppError } from '../common/app-error';
import { sha256Hex } from '../common/crypto';

/** AAD binding an encrypted private key to its credential row. */
export const credentialAad = (id: string) => `ssh_credential:${id}`;

export const MIN_RSA_BITS = 3072;

export interface NormalizedKey {
  algorithm: SshCredentialAlgorithm;
  /** `<type> <base64>` one line, no comment */
  publicKey: string;
  fingerprintSha256: string;
  /** unencrypted OpenSSH private key (in memory only; encrypt before storing) */
  privateOpenSsh: string;
}

/** `SHA256:<base64 no padding>` of the SSH wire-format public key blob. */
export function fingerprintOf(blob: Buffer): string {
  return `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
}

/** First SSH `string` of a wire blob = the key type. */
export function blobKeyType(blob: Buffer): string | null {
  if (blob.length < 4) return null;
  const n = blob.readUInt32BE(0);
  if (n <= 0 || n > 64 || 4 + n > blob.length) return null;
  return blob.subarray(4, 4 + n).toString('latin1');
}

export function publicLine(blob: Buffer): string {
  return `${blobKeyType(blob)} ${blob.toString('base64')}`;
}

// ---------------------------------------------------------------- OpenSSH private key writer

const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};
const sshString = (v: Buffer | string) => {
  const b = typeof v === 'string' ? Buffer.from(v, 'latin1') : v;
  return Buffer.concat([u32(b.length), b]);
};
/** SSH mpint from an unsigned big-endian magnitude. */
const mpint = (mag: Buffer) => {
  let i = 0;
  while (i < mag.length - 1 && mag[i] === 0) i++;
  let b = mag.subarray(i);
  if (b.length && b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return sshString(b);
};
const b64u = (s: string | undefined) => {
  if (!s) throw new Error('incomplete key');
  return Buffer.from(s, 'base64url');
};

/**
 * Serialises an unencrypted `openssh-key-v1` private key (cipher none) from a parsed key. Used to
 * store imported keys whose passphrase is discarded, in the one format ssh2 parses for every type.
 */
export function toOpenSshPrivate(parsed: ParsedKey): string {
  const blob = parsed.getPublicSSH();
  const type = blobKeyType(blob);
  const jwk = createPrivateKey(parsed.getPrivatePEM()).export({ format: 'jwk' });
  let body: Buffer;
  if (type === 'ssh-ed25519') {
    const seed = b64u(jwk.d);
    const pub = b64u(jwk.x);
    body = Buffer.concat([sshString(pub), sshString(Buffer.concat([seed, pub]))]);
  } else if (type === 'ecdsa-sha2-nistp256') {
    const q = Buffer.concat([Buffer.from([4]), b64u(jwk.x), b64u(jwk.y)]);
    body = Buffer.concat([sshString('nistp256'), sshString(q), mpint(b64u(jwk.d))]);
  } else if (type === 'ssh-rsa') {
    body = Buffer.concat([
      mpint(b64u(jwk.n)),
      mpint(b64u(jwk.e)),
      mpint(b64u(jwk.d)),
      mpint(b64u(jwk.qi)),
      mpint(b64u(jwk.p)),
      mpint(b64u(jwk.q)),
    ]);
  } else {
    throw new Error('unsupported key type');
  }
  const check = randomBytes(4);
  let priv = Buffer.concat([check, check, sshString(type), body, sshString('')]);
  const pad: number[] = [];
  for (let i = 1; (priv.length + pad.length) % 8 !== 0; i++) pad.push(i);
  priv = Buffer.concat([priv, Buffer.from(pad)]);
  const raw = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'latin1'),
    sshString('none'),
    sshString('none'),
    sshString(''),
    u32(1),
    sshString(blob),
    sshString(priv),
  ]);
  const b64 = raw.toString('base64').replace(/(.{70})/g, '$1\n');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64.trim()}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

function single(parsed: ParsedKey | ParsedKey[] | Error): ParsedKey | Error {
  if (Array.isArray(parsed)) return parsed[0] ?? new Error('no key');
  return parsed;
}

function rsaBits(parsed: ParsedKey): number {
  const pub = createPublicKey(parsed.getPublicPEM());
  return pub.asymmetricKeyDetails?.modulusLength ?? 0;
}

const unsupported = (message: string) =>
  new AppError(422, ERROR_CODES.SSH_KEY_UNSUPPORTED, message);

/** Validates + normalises an imported private key (§2 rejects). Never echoes key material. */
export function importPrivateKey(text: string, passphrase?: string): NormalizedKey {
  const trimmed = text.trim();
  if (!/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(trimmed))
    throw unsupported('Not a PEM/OpenSSH private key');
  if (/ENCRYPTED/.test(trimmed.split('\n', 3).join('\n')) && !passphrase)
    throw new AppError(422, ERROR_CODES.SSH_KEY_ENCRYPTED, 'The private key is encrypted');
  const parsed = single(sshUtils.parseKey(trimmed, passphrase || undefined));
  if (parsed instanceof Error) {
    if (/encrypted|passphrase|decrypt|integrity/i.test(parsed.message))
      throw new AppError(
        422,
        ERROR_CODES.SSH_KEY_ENCRYPTED,
        passphrase ? 'The passphrase does not decrypt the key' : 'The private key is encrypted',
      );
    throw unsupported('The private key could not be parsed');
  }
  if (!parsed.isPrivateKey()) throw unsupported('A private key is required');
  const blob = parsed.getPublicSSH();
  const type = blobKeyType(blob);
  let algorithm: SshCredentialAlgorithm;
  if (type === 'ssh-ed25519') algorithm = 'ssh-ed25519';
  else if (type === 'ecdsa-sha2-nistp256') algorithm = 'ecdsa-sha2-nistp256';
  else if (type === 'ssh-rsa') {
    if (rsaBits(parsed) < MIN_RSA_BITS)
      throw unsupported(`RSA keys must be at least ${MIN_RSA_BITS} bits`);
    algorithm = 'rsa-sha2-512';
  } else throw unsupported('Supported key types: ed25519, ecdsa-sha2-nistp256, RSA ≥ 3072');
  let privateOpenSsh: string;
  try {
    privateOpenSsh = toOpenSshPrivate(parsed);
  } catch {
    throw unsupported('The private key could not be normalised');
  }
  // round-trip: the stored form must parse back to the same public key
  const again = single(sshUtils.parseKey(privateOpenSsh));
  if (again instanceof Error || !again.getPublicSSH().equals(blob))
    throw unsupported('The private key could not be normalised');
  return {
    algorithm,
    publicKey: publicLine(blob),
    fingerprintSha256: fingerprintOf(blob),
    privateOpenSsh,
  };
}

/** Center-generated ed25519 key. */
export function generateEd25519(): NormalizedKey {
  const kp = sshUtils.generateKeyPairSync('ed25519');
  const parsed = single(sshUtils.parseKey(kp.private));
  if (parsed instanceof Error) throw new Error('ed25519 generation failed');
  const blob = parsed.getPublicSSH();
  return {
    algorithm: 'ssh-ed25519',
    publicKey: publicLine(blob),
    fingerprintSha256: fingerprintOf(blob),
    privateOpenSsh: kp.private,
  };
}

// ---------------------------------------------------------------- grants / tickets

export function grantHash(g: {
  userId: string;
  serverId: string;
  sshUser: string;
  endpointPath: string;
  durationMin: number;
}): string {
  return sha256Hex([g.userId, g.serverId, g.sshUser, g.endpointPath, g.durationMin].join('|'));
}

export function newTicket(): { ticket: string; hash: string } {
  const ticket = randomBytes(32).toString('base64url');
  return { ticket, hash: sha256Hex(ticket) };
}

// ---------------------------------------------------------------- endpoints / host keys

export interface AddressFact {
  family: string;
  scope: string;
  address: string;
}
export interface InventoryFact {
  privateIpv4: string | null;
  publicIpv4: string | null;
}

/** Every address of `scope` the Center knows for a server (agent-detected, override, inventory). */
export function knownAddressesForScope(
  addresses: AddressFact[],
  inventory: InventoryFact[],
  scope: SshEndpointPath,
): Set<string> {
  const out = new Set<string>();
  for (const a of addresses) if (a.scope === scope) out.add(normIp(a.address));
  for (const r of inventory) {
    const v = scope === 'private' ? r.privateIpv4 : r.publicIpv4;
    if (v) out.add(normIp(v));
  }
  return out;
}

const normIp = (s: string) => s.trim().toLowerCase();

export type EndpointVerdict = 'verified' | 'lab' | 'unverified';

/** §3: host must be an IP literal equal to a known address of that scope, or a lab endpoint. */
export function verifyEndpointHost(
  ep: { path: SshEndpointPath; host: string; port: number },
  known: Set<string>,
  lab: Array<{ host: string; port: number }>,
): EndpointVerdict {
  if (isIP(ep.host) === 0) return 'unverified';
  const host = normIp(ep.host);
  if (known.has(host)) return 'verified';
  if (lab.some((l) => normIp(l.host) === host && l.port === ep.port)) return 'lab';
  return 'unverified';
}

export interface TrustedKeyLike {
  fingerprintSha256: string;
  status: string;
}

export type HostKeyVerdict = 'trusted' | 'untrusted' | 'mismatch';

/** Strict compare (never TOFU): the presented key must be a trusted key of that endpoint. */
export function compareHostKey(presented: string, keys: TrustedKeyLike[]): HostKeyVerdict {
  const trusted = keys.filter((k) => k.status === 'trusted');
  if (trusted.length === 0) return 'untrusted';
  return trusted.some((k) => k.fingerprintSha256 === presented) ? 'trusted' : 'mismatch';
}

/** Agent facts cross-check: true/false when facts exist, null when the agent reported none. */
export function agentMatchOf(fingerprint: string, facts: unknown): boolean | null {
  if (!facts || typeof facts !== 'object') return null;
  const keys = (facts as { hostKeys?: unknown }).hostKeys;
  if (!Array.isArray(keys) || keys.length === 0) return null;
  return keys.some(
    (k) =>
      !!k &&
      typeof k === 'object' &&
      (k as { fingerprintSha256?: unknown }).fingerprintSha256 === fingerprint,
  );
}
