import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import { ERROR_CODES } from '@ppanel/shared-contracts';
import { isIP } from 'node:net';
import { randomBytes, webcrypto, X509Certificate as NodeX509 } from 'node:crypto';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService, type Tx } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const subtle = webcrypto.subtle;
const EC_ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' } as const;
const CA_PURPOSE = 'agent_ca';
const DAY = 24 * 3600 * 1000;

/** Normalised serial: lowercase hex, no separators, no leading zeros (matches Node's getPeerCertificate()). */
export function normalizeSerial(serial: string): string {
  const s = serial
    .replace(/[^0-9a-f]/gi, '')
    .toLowerCase()
    .replace(/^0+/, '');
  return s || '0';
}

function newSerial(): string {
  const b = randomBytes(16);
  b[0] = (b[0]! & 0x7f) | 0x10; // positive, no leading zero byte
  return b.toString('hex');
}

function toPem(der: ArrayBuffer, label: string): string {
  const b64 = Buffer.from(der)
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .trim();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

export interface IssuedCert {
  certPem: string;
  serial: string;
  notBefore: Date;
  notAfter: Date;
  fingerprintSha256: string;
}

interface LoadedCa {
  id: string;
  cert: x509.X509Certificate;
  certPem: string;
  privateKey: CryptoKey;
}

/** Internal ECDSA P-256 CA. Private key is stored AES-256-GCM-encrypted (PPANEL_MASTER_KEY) in ca_keys. */
@Injectable()
export class CaService implements OnModuleInit {
  private ca: LoadedCa | undefined;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.ensureCa();
  }

  get caPem(): string {
    if (!this.ca) throw new Error('CA not initialised');
    return this.ca.certPem;
  }

  async ensureCa(): Promise<void> {
    if (this.ca) return;
    let row = await this.prisma.caKey.findFirst({
      where: { purpose: CA_PURPOSE, active: true },
      orderBy: { createdAt: 'desc' },
    });
    if (!row) {
      row = await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('ppanel_ca_bootstrap'))`;
        const existing = await tx.caKey.findFirst({ where: { purpose: CA_PURPOSE, active: true } });
        if (existing) return existing;
        return this.generateCa(tx);
      });
    }
    const pkcs8 = decryptSecret(this.config.masterKey, row.privateKeyEnc, `ca_key:${row.id}`);
    const privateKey = await subtle.importKey('pkcs8', pkcs8, EC_ALG, false, ['sign']);
    this.ca = {
      id: row.id,
      cert: new x509.X509Certificate(row.certPem),
      certPem: row.certPem,
      privateKey,
    };
  }

  private async generateCa(tx: Tx) {
    const keys = (await subtle.generateKey(EC_ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const id = uuidv7();
    const notBefore = new Date(Date.now() - 60_000);
    const notAfter = new Date(Date.now() + 10 * 365 * DAY);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: newSerial(),
      name: `CN=pPanel Internal Agent CA ${id.slice(0, 8)}, O=pPanel`,
      notBefore,
      notAfter,
      keys,
      signingAlgorithm: SIGN_ALG,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true,
        ),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });
    const pkcs8 = Buffer.from(await subtle.exportKey('pkcs8', keys.privateKey));
    const row = await tx.caKey.create({
      data: {
        id,
        purpose: CA_PURPOSE,
        certPem: cert.toString('pem') + '\n',
        privateKeyEnc: encryptSecret(this.config.masterKey, pkcs8, `ca_key:${id}`),
        notAfter,
      },
    });
    pkcs8.fill(0);
    logger.emit('info', 'internal agent CA generated', { caId: id });
    return row;
  }

  /** Validates an agent CSR (ECDSA P-256, valid self-signature). Subject is ignored. */
  async parseCsr(csrPem: string): Promise<x509.Pkcs10CertificateRequest> {
    const invalid = () =>
      new AppError(422, ERROR_CODES.CSR_INVALID, 'CSR must be a valid ECDSA P-256 PKCS#10 request');
    let csr: x509.Pkcs10CertificateRequest;
    try {
      csr = new x509.Pkcs10CertificateRequest(csrPem.trim());
    } catch {
      throw invalid();
    }
    const alg = csr.publicKey.algorithm as EcKeyAlgorithm;
    if (alg.name !== 'ECDSA' || alg.namedCurve !== 'P-256') throw invalid();
    let ok = false;
    try {
      ok = await csr.verify();
    } catch {
      ok = false;
    }
    if (!ok) throw invalid();
    return csr;
  }

  async issueAgentCert(csr: x509.Pkcs10CertificateRequest, serverId: string): Promise<IssuedCert> {
    await this.ensureCa();
    const ca = this.ca!;
    const notBefore = new Date(Date.now() - 60_000);
    const notAfter = new Date(Date.now() + this.config.PPANEL_AGENT_CERT_DAYS * DAY);
    const publicKey = await csr.publicKey.export(EC_ALG, ['verify']);
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: newSerial(),
      subject: `CN=agent:${serverId}`,
      issuer: ca.cert.subject,
      notBefore,
      notAfter,
      publicKey,
      signingKey: ca.privateKey,
      signingAlgorithm: SIGN_ALG,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
        new x509.SubjectAlternativeNameExtension([
          { type: 'url', value: `ppanel://agent/${serverId}` },
        ]),
        await x509.AuthorityKeyIdentifierExtension.create(ca.cert),
        await x509.SubjectKeyIdentifierExtension.create(publicKey),
      ],
    });
    return this.describe(cert);
  }

  /** Gateway TLS server certificate (fresh key per process start, never persisted). */
  async issueGatewayCert(
    hostnames: string[],
  ): Promise<{ keyPem: string; certPem: string; caPem: string; notAfter: Date }> {
    await this.ensureCa();
    const ca = this.ca!;
    const keys = (await subtle.generateKey(EC_ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const names = new Set(['localhost', '127.0.0.1', '::1', ...hostnames]);
    const san = [...names].map((n) =>
      isIP(n) ? { type: 'ip' as const, value: n } : { type: 'dns' as const, value: n },
    );
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: newSerial(),
      subject: 'CN=ppanel-agent-gateway',
      issuer: ca.cert.subject,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 90 * DAY),
      publicKey: keys.publicKey,
      signingKey: ca.privateKey,
      signingAlgorithm: SIGN_ALG,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
        new x509.SubjectAlternativeNameExtension(san),
        await x509.AuthorityKeyIdentifierExtension.create(ca.cert),
      ],
    });
    const keyPem = toPem(await subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY');
    return {
      keyPem,
      certPem: cert.toString('pem') + '\n',
      caPem: ca.certPem,
      notAfter: cert.notAfter,
    };
  }

  private describe(cert: x509.X509Certificate): IssuedCert {
    const pem = cert.toString('pem') + '\n';
    const nodeCert = new NodeX509(pem);
    return {
      certPem: pem,
      serial: normalizeSerial(nodeCert.serialNumber),
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      fingerprintSha256: nodeCert.fingerprint256.replace(/:/g, '').toLowerCase(),
    };
  }
}
