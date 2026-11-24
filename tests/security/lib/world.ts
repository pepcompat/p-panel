/**
 * Security-suite fixture ("world"): two servers A and B, one resource of every scoped type owned by
 * server A, global resources, and principals with different roles/scopes. Rows are inserted directly
 * (fast, deterministic) except global resources whose secrets must be encrypted by the API.
 */
import {
  bearer,
  bootApp,
  login,
  resetDb,
  type TestApp,
} from '../../../apps/api/test/integration/helpers';
import { encryptSecret, sha256Hex } from '../../../apps/api/src/common/crypto';
import { uuidv7 } from '../../../apps/api/src/common/ids';
import { credentialAad, generateEd25519 } from '../../../apps/api/src/ssh/ssh-keys';

export const MARK_A = 'MARKA7x9';
export const PASSWORD = 'long-enough-password';
const hex64 = (c: string) => c.repeat(64).slice(0, 64);

export interface Principals {
  owner: string;
  viewer: string;
  deployer: string;
  /** ops_admin scoped to server B only */
  scopedB: string;
  /** platform_owner scoped to server B only (users.manage must still require global) */
  scopedOwnerB: string;
  /** viewer scoped to server B */
  scopedViewerB: string;
}

export interface WorldIds {
  serverA: string;
  serverB: string;
  appA: string;
  composeAppA: string;
  nginxAppA: string;
  deploymentA: string;
  deploymentPendingA: string;
  revisionA: string;
  jobA: string;
  scanA: string;
  buildA: string;
  inspectionA: string;
  ruleA: string;
  incidentA: string;
  channel: string;
  integration: string;
  autoDeployA: string;
  repo: string;
  policyA: string;
  runA: string;
  restoreA: string;
  enrollmentProd: string;
  targetUser: string;
  targetBinding: string;
  groupA: string;
  // P9
  provider: string;
  gatewayA: string;
  routeA: string;
  planA: string;
  diagTestA: string;
  // P10
  sshCredential: string;
  sshDeploymentA: string;
  sshHostKeyA: string;
  sshGrantA: string;
  sshSessionA: string;
}

export interface World {
  t: TestApp;
  p: Principals;
  ids: WorldIds;
  /** every id/marker that a principal scoped to server B must never see */
  aSecrets: string[];
}

async function createUser(
  t: TestApp,
  owner: string,
  email: string,
  bindings: Array<Record<string, string>>,
): Promise<string> {
  const r = await t.http
    .post('/api/v1/users')
    .set(bearer(owner))
    .send({ email, password: PASSWORD, displayName: email.split('@')[0], bindings });
  if (r.status !== 201)
    throw new Error(`create user ${email}: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.data.user.id as string;
}

export async function loginEmail(t: TestApp, email: string, password = PASSWORD): Promise<string> {
  const r = await t.http.post('/api/v1/auth/login').send({ email, password });
  if (r.status !== 200) throw new Error(`login ${email}: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.data.accessToken as string;
}

export async function buildWorld(
  existing?: TestApp,
  overrides?: Record<string, string>,
): Promise<World> {
  const t = existing ?? (await bootApp(overrides));
  t.limiter.reset();
  await resetDb(t.prisma);
  const db = t.prisma;
  const owner = await login(t, 'superadmin');
  const ownerId = (await db.user.findUniqueOrThrow({ where: { email: 'superadmin@ppanel.local' } }))
    .id;
  const now = new Date();

  const groupA = uuidv7();
  await db.serverGroup.create({ data: { id: groupA, name: 'grp-global' } });
  const serverA = uuidv7();
  const serverB = uuidv7();
  for (const [id, name] of [
    [serverA, `srv-${MARK_A}`],
    [serverB, 'srv-b'],
  ] as const) {
    await db.server.create({
      data: {
        id,
        name,
        hostname: `${name}.lab`,
        environment: 'development',
        status: 'online',
        lastHeartbeatAt: now,
        agentVersion: '0.1.0',
        groupId: id === serverA ? groupA : null,
        tags: id === serverA ? [`tag-${MARK_A}`] : [],
      },
    });
  }

  // ---------------------------------------------------------------- applications on A
  const appA = uuidv7();
  const composeAppA = uuidv7();
  const nginxAppA = uuidv7();
  await db.application.create({
    data: {
      id: appA,
      serverId: serverA,
      name: `app-${MARK_A.toLowerCase()}`,
      kind: 'container',
      ownershipMode: 'managed',
      domains: [`a-${MARK_A.toLowerCase()}.example.test`],
      sourceFindingFingerprint: `container:${appA}`,
    },
  });
  await db.application.create({
    data: {
      id: composeAppA,
      serverId: serverA,
      name: `compose-${MARK_A.toLowerCase()}`,
      kind: 'compose',
      ownershipMode: 'managed',
      sourceFindingFingerprint: `compose:${composeAppA}`,
    },
  });
  await db.application.create({
    data: {
      id: nginxAppA,
      serverId: serverA,
      name: `nginx-${MARK_A.toLowerCase()}`,
      kind: 'nginx_static',
      ownershipMode: 'adopted',
      sourceFindingFingerprint: `nginx:${nginxAppA}`,
      nginxFiles: [],
    },
  });
  for (const id of [appA, composeAppA])
    await db.containerApp.create({
      data: {
        applicationId: id,
        containerPort: 8080,
        healthcheck: { path: '/healthz' },
        resources: {},
        secretKeys: ['API_KEY'],
        createdBy: ownerId,
      },
    });
  await db.composeAppVersion.create({
    data: {
      id: uuidv7(),
      applicationId: composeAppA,
      version: 1,
      yaml: `services:\n  web:\n    image: nginx@sha256:${hex64('a')}\n    labels: { mark: ${MARK_A} }\n`,
      yamlSha256: hex64('b'),
      routeService: 'web',
      routePort: 80,
      plan: {},
      createdBy: ownerId,
    },
  });
  await db.secret.create({
    data: {
      id: uuidv7(),
      applicationId: appA,
      key: 'API_KEY',
      valueEncrypted: encryptSecret(
        t.config.masterKey,
        `secret-${MARK_A}`,
        `secret:${appA}:API_KEY`,
      ),
      createdBy: ownerId,
      updatedBy: ownerId,
    },
  });

  // ---------------------------------------------------------------- jobs / discovery
  const jobA = uuidv7();
  await db.job.create({
    data: {
      id: jobA,
      serverId: serverA,
      type: 'inventory.collect',
      params: { mark: MARK_A },
      status: 'succeeded',
      mutating: false,
      idempotencyKey: `idem-${MARK_A}`,
      expiresAt: new Date(Date.now() + 3600_000),
      correlationId: `corr-${MARK_A}`,
      actorId: ownerId,
    },
  });
  const scanA = uuidv7();
  const scanJob = uuidv7();
  await db.job.create({
    data: {
      id: scanJob,
      serverId: serverA,
      type: 'discovery.scan',
      status: 'succeeded',
      mutating: false,
      idempotencyKey: `scan-${MARK_A}`,
      expiresAt: new Date(Date.now() + 3600_000),
      correlationId: `scan-${MARK_A}`,
    },
  });
  await db.discoveryScan.create({
    data: { id: scanA, serverId: serverA, jobId: scanJob, status: 'completed', completedAt: now },
  });
  await db.discoveryFinding.create({
    data: {
      id: uuidv7(),
      scanId: scanA,
      serverId: serverA,
      kind: 'nginx_server',
      fingerprint: `fp-${MARK_A}`,
      title: `finding-${MARK_A}`,
      confidence: 'high',
    },
  });

  // ---------------------------------------------------------------- deployments / revisions / builds
  const deploymentA = uuidv7();
  const deploymentPendingA = uuidv7();
  await db.deployment.create({
    data: {
      id: deploymentA,
      applicationId: appA,
      serverId: serverA,
      number: 1,
      trigger: 'manual',
      image: `registry.example.test/${MARK_A.toLowerCase()}@sha256:${hex64('c')}`,
      status: 'succeeded',
      planHash: hex64('d'),
      approvalRequired: false,
      createdBy: ownerId,
      reason: `reason-${MARK_A}`,
    },
  });
  await db.deploymentStep.create({
    data: { id: uuidv7(), deploymentId: deploymentA, seq: 1, name: 'pull', status: 'succeeded' },
  });
  await db.deployment.create({
    data: {
      id: deploymentPendingA,
      applicationId: appA,
      serverId: serverA,
      number: 2,
      trigger: 'manual',
      image: `registry.example.test/x@sha256:${hex64('e')}`,
      status: 'awaiting_approval',
      planHash: hex64('f'),
      approvalRequired: true,
      createdBy: ownerId,
    },
  });
  const revisionA = uuidv7();
  await db.nginxConfigRevision.create({
    data: {
      id: revisionA,
      serverId: serverA,
      applicationId: nginxAppA,
      status: 'draft',
      files: [],
      planHash: hex64('1'),
      approvalRequired: true,
      createdBy: ownerId,
    },
  });
  await db.buildConfig.create({
    data: {
      applicationId: appA,
      repoUrl: `https://git.example.test/${MARK_A}/repo.git`,
      buildServerId: serverA,
      pushRepo: 'registry.example.test/a',
      dockerfile: 'Dockerfile',
      createdBy: ownerId,
      updatedBy: ownerId,
    },
  });
  const buildA = uuidv7();
  await db.build.create({
    data: {
      id: buildA,
      applicationId: appA,
      buildServerId: serverA,
      status: 'succeeded',
      commitSha: hex64('2').slice(0, 40),
      trigger: 'manual',
      pushRepo: 'registry.example.test/a',
      deployAfter: false,
      log: [`build-log-${MARK_A}`],
      logTail: [`build-log-${MARK_A}`],
    },
  });
  const inspectionA = uuidv7();
  const inspJob = uuidv7();
  await db.job.create({
    data: {
      id: inspJob,
      serverId: serverA,
      type: 'source.inspect',
      status: 'succeeded',
      mutating: false,
      idempotencyKey: `insp-${MARK_A}`,
      expiresAt: new Date(Date.now() + 3600_000),
      correlationId: `insp-${MARK_A}`,
      result: { mark: MARK_A },
    },
  });
  await db.sourceInspection.create({
    data: {
      id: inspectionA,
      applicationId: appA,
      jobId: inspJob,
      commitSha: hex64('3').slice(0, 40),
      createdBy: ownerId,
    },
  });
  await db.managedRouting.create({
    data: {
      serverId: serverA,
      status: 'awaiting_approval',
      revisionId: uuidv7(),
      planHash: hex64('4'),
      approvalRequired: true,
      createdBy: ownerId,
    },
  });

  // ---------------------------------------------------------------- observability
  const ruleA = uuidv7();
  await db.alertRule.create({
    data: {
      id: ruleA,
      name: `rule-${MARK_A}`,
      scopeType: 'server',
      scopeId: serverA,
      kind: 'server_offline',
      severity: 'critical',
      createdBy: ownerId,
    },
  });
  const incidentA = uuidv7();
  await db.incident.create({
    data: {
      id: incidentA,
      ruleId: ruleA,
      ruleName: `rule-${MARK_A}`,
      kind: 'server_offline',
      targetType: 'server',
      targetId: serverA,
      targetName: `srv-${MARK_A}`,
      serverId: serverA,
      environment: 'development',
      severity: 'critical',
      startedAt: now,
    },
  });
  const ch = await t.http
    .post('/api/v1/notification-channels')
    .set(bearer(owner))
    .send({
      type: 'webhook',
      name: `chan-${MARK_A}`,
      config: { url: 'https://hooks.example.test/x', signingSecret: 'signing-secret-0123456789' },
    });
  if (ch.status !== 201) throw new Error(`channel: ${ch.status} ${JSON.stringify(ch.body)}`);
  const channel = ch.body.data.channel?.id ?? ch.body.data.id;

  const ig = await t.http
    .post('/api/v1/integrations/github')
    .set(bearer(owner))
    .send({ name: 'gh-global', webhookSecret: 'webhook-secret-0123456789' });
  if (ig.status !== 201) throw new Error(`integration: ${ig.status} ${JSON.stringify(ig.body)}`);
  const integration = ig.body.data.integration?.id ?? ig.body.data.id;
  const autoDeployA = uuidv7();
  await db.autoDeployPolicy.create({
    data: {
      id: autoDeployA,
      applicationId: appA,
      integrationId: integration,
      repo: `org/${MARK_A}`,
      branches: ['main'],
      imageTemplate: 'registry.example.test/a:{sha}',
      createdBy: ownerId,
    },
  });

  await db.webhookDelivery.create({
    data: {
      id: uuidv7(),
      integrationId: integration,
      deliveryId: `dlv-${MARK_A}`,
      event: 'push',
      repo: `org/${MARK_A}`,
      ref: 'refs/heads/main',
      after: hex64('8').slice(0, 40),
      signatureOk: true,
      result: 'deployed',
      deploymentIds: [deploymentA],
    },
  });

  // ---------------------------------------------------------------- backups
  const repo = uuidv7();
  await db.backupRepository.create({
    data: {
      id: repo,
      name: 'repo-global',
      baseUrl: 'https://backup.example.test',
      createdBy: ownerId,
    },
  });
  await db.backupRepoAccess.create({
    data: {
      repositoryId: repo,
      serverId: serverA,
      restUser: `ru-${MARK_A.toLowerCase()}`,
      restPasswordEnc: encryptSecret(t.config.masterKey, 'x', 'x'),
      repoPasswordEnc: encryptSecret(t.config.masterKey, 'x', 'x'),
      createdBy: ownerId,
      initializedAt: now,
    },
  });
  const policyA = uuidv7();
  await db.backupPolicy.create({
    data: {
      id: policyA,
      name: `policy-${MARK_A}`,
      serverId: serverA,
      repositoryId: repo,
      targets: [{ type: 'paths', paths: ['/srv/a'] }],
      scheduleCron: '0 3 * * *',
      timezone: 'UTC',
      retention: { keepDaily: 7 },
      verify: { level: 'check' },
      createdBy: ownerId,
      updatedBy: ownerId,
    },
  });
  const runA = uuidv7();
  await db.backupRun.create({
    data: {
      id: runA,
      policyId: policyA,
      serverId: serverA,
      repositoryId: repo,
      trigger: 'manual',
      status: 'uploaded',
      targets: [{ type: 'paths', paths: ['/srv/a'] }],
      snapshots: [{ targetIndex: 0, snapshotId: hex64('5'), tag: MARK_A }],
    },
  });
  const restoreA = uuidv7();
  await db.restore.create({
    data: {
      id: restoreA,
      runId: runA,
      snapshotId: hex64('5'),
      serverId: serverA,
      repositoryId: repo,
      target: { type: 'paths', paths: ['/srv/a'] },
      targetIndex: 0,
      status: 'planned',
      impact: { mark: MARK_A },
      planHash: hex64('6'),
      approvalRequired: true,
      createdBy: ownerId,
    },
  });

  // ---------------------------------------------------------------- P9 network / gateway on A
  const provider = uuidv7();
  await db.providerIntegration.create({
    data: {
      id: provider,
      provider: 'digitalocean',
      name: 'do-global',
      tokenEnc: encryptSecret(
        t.config.masterKey,
        `TEST_FAKE_DO_${MARK_A}`,
        `provider_integration:${provider}`,
      ),
      apiBase: 'https://api.digitalocean.com',
      status: 'ok',
      createdBy: ownerId,
    },
  });
  await db.serverNetworkInventory.create({
    data: {
      id: uuidv7(),
      serverId: serverA,
      source: 'inventory',
      region: 'lab1',
      vpcUuid: `vpc-${MARK_A.toLowerCase()}`,
      vpcName: `vpcname-${MARK_A}`,
      privateIpv4: '10.77.0.1',
      observedAt: now,
    },
  });
  const gwApp = uuidv7();
  await db.application.create({
    data: {
      id: gwApp,
      serverId: serverA,
      name: 'ppanel-gateway',
      kind: 'gateway',
      ownershipMode: 'managed',
      sourceFindingFingerprint: `gateway:server:${serverA}`,
    },
  });
  const gatewayA = uuidv7();
  await db.gateway.create({
    data: {
      id: gatewayA,
      serverId: serverA,
      name: `gw-${MARK_A.toLowerCase()}`,
      applicationId: gwApp,
      createdBy: ownerId,
    },
  });
  const routeA = uuidv7();
  await db.gatewayRoute.create({
    data: {
      id: routeA,
      gatewayId: gatewayA,
      domain: `r-${MARK_A.toLowerCase()}.example.test`,
      mode: 'hybrid',
      backends: [{ serverId: serverA, address: '10.77.0.1', port: 8080 }],
    },
  });
  const planA = uuidv7();
  await db.gatewayChangePlan.create({
    data: {
      id: planA,
      gatewayId: gatewayA,
      status: 'awaiting_approval',
      routesSnapshot: [],
      rendered: [],
      planHash: hex64('7'),
      shadowResults: [],
      createdBy: ownerId,
    },
  });
  const diagTestA = uuidv7();
  await db.networkConnectivityTest.create({
    data: {
      id: diagTestA,
      serverId: serverA,
      kind: 'diagnose',
      params: { mark: MARK_A },
      result: { mark: MARK_A },
      status: 'succeeded',
      requestedBy: ownerId,
      finishedAt: now,
    },
  });

  // ---------------------------------------------------------------- P10 SSH (server A)
  const sshKey = generateEd25519();
  const sshCredential = uuidv7();
  await db.sshCredential.create({
    data: {
      id: sshCredential,
      name: 'global ssh key',
      kind: 'generated',
      algorithm: sshKey.algorithm,
      publicKey: sshKey.publicKey,
      fingerprintSha256: sshKey.fingerprintSha256,
      privateKeyEnc: encryptSecret(
        t.config.masterKey,
        sshKey.privateOpenSsh,
        credentialAad(sshCredential),
      ),
      createdBy: ownerId,
    },
  });
  const sshDeploymentA = uuidv7();
  await db.sshKeyDeployment.create({
    data: {
      id: sshDeploymentA,
      serverId: serverA,
      credentialId: sshCredential,
      sshUser: 'ops',
      status: 'installed',
      lastError: `dep-${MARK_A}`,
    },
  });
  const sshEndpointA = uuidv7();
  await db.sshEndpoint.create({
    data: {
      id: sshEndpointA,
      serverId: serverA,
      path: 'private',
      host: '10.77.0.1',
      port: 22,
      allowedUsers: ['ops'],
    },
  });
  const sshHostKeyA = uuidv7();
  await db.sshHostKey.create({
    data: {
      id: sshHostKeyA,
      serverId: serverA,
      endpointId: sshEndpointA,
      algorithm: 'ssh-ed25519',
      fingerprintSha256: `SHA256:${MARK_A}${'h'.repeat(35)}`,
      publicKey: `ssh-ed25519 AAAA${MARK_A}`,
      status: 'trusted',
      seenVia: 'scan',
      trustedBy: ownerId,
      trustedAt: now,
    },
  });
  const sshGrantA = uuidv7();
  await db.sshAccessGrant.create({
    data: {
      id: sshGrantA,
      userId: ownerId,
      serverId: serverA,
      sshUser: 'ops',
      endpointPath: 'private',
      reason: `grant-${MARK_A}`,
      durationMin: 60,
      status: 'active',
      grantHash: hex64('9'),
      startsAt: now,
      expiresAt: new Date(now.getTime() + 3_600_000),
    },
  });
  const sshSessionA = uuidv7();
  await db.sshSession.create({
    data: {
      id: sshSessionA,
      grantId: sshGrantA,
      userId: ownerId,
      serverId: serverA,
      sshUser: 'ops',
      endpointPath: 'private',
      endpointHost: '10.77.0.1',
      endpointPort: 22,
      credentialFingerprint: sshKey.fingerprintSha256,
      status: 'closed',
      endReason: 'client_closed',
      clientIp: '127.0.0.1',
      closedAt: now,
    },
  });

  // ---------------------------------------------------------------- enrollment / users
  const en = await t.http
    .post('/api/v1/enrollments')
    .set(bearer(owner))
    .send({ name: `enr-${MARK_A.toLowerCase()}`, environment: 'production' });
  if (en.status !== 201) throw new Error(`enrollment: ${en.status} ${JSON.stringify(en.body)}`);
  const enrollmentProd = en.body.data.enrollment?.id ?? en.body.data.id;

  const targetUser = await createUser(t, owner, `target-${MARK_A.toLowerCase()}@ppanel.local`, [
    { roleKey: 'viewer', scopeType: 'server', scopeId: serverA },
  ]);
  const targetBinding = (await db.roleBinding.findFirstOrThrow({ where: { userId: targetUser } }))
    .id;
  await createUser(t, owner, 'scoped-b@ppanel.local', [
    { roleKey: 'ops_admin', scopeType: 'server', scopeId: serverB },
  ]);
  await createUser(t, owner, 'scoped-owner-b@ppanel.local', [
    { roleKey: 'platform_owner', scopeType: 'server', scopeId: serverB },
  ]);
  await createUser(t, owner, 'scoped-viewer-b@ppanel.local', [
    { roleKey: 'viewer', scopeType: 'server', scopeId: serverB },
  ]);

  const p: Principals = {
    owner,
    viewer: await login(t, 'user1'),
    deployer: await login(t, 'dev'),
    scopedB: await loginEmail(t, 'scoped-b@ppanel.local'),
    scopedOwnerB: await loginEmail(t, 'scoped-owner-b@ppanel.local'),
    scopedViewerB: await loginEmail(t, 'scoped-viewer-b@ppanel.local'),
  };
  const ids: WorldIds = {
    serverA,
    serverB,
    appA,
    composeAppA,
    nginxAppA,
    deploymentA,
    deploymentPendingA,
    revisionA,
    jobA,
    scanA,
    buildA,
    inspectionA,
    ruleA,
    incidentA,
    channel,
    integration,
    autoDeployA,
    repo,
    policyA,
    runA,
    restoreA,
    enrollmentProd,
    targetUser,
    targetBinding,
    groupA,
    provider,
    gatewayA,
    routeA,
    planA,
    diagTestA,
    sshCredential,
    sshDeploymentA,
    sshHostKeyA,
    sshGrantA,
    sshSessionA,
  };
  void sha256Hex;
  // server-B principals must never see any of these (global admin objects included: they need a
  // *global* binding).
  // Server-B principals must never see any of these. Excluded (global, non-secret metadata that a
  // scoped principal legitimately needs, accepted in SECURITY_TEST_REPORT.md SEC-P7-A1): server group
  // ids/names, GitHub integration ids/names, backup repository ids/names/baseUrl. The repository's
  // per-server access entries (restUser, url) of server A stay in the set via MARK_A.
  // P10: SSH credentials are global objects (public key metadata; deployments filtered by scope).
  const GLOBAL_OK = new Set([
    'serverB',
    'groupA',
    'integration',
    'repo',
    'provider',
    'sshCredential',
  ]);
  const aSecrets = [
    MARK_A,
    MARK_A.toLowerCase(),
    ...Object.entries(ids)
      .filter(([k]) => !GLOBAL_OK.has(k))
      .map(([, v]) => v),
  ];
  return { t, p, ids, aSecrets };
}
