import assert from 'node:assert/strict';
import * as fsPromises from 'node:fs/promises';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import example from '../../fixtures/physical-e2e.example.json' with { type: 'json' };
import configSchema from '../../schemas/physical-e2e-config.v4.schema.json' with { type: 'json' };
import evidenceSchema from '../../schemas/physical-e2e-evidence.v4.schema.json' with { type: 'json' };
import {
  ANDROID_LAUNCH_ACTIVITY,
  ANDROID_PACKAGE,
  CONFIG_VERSION,
  DEEP_ID_PATTERN,
  EVIDENCE_SCHEMA_VERSION,
  REQUIRED_FLOWS,
  assertArm64WindowsExecutable,
  createMarkers,
  endpointProbe,
  interpolate,
  parseComposePs,
  runPhysicalE2E,
  sha256,
  validateConfig,
  validateEvidence,
  verifyReleaseEvidence,
  waitForEndpointUnavailable
} from '../../src/physical-e2e.mjs';

const signerBytes = Buffer.alloc(48, 0xab);
const signerHex = signerBytes.toString('hex');
const signerSha256 = sha256(signerBytes);
const regularFs = { ...fsPromises, isReparsePoint: async () => false };
const windowsDeepId = `deep1${'q'.repeat(85)}`;
const androidDeepId = `deep1${'p'.repeat(85)}`;
const recoveryPhrase = Array.from({ length: 24 }, (_, index) => `word${String.fromCharCode(97 + index)}`).join(' ');

function arm64Pe() {
  const bytes = Buffer.alloc(128);
  bytes.write('MZ');
  bytes.writeUInt32LE(64, 0x3c);
  bytes.write('PE\0\0', 64);
  bytes.writeUInt16LE(0xaa64, 68);
  return bytes;
}

async function localConfig(prefix = 'deep-physical-v4-') {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const config = structuredClone(example);
  config.compose.file = join(root, 'compose.yml');
  config.android.apkPath = join(root, 'deep.apk');
  config.windows.exePath = join(root, config.windows.processName);
  config.windows.appDataRoot = join(root, 'appdata-e2e');
  config.limits.longOfflineMs = 30_000;
  for (const pin of config.compose.endpointPins) pin.expectedBuildSha256 = sha256(`test-build:${pin.service}`);
  await writeFile(config.compose.file, 'services: {}');
  await writeFile(config.android.apkPath, 'apk fixture');
  await writeFile(config.windows.exePath, arm64Pe());
  return { root, config };
}

function commandMock(config, state, events) {
  return async (file, args) => {
    events.push({ kind: 'command', file, args: [...args], online: state.servicesOnline });
    if (file === 'docker' && args.includes('ps')) {
      return {
        stdout: JSON.stringify(config.compose.services.map(Service => ({ Service, State: 'running', Health: 'healthy' }))),
        stderr: ''
      };
    }
    if (file === 'docker' && args.includes('stop')) state.servicesOnline = false;
    if (file === 'docker' && args.includes('start')) state.servicesOnline = true;
    if (file === 'aapt') return { stdout: `package: name='${ANDROID_PACKAGE}' versionCode='7' versionName='1.2.3'`, stderr: '' };
    if (file === 'apksigner') return { stdout: `Signer #1 certificate SHA-256 digest: ${signerSha256}`, stderr: '' };
    if (file === 'powershell.exe') {
      const pid = Number(args.at(-1).match(/ProcessId=(\d+)/)?.[1]);
      return {
        stdout: JSON.stringify({
          ProcessId: pid,
          Name: config.windows.processName,
          ExecutablePath: config.windows.exePath,
          MainWindowHandle: pid + 100
        }),
        stderr: ''
      };
    }
    if (file === 'adb' && args.includes('get-state')) return { stdout: 'device\n', stderr: '' };
    if (file === 'adb' && args.includes('pm')) return { stdout: `package:/data/app/${ANDROID_PACKAGE}/base.apk\n`, stderr: '' };
    if (file === 'adb' && args.includes('dumpsys')) return { stdout: `versionCode=7 versionName=1.2.3 signatures:[${signerHex}]\n`, stderr: '' };
    if (file === 'adb' && args.includes('resolve-activity')) return { stdout: `${ANDROID_PACKAGE}/${ANDROID_LAUNCH_ACTIVITY}\n`, stderr: '' };
    return { stdout: '', stderr: '' };
  };
}

function webdriverFetch(config, runId, state, events) {
  const markers = createMarkers(runId);
  const sessions = new Map();
  let sessionCounter = 0;
  const values = {
    'Settings.DeepId': windowsDeepId,
    [`${ANDROID_PACKAGE}:id/Settings.DeepId`]: androidDeepId,
    'Settings.RecoveryPhraseValue': recoveryPhrase,
    'PhysicalE2E.NetworkCallbackCount': '0',
    'Contact.State.Pending': 'Pending',
    [`${ANDROID_PACKAGE}:id/Contact.State.Pending`]: 'Pending',
    'Contact.State.Verified': 'Verified',
    [`${ANDROID_PACKAGE}:id/Contact.State.Verified`]: 'Verified',
    'Group.State.Pending': 'Pending',
    'Group.State.Active': 'Active',
    [`${ANDROID_PACKAGE}:id/Group.State.Active`]: 'Active',
    [`${ANDROID_PACKAGE}:id/Group.State.Removed`]: 'Removed',
    'Group.Member.State.Removed': 'Removed',
    'DesktopWorkspace.DirectDelivery.Queued': 'Queued',
    'DesktopWorkspace.DirectDelivery.Delivered': 'Delivered',
    'DesktopWorkspace.ConversationRow': `${markers.contactMarkerAndroid} ${markers.contactMarkerWindows}`,
    [`${ANDROID_PACKAGE}:id/Conversations.ConversationRow`]: `${markers.contactMarkerAndroid} ${markers.contactMarkerWindows}`,
    [`${ANDROID_PACKAGE}:id/Groups.InviteRow`]: markers.groupName,
    'Group.MemberRow': markers.contactMarkerAndroid,
    'DesktopWorkspace.DirectMessageBody': `${markers.androidToWindowsMessage} ${markers.windowsToAndroidMessage}`,
    [`${ANDROID_PACKAGE}:id/Chat.MessageBody`]: `${markers.windowsToAndroidMessage} ${markers.androidToWindowsMessage} ${markers.longOfflineMessage}`,
    [`${ANDROID_PACKAGE}:id/GroupChat.MessageBody`]: markers.groupMessage
  };
  return async (input, init = {}) => {
    const url = new URL(input);
    const endpointPin = config.compose.endpointPins.find(pin => new URL(pin.url).port === url.port && url.pathname.includes('/health/'));
    if (endpointPin) {
      events.push({ kind: 'endpoint', service: endpointPin.service, online: state.servicesOnline });
      if (!state.servicesOnline) throw new TypeError('service unavailable');
      return Response.json({ service: endpointPin.service, buildSha256: endpointPin.expectedBuildSha256 });
    }
    const method = init.method ?? 'GET';
    events.push({ kind: 'webdriver', method, path: url.pathname, online: state.servicesOnline });
    if (url.pathname === '/session' && method === 'POST') {
      const caps = JSON.parse(init.body).capabilities.alwaysMatch;
      const id = `driver-${++sessionCounter}`;
      sessions.set(id, caps.platformName.toLowerCase());
      return Response.json({ value: { sessionId: id, capabilities: caps } });
    }
    if (/\/session\/[^/]+$/.test(url.pathname) && method === 'DELETE') return Response.json({ value: null });
    if (url.pathname.endsWith('/elements') && method === 'POST') {
      const selector = JSON.parse(init.body);
      return Response.json({ value: [{ 'element-6066-11e4-a52e-4f735466cecf': encodeURIComponent(selector.value) }] });
    }
    if (url.pathname.endsWith('/displayed')) return Response.json({ value: true });
    if (url.pathname.endsWith('/click') || url.pathname.endsWith('/value')) return Response.json({ value: null });
    const textMatch = url.pathname.match(/\/session\/([^/]+)\/element\/([^/]+)\/text$/);
    if (textMatch) {
      const selector = decodeURIComponent(textMatch[2]);
      if (selector === 'Settings.DeepId' && sessions.get(textMatch[1]) === 'android') return Response.json({ value: androidDeepId });
      return Response.json({ value: values[selector] ?? '' });
    }
    throw new Error(`unexpected fetch ${method} ${url.pathname}`);
  };
}

async function harness(runId = 'clean-break-run-0001') {
  const local = await localConfig();
  const state = { servicesOnline: true, clock: 0 };
  const events = [];
  const pids = [4101, 4102, 4103, 4104];
  const dependencies = {
    command: commandMock(local.config, state, events),
    fetch: webdriverFetch(local.config, runId, state, events),
    fs: regularFs,
    spawn: () => {
      const pid = pids.shift();
      events.push({ kind: 'spawn', pid, online: state.servicesOnline });
      return { pid };
    },
    now: () => state.clock,
    sleep: async milliseconds => { state.clock += milliseconds; }
  };
  return { ...local, runId, state, events, dependencies, artifactsDir: join(local.root, 'artifacts') };
}

test('checked-in v4 fixture and schemas describe only clean-break release-critical flows', () => {
  assert.equal(example.version, CONFIG_VERSION);
  assert.equal(configSchema.properties.version.const, CONFIG_VERSION);
  assert.equal(evidenceSchema.properties.schemaVersion.const, EVIDENCE_SCHEMA_VERSION);
  assert.deepEqual(Object.keys(example.flows), [...REQUIRED_FLOWS]);
  assert.deepEqual(configSchema.properties.flows.required, [...REQUIRED_FLOWS]);
  assert.equal(example.selectors.android.ownIdentity.value, `${ANDROID_PACKAGE}:id/Settings.DeepId`);
  assert.equal(example.selectors.windows.ownIdentity.value, 'Settings.DeepId');
  assert.equal(example.selectors.android.identityInput.value, `${ANDROID_PACKAGE}:id/NewConversation.DeepId`);
  assert.equal(example.selectors.windows.identityInput.value, 'NewConversation.DeepId');
  const serialized = JSON.stringify({ example, configSchema, evidenceSchema });
  for (const legacy of ['Settings.SessionId', 'NewConversation.SessionId', '^05[', 'androidToWindowsAttachment', 'manualRetryAfterRestart']) {
    assert.equal(serialized.includes(legacy), false, `legacy release surface remains: ${legacy}`);
  }
  assert.doesNotThrow(() => validateConfig(example));
});

test('strict config validation rejects legacy identity, unbounded inputs, extra fields, weak provenance, and reordered state transitions', () => {
  const cases = [];
  const legacyIdentity = structuredClone(example);
  legacyIdentity.android.identityPattern = '^05[0-9a-fA-F]{64}$';
  cases.push([legacyIdentity, /Session identity|canonical permanent Deep ID/]);
  const legacySelector = structuredClone(example);
  legacySelector.selectors.windows.ownIdentity.value = 'Settings.SessionId';
  cases.push([legacySelector, /Session identity/]);
  const externalEndpoint = structuredClone(example);
  externalEndpoint.compose.endpointPins[0].url = 'https://uat.example.test/health/ready';
  cases.push([externalEndpoint, /local physical harness/]);
  const extraField = structuredClone(example);
  extraField.windows.fallback = true;
  cases.push([extraField, /fields must match the v4 schema exactly/]);
  const secret = structuredClone(example);
  secret.compose.apiToken = 'nope';
  cases.push([secret, /fields must match the v4 schema exactly|must not contain a secret/]);
  const tooMany = structuredClone(example);
  tooMany.limits.maxTotalActions = 63;
  cases.push([tooMany, /maxTotalActions must be 64-256/]);
  const unpinnedBuild = structuredClone(example);
  unpinnedBuild.compose.endpointPins[0].expectedBuildSha256 = '0'.repeat(64);
  cases.push([unpinnedBuild, /cannot be empty/]);
  const reorder = structuredClone(example);
  [reorder.flows.reciprocalContact[9], reorder.flows.reciprocalContact[16]] =
    [reorder.flows.reciprocalContact[16], reorder.flows.reciprocalContact[9]];
  cases.push([reorder, /strict order/]);
  const missingExclusion = structuredClone(example);
  missingExclusion.flows.smallClosedGroup = missingExclusion.flows.smallClosedGroup.filter(action => action.purpose !== 'removedDeviceExcluded');
  cases.push([missingExclusion, /removedDeviceExcluded/]);
  const earlyOnline = structuredClone(example);
  earlyOnline.flows.offlineAccountRestore.splice(5, 0, earlyOnline.flows.offlineAccountRestore.pop());
  cases.push([earlyOnline, /strict order/]);
  for (const [config, pattern] of cases) assert.throws(() => validateConfig(config), pattern);
});

test('marker interpolation is deterministic and never accepts unknown runtime material', () => {
  const first = createMarkers('same-long-prefix-0000000000000000000000000001');
  const second = createMarkers('same-long-prefix-0000000000000000000000000002');
  assert.notEqual(first.groupName, second.groupName);
  assert.equal(interpolate('{{longOfflineMessage}}', first), first.longOfflineMessage);
  assert.throws(() => interpolate('{{unknown}}', first), /Unknown physical E2E template/);
});

test('compose and executable provenance parsers fail closed', async () => {
  assert.equal(parseComposePs('[{"Service":"router"}]').length, 1);
  assert.equal(parseComposePs('{"Service":"router"}\n{"Service":"mailbox"}').length, 2);
  const pe = arm64Pe();
  assert.doesNotThrow(() => assertArm64WindowsExecutable(pe));
  pe.writeUInt16LE(0x8664, 68);
  assert.throws(() => assertArm64WindowsExecutable(pe), /ARM64/);
  const pin = example.compose.endpointPins[0];
  await assert.rejects(endpointProbe(pin, async () => Response.json({ service: 'not-router' })), /provenance mismatch/);
});

test('offline proof rejects every still-reachable HTTP response and is bounded by one deadline', async () => {
  const pin = example.compose.endpointPins[0];
  let clock = 0;
  await assert.rejects(waitForEndpointUnavailable(
    pin,
    async () => new Response('down', { status: 503 }),
    1000,
    250,
    async milliseconds => { clock += milliseconds; },
    { now: () => clock }
  ), /remained reachable/);
  clock = 0;
  const proof = await waitForEndpointUnavailable(
    pin,
    async () => { throw new TypeError('connection refused'); },
    1000,
    250,
    async milliseconds => { clock += milliseconds; },
    { now: () => clock }
  );
  assert.equal(proof.unavailable, true);
  assert.match(proof.urlSha256, /^[0-9a-f]{64}$/);
});

test('injected dependencies can never mint release-eligible evidence', async () => {
  const h = await harness('injected-release-reject-0001');
  await assert.rejects(runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies
  }), /injected dependencies require testOnly=true/);
  await rm(h.root, { recursive: true, force: true });
});

test('test-only runner proves ordering, bounded offline/retry evidence, cleanup, and redaction', async () => {
  const h = await harness();
  const evidence = await runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies,
    testOnly: true
  });
  assert.equal(evidence.status, 'test-only-passed');
  assert.equal(evidence.releaseEligible, false);
  assert.equal(evidence.provenance.mode, 'test-double');
  assert.deepEqual(evidence.flows.map(flow => flow.name), [...REQUIRED_FLOWS]);
  assert.deepEqual(evidence.processes.map(process => process.phase), ['initial', 'restore', 'restart', 'restart']);
  assert.equal(evidence.networkPeriods.length, 2);
  assert.equal(evidence.networkPeriods[0].purpose, 'offlineAccountCreateRestore');
  assert.equal(evidence.networkPeriods[1].purpose, 'longOfflineServicesStop');
  assert.ok(evidence.networkPeriods[1].offlineElapsedMs >= h.config.limits.longOfflineMs);
  assert.ok(evidence.networkPeriods.every(period => period.unavailable.length === h.config.compose.services.length));
  assert.equal(evidence.cleanup.succeeded, true);
  assert.equal(h.state.servicesOnline, true);

  const firstSpawn = h.events.findIndex(event => event.kind === 'spawn');
  const initialStop = h.events.findIndex(event => event.kind === 'command' && event.file === 'docker' && event.args.includes('stop'));
  assert.ok(initialStop >= 0 && initialStop < firstSpawn, 'clients must launch only after services are proven offline');
  const serialized = JSON.stringify(evidence);
  for (const forbidden of [windowsDeepId, androidDeepId, recoveryPhrase, ...Object.values(createMarkers(h.runId)).filter(value => value !== h.runId)]) {
    assert.equal(serialized.includes(forbidden), false, 'evidence leaked private runtime material or message content');
  }
  assert.ok(Buffer.byteLength(serialized) <= h.config.limits.maxEvidenceBytes);
  assert.doesNotThrow(() => validateEvidence(evidence, h.config.limits.maxEvidenceBytes));
  const artifact = JSON.parse(await readFile(join(h.artifactsDir, 'physical-deep-e2e.json'), 'utf8'));
  assert.equal(artifact.status, 'test-only-passed');
  await assert.rejects(fsPromises.access(join(h.config.windows.appDataRoot, `physical-e2e-${h.runId}`)));
  await rm(h.root, { recursive: true, force: true });
});

test('mid-flow failure still writes bounded all-flow failure evidence and completes cleanup', async () => {
  const h = await harness('partial-failure-0001');
  const baseFetch = h.dependencies.fetch;
  h.dependencies.fetch = async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname.endsWith('/elements') && init.method === 'POST') {
      const selector = JSON.parse(init.body);
      if (selector.value === 'Welcome.DisplayName') return Response.json({ value: [] });
    }
    return baseFetch(input, init);
  };
  await assert.rejects(runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies,
    testOnly: true
  }), /did not resolve/);
  const artifact = JSON.parse(await readFile(join(h.artifactsDir, 'physical-deep-e2e.json'), 'utf8'));
  assert.equal(artifact.status, 'test-only-failed');
  assert.deepEqual(artifact.flows.map(flow => flow.name), [...REQUIRED_FLOWS]);
  assert.equal(artifact.flows[0].status, 'failed');
  assert.ok(artifact.flows.slice(1).every(flow => flow.status === 'not-run'));
  assert.equal(artifact.cleanup.succeeded, true);
  assert.equal(h.state.servicesOnline, true);
  assert.doesNotThrow(() => validateEvidence(artifact, h.config.limits.maxEvidenceBytes));
  await rm(h.root, { recursive: true, force: true });
});

test('evidence validator rejects fake release provenance, plaintext Deep IDs, reordered flows, and overflow', async () => {
  const h = await harness('evidence-hostile-0001');
  const evidence = await runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies,
    testOnly: true
  });
  const fakeRelease = structuredClone(evidence);
  fakeRelease.status = 'passed';
  assert.throws(() => validateEvidence(fakeRelease, h.config.limits.maxEvidenceBytes), /test-double evidence cannot use a release status/);
  assert.throws(() => verifyReleaseEvidence(h.config, evidence), /requires passed physical evidence/);
  const leakedIdentity = structuredClone(evidence);
  leakedIdentity.leak = windowsDeepId;
  assert.throws(() => validateEvidence(leakedIdentity, h.config.limits.maxEvidenceBytes), /plaintext Deep ID/);
  const reordered = structuredClone(evidence);
  reordered.flows.reverse();
  assert.throws(() => validateEvidence(reordered, h.config.limits.maxEvidenceBytes), /incomplete or reordered/);
  assert.throws(() => validateEvidence(evidence, 100), /maxEvidenceBytes/);
  await rm(h.root, { recursive: true, force: true });
});

test('canonical Deep ID grammar is exact lowercase 90-character Bech32m text', () => {
  const pattern = new RegExp(DEEP_ID_PATTERN);
  assert.match(windowsDeepId, pattern);
  assert.equal(windowsDeepId.length, 90);
  assert.equal(pattern.test(`deep1${'Q'.repeat(85)}`), false);
  assert.equal(pattern.test(`05${'1'.repeat(64)}`), false);
  assert.equal(pattern.test(`deep1${'q'.repeat(84)}`), false);
});
