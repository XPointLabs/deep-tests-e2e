import assert from 'node:assert/strict';
import * as fsPromises from 'node:fs/promises';
import { link, lstat, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import example from '../../fixtures/physical-e2e.example.json' with { type: 'json' };
import {
  ANDROID_PACKAGE,
  assertArm64WindowsExecutable,
  assertPathAbsent,
  createMarkers,
  endpointProbe,
  inspectWindowsProcess,
  interpolate,
  isWindowsReparsePoint,
  parseComposePs,
  preflight,
  runPhysicalE2E,
  sha256,
  validateConfig,
  verifyDownloadedAttachment,
  waitForEndpointPin
} from '../../src/physical-e2e.mjs';

const signerBytes = Buffer.alloc(48, 0xab);
const signerHex = signerBytes.toString('hex');
const signerSha256 = sha256(signerBytes);
const regularFs = { ...fsPromises, isReparsePoint: async () => false };

function arm64Pe() {
  const bytes = Buffer.alloc(128);
  bytes.write('MZ');
  bytes.writeUInt32LE(64, 0x3c);
  bytes.write('PE\0\0', 64);
  bytes.writeUInt16LE(0xaa64, 68);
  return bytes;
}

async function localConfig(prefix = 'deep-physical-test-') {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const config = structuredClone(example);
  config.compose.file = join(root, 'compose.yml');
  config.android.apkPath = join(root, 'deep.apk');
  config.windows.exePath = join(root, config.windows.processName);
  config.windows.appDataRoot = join(root, 'appdata');
  config.attachmentPath = join(root, 'source.bin');
  await writeFile(config.compose.file, 'services: {}');
  await writeFile(config.android.apkPath, 'apk fixture');
  await writeFile(config.windows.exePath, arm64Pe());
  await writeFile(config.attachmentPath, 'decrypted fixture');
  return { root, config };
}

function commandMock(config, log, pids = [4101, 4102]) {
  const permittedPids = [...pids];
  return async (file, args) => {
    log.push({ file, args });
    if (file === 'docker' && args.includes('ps')) {
      return {
        stdout: JSON.stringify(config.compose.services.map(Service => ({
          Service,
          State: 'running',
          Health: 'healthy'
        })))
      };
    }
    if (file === 'aapt') {
      return { stdout: "package: name='network.xpoint.deep.e2e' versionCode='7' versionName='1.2.3'" };
    }
    if (file === 'apksigner') {
      return { stdout: `Signer #1 certificate SHA-256 digest: ${signerSha256}` };
    }
    if (file === 'powershell.exe') {
      const script = args.at(-1);
      const pid = Number(script.match(/ProcessId=(\d+)/)[1]);
      assert.ok(permittedPids.includes(pid));
      return {
        stdout: JSON.stringify({
          ProcessId: pid,
          Name: config.windows.processName,
          ExecutablePath: config.windows.exePath,
          MainWindowHandle: pid + 100
        })
      };
    }
    if (file === 'adb' && args.includes('get-state')) return { stdout: 'device\n' };
    if (file === 'adb' && args.includes('pm')) return { stdout: 'package:/data/app/network.xpoint.deep.e2e/base.apk\n' };
    if (file === 'adb' && args.includes('dumpsys')) {
      return { stdout: `versionCode=7 versionName=1.2.3 signatures:[${signerHex}]\n` };
    }
    return { stdout: '' };
  };
}

function endpointFetch(config) {
  return async input => {
    const url = new URL(input);
    const pin = config.compose.endpointPins.find(item => new URL(item.url).port === url.port);
    return new Response(`{"ok":true,"service":"${pin?.service}"}`, { status: 200 });
  };
}

function webdriverFetch(config, runId, log, downloadWrites) {
  const markers = createMarkers(runId);
  const downloadPath = join(config.windows.appDataRoot, `physical-e2e-${runId}`, 'Downloads', markers.attachmentName);
  const sessions = new Map();
  let sessionCounter = 0;
  return async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname.includes('/health/')) {
      const pin = config.compose.endpointPins.find(item => new URL(item.url).port === url.port);
      log.push({ endpointService: pin?.service, url: url.href });
      return new Response(`{"ok":true,"service":"${pin?.service}"}`, { status: 200 });
    }
    const method = init.method ?? 'GET';
    log.push({ url: url.href, method, body: init.body });
    if (url.pathname === '/session' && method === 'POST') {
      const caps = JSON.parse(init.body).capabilities.alwaysMatch;
      const id = `session-${++sessionCounter}`;
      sessions.set(id, caps.platformName.toLowerCase());
      return Response.json({ value: { sessionId: id, capabilities: caps } });
    }
    if (/\/session\/[^/]+$/.test(url.pathname) && method === 'DELETE') {
      return Response.json({ value: null });
    }
    if (url.pathname.endsWith('/element') && method === 'POST') {
      const selector = JSON.parse(init.body);
      return Response.json({ value: { 'element-6066-11e4-a52e-4f735466cecf': encodeURIComponent(selector.value) } });
    }
    const click = url.pathname.match(/\/session\/([^/]+)\/element\/([^/]+)\/click$/);
    if (click) {
      const selector = decodeURIComponent(click[2]);
      if (selector === 'DownloadAttachmentButton') {
        downloadWrites.push(downloadPath);
        await writeFile(downloadPath, 'decrypted fixture');
      }
      return Response.json({ value: null });
    }
    if (url.pathname.endsWith('/value') && method === 'POST') {
      return Response.json({ value: null });
    }
    const textMatch = url.pathname.match(/\/session\/([^/]+)\/element\/([^/]+)\/text$/);
    if (textMatch) {
      const selector = decodeURIComponent(textMatch[2]);
      const target = sessions.get(textMatch[1]);
      const values = {
        OwnIdentity: target === 'windows' ? `05${'1'.repeat(64)}` : `05${'2'.repeat(64)}`,
        IdentityValidation: 'invalid identity rejected',
        ContactList: `${markers.contactMarkerWindows} ${markers.contactMarkerAndroid}`,
        ConversationMessages: `${markers.windowsToAndroidMessage} ${markers.androidToWindowsMessage} ${markers.attachmentName}`,
        RouteNodeMarker: config.chaos?.expectedRouteNode ?? 'router'
      };
      return Response.json({ value: values[selector] ?? '' });
    }
    throw new Error(`unexpected fetch ${method} ${url.pathname}`);
  };
}

async function harness(runId = 'review-run-0001') {
  const local = await localConfig();
  const commandLog = [];
  const webdriverLog = [];
  const downloadWrites = [];
  const pids = [4101, 4102];
  const dependencies = {
    command: commandMock(local.config, commandLog, pids),
    fetch: webdriverFetch(local.config, runId, webdriverLog, downloadWrites),
    fs: regularFs,
    spawn: () => ({ pid: pids.shift() }),
    sleep: async () => {}
  };
  const artifactsDir = join(local.root, 'artifacts');
  return { ...local, runId, dependencies, commandLog, webdriverLog, downloadWrites, artifactsDir };
}

test('markers are unique, include the attachment filename, and reject unknown templates', () => {
  const first = createMarkers('same-long-prefix-0000000000000000000000000001');
  const second = createMarkers('same-long-prefix-0000000000000000000000000002');
  assert.notEqual(first.attachmentName, second.attachmentName);
  assert.match(first.attachmentName, /^deep-e2e-attachment-[0-9a-f]{20}\.bin$/);
  assert.equal(interpolate('{{windowsToAndroidMessage}}', first), first.windowsToAndroidMessage);
  assert.throws(() => interpolate('{{unknown}}', first), /Unknown physical E2E template/);
});

test('compose parser accepts Docker array and line formats', () => {
  assert.equal(parseComposePs('[{"Service":"router"}]').length, 1);
  assert.equal(parseComposePs('{"Service":"router"}\n{"Service":"file"}').length, 2);
});

test('Windows executable gate accepts only ARM64 PE', () => {
  const bytes = arm64Pe();
  assert.doesNotThrow(() => assertArm64WindowsExecutable(bytes));
  bytes.writeUInt16LE(0x8664, 68);
  assert.throws(() => assertArm64WindowsExecutable(bytes), /ARM64/);
});

test('default Windows ReparsePoint adapter uses a bounded exact FileAttributes query', async () => {
  const path = join(tmpdir(), 'deep-reparse-adapter-unit');
  let invocation;
  const detected = await isWindowsReparsePoint(path, undefined, {
    timeoutMs: 1234,
    command: async (file, args, options) => {
      invocation = { file, args, options };
      return { stdout: '1024\r\n', stderr: '' };
    }
  });
  assert.equal(detected, true);
  assert.equal(invocation.file, 'powershell.exe');
  assert.equal(invocation.options.timeout, 1234);
  assert.match(invocation.args.at(-1), /^\$ErrorActionPreference='Stop';\[int\]\[IO\.File\]::GetAttributes\('/);
  await assert.rejects(
    isWindowsReparsePoint(path, undefined, { command: async () => ({ stdout: 'True and maybe', stderr: '' }) }),
    /invalid attributes/
  );
  await assert.rejects(
    isWindowsReparsePoint(path, undefined, { command: async () => { throw new Error('timed out'); } }),
    /timed out/
  );
});

test('default Windows ReparsePoint adapter detects a real junction', async t => {
  if (process.platform !== 'win32') {
    t.skip('Windows-only junction integration');
    return;
  }
  const root = await mkdtemp(join(tmpdir(), 'deep-reparse-integration-'));
  const target = join(root, 'target');
  const junction = join(root, 'junction');
  await mkdir(target);
  try {
    await symlink(target, junction, 'junction');
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error?.code)) {
      t.skip(`junction creation unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  try {
    assert.equal(await isWindowsReparsePoint(junction, await lstat(junction)), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('config mutation gates reject coordinates, weak endpoints, incomplete negative flow, and uncorrelated chaos', () => {
  const coordinate = structuredClone(example);
  coordinate.flows.invalidIdentity[0].selector.using = 'xpath';
  assert.throws(() => validateConfig(coordinate), /never coordinates/);

  const endpoint = structuredClone(example);
  endpoint.compose.endpointPins.pop();
  assert.throws(() => validateConfig(endpoint), /exactly one successful endpoint pin/);

  const relabeled = structuredClone(example);
  relabeled.compose.endpointPins[1].url = `${relabeled.compose.endpointPins[0].url}/`;
  relabeled.compose.endpointPins[1].bodyIncludes = '"service":"registry"';
  assert.throws(() => validateConfig(relabeled), /reuses another service URL/);

  const legacyMarker = structuredClone(example);
  legacyMarker.compose.endpointPins[0].bodyIncludes = '"service":"router"';
  assert.throws(() => validateConfig(legacyMarker), /must not use a substring body marker/);

  const queryProvenance = structuredClone(example);
  queryProvenance.compose.endpointPins[0].url += '?service=registry';
  assert.throws(() => validateConfig(queryProvenance), /cannot contain a query string/);

  const fragmentProvenance = structuredClone(example);
  fragmentProvenance.compose.endpointPins[0].url += '#registry';
  assert.throws(() => validateConfig(fragmentProvenance), /cannot contain a fragment/);

  const userinfoProvenance = structuredClone(example);
  userinfoProvenance.compose.endpointPins[0].url = 'http://registry@127.0.0.1:18081/health/ready';
  assert.throws(() => validateConfig(userinfoProvenance), /cannot contain credentials/);

  const status = structuredClone(example);
  status.compose.endpointPins[0].expectedStatus = 204;
  assert.throws(() => validateConfig(status), /must require HTTP 200/);

  const negative = structuredClone(example);
  negative.flows.invalidIdentity = negative.flows.invalidIdentity.filter(action => action.purpose !== 'invalidIdentityContactAbsent');
  assert.throws(() => validateConfig(negative), /invalidIdentityContactAbsent/);

  const reordered = structuredClone(example);
  [reordered.flows.windowsToAndroidText[0], reordered.flows.windowsToAndroidText[1]] =
    [reordered.flows.windowsToAndroidText[1], reordered.flows.windowsToAndroidText[0]];
  assert.throws(() => validateConfig(reordered), /strict order/);

  const earlyHash = structuredClone(example);
  [earlyHash.flows.androidToWindowsAttachment[3], earlyHash.flows.androidToWindowsAttachment[4]] =
    [earlyHash.flows.androidToWindowsAttachment[4], earlyHash.flows.androidToWindowsAttachment[3]];
  assert.throws(() => validateConfig(earlyHash), /strict order/);

  const wrongNegativeTarget = structuredClone(example);
  wrongNegativeTarget.flows.invalidIdentity.at(-1).target = 'android';
  assert.throws(() => validateConfig(wrongNegativeTarget), /invalidIdentityContactAbsent/);

  const duplicatePurpose = structuredClone(example);
  duplicatePurpose.flows.androidToWindowsText[1].purpose = 'messageEntry';
  assert.throws(() => validateConfig(duplicatePurpose), /purposes must be unique/);

  const outside = structuredClone(example);
  outside.flows.androidToWindowsAttachment.at(-1).target = 'android';
  assert.throws(() => validateConfig(outside), /must target Windows/);

  const traversal = structuredClone(example);
  traversal.android.attachmentDirectory = '/sdcard/Download/../../data';
  assert.throws(() => validateConfig(traversal), /cannot traverse/);

  const chaos = structuredClone(example);
  chaos.chaos = {
    enabled: true,
    expectedRouteNode: 'route-node-001',
    healthTimeoutMs: 5000,
    healthPollMs: 250,
    routeMarker: {
      target: 'windows',
      type: 'captureRouteMarker',
      selector: { using: 'accessibility id', value: 'RouteNodeMarker' },
      saveAs: 'observedRouteNode',
      expected: '{{expectedRouteNode}}'
    },
    routeBindings: [{ routeNode: 'another-node', composeService: 'router' }],
    actions: [{ type: 'restartComposeService', routeRef: '{{observedRouteNode}}' }]
  };
  assert.throws(() => validateConfig(chaos), /exactly one compose service binding/);

  const routeOverride = structuredClone(chaos);
  routeOverride.chaos.routeBindings = [{ routeNode: 'route-node-001', composeService: 'router' }];
  routeOverride.chaos.actions[0].service = 'file';
  assert.throws(() => validateConfig(routeOverride), /must be derived/);
});

test('download verifier rejects a source/outside path and reparse file', async () => {
  const root = await mkdtemp(join(tmpdir(), 'deep-download-adversarial-'));
  const downloadRoot = join(root, 'Downloads');
  const outside = join(root, 'source.bin');
  await writeFile(outside, 'fixture');
  await assert.rejects(verifyDownloadedAttachment(outside, downloadRoot, sha256('fixture')), /escaped/);
  await mkdir(downloadRoot);
  const hardLink = join(downloadRoot, 'hard-link.bin');
  await link(outside, hardLink);
  const sourceIdentity = await stat(outside);
  await assert.rejects(
    verifyDownloadedAttachment(hardLink, downloadRoot, sha256('fixture'), regularFs, sourceIdentity),
    /hard link/
  );

  const fakeFs = {
    lstat: async path => path === downloadRoot
      ? { isSymbolicLink: () => false }
      : { isSymbolicLink: () => true, isFile: () => true, size: 7 },
    realpath: async path => path,
    readFile: async () => Buffer.from('fixture')
  };
  await assert.rejects(
    verifyDownloadedAttachment(join(downloadRoot, 'file.bin'), downloadRoot, sha256('fixture'), fakeFs),
    /symlink\/reparse/
  );
  await rm(root, { recursive: true, force: true });
});

test('Windows ReparsePoint attribute adapter rejects source, destination, and managed directories', async () => {
  const source = await localConfig('deep-source-reparse-');
  await assert.rejects(preflight(source.config, {
    command: commandMock(source.config, []),
    fetch: endpointFetch(source.config),
    fs: { ...fsPromises, isReparsePoint: async path => path === source.config.attachmentPath }
  }, 'source-attribute-run'), /attachment source cannot have the Windows ReparsePoint attribute/);
  await rm(source.root, { recursive: true, force: true });

  const directory = await localConfig('deep-directory-reparse-');
  await assert.rejects(preflight(directory.config, {
    command: commandMock(directory.config, []),
    fetch: endpointFetch(directory.config),
    fs: { ...fsPromises, isReparsePoint: async path => path === directory.config.windows.appDataRoot }
  }, 'directory-attribute-run'), /directory 'appdata' cannot have the Windows ReparsePoint attribute/);
  await rm(directory.root, { recursive: true, force: true });

  const destinationFs = {
    lstat: async () => ({ isSymbolicLink: () => false, isFile: () => true, size: 7 }),
    isReparsePoint: async path => path.endsWith('file.bin'),
    realpath: async path => path,
    readFile: async () => Buffer.from('fixture')
  };
  await assert.rejects(
    verifyDownloadedAttachment('C:\\isolated\\Downloads\\file.bin', 'C:\\isolated\\Downloads', sha256('fixture'), destinationFs),
    /decrypted destination cannot have the Windows ReparsePoint attribute/
  );
});

test('health provenance requires an exact JSON service identity', async () => {
  const pin = structuredClone(example.compose.endpointPins.find(item => item.service === 'file'));
  await assert.rejects(
    endpointProbe(pin, async () => Response.json({ ok: true, service: 'profile' })),
    /service provenance mismatch/
  );
});

test('endpoint re-health uses one wall-clock deadline and records elapsed evidence', async () => {
  const pin = structuredClone(example.compose.endpointPins[0]);
  await assert.rejects(
    waitForEndpointPin(pin, async () => {
      await new Promise(resolve => setTimeout(resolve, 35));
      return Response.json({ service: pin.service });
    }, 10, 1),
    /deadline/
  );
  const health = await waitForEndpointPin(pin, async () => Response.json({ service: pin.service }), 100, 1);
  assert.equal(health.service, pin.service);
  assert.ok(Number.isInteger(health.elapsedMs) && health.elapsedMs >= 0);
});

test('Windows process inspection bounds PowerShell by its remaining deadline and retries transient readiness', async () => {
  const config = structuredClone(example);
  config.windows.launchTimeoutMs = 10;
  config.windows.launchPollMs = 1;
  await assert.rejects(
    inspectWindowsProcess(async (_file, args, options) => {
      assert.ok(options.timeout <= config.windows.launchTimeoutMs);
      assert.match(args.at(-1), /^\$ErrorActionPreference='Stop';/);
      await new Promise(resolve => setTimeout(resolve, 35));
      return { stdout: JSON.stringify({ ProcessId: 91, Name: config.windows.processName, ExecutablePath: config.windows.exePath, MainWindowHandle: 1 }) };
    }, config, { pid: 91 }),
    /deadline/
  );

  let attempts = 0;
  const provenance = await inspectWindowsProcess(async () => {
    attempts += 1;
    if (attempts === 1) throw new Error('Get-Process: Cannot find a process with the process identifier 92.');
    return { stdout: JSON.stringify({
      ProcessId: 92,
      Name: config.windows.processName,
      ExecutablePath: config.windows.exePath,
      MainWindowHandle: attempts === 2 ? 0 : 123
    }) };
  }, { ...config, windows: { ...config.windows, launchTimeoutMs: 100 } }, { pid: 92 }, { sleep: async () => {} });
  assert.equal(provenance.pid, 92);
  assert.ok(provenance.elapsedMs >= 0);
  assert.equal(attempts, 3);

  let nullAttempts = 0;
  const afterNull = await inspectWindowsProcess(async () => {
    nullAttempts += 1;
    if (nullAttempts === 1) {
      return { stdout: JSON.stringify({ ProcessId: null, Name: null, ExecutablePath: null, MainWindowHandle: 0 }), stderr: '' };
    }
    return { stdout: JSON.stringify({
      ProcessId: 93,
      Name: config.windows.processName,
      ExecutablePath: config.windows.exePath,
      MainWindowHandle: 456
    }), stderr: '' };
  }, { ...config, windows: { ...config.windows, launchTimeoutMs: 100 } }, { pid: 93 }, { sleep: async () => {} });
  assert.equal(afterNull.pid, 93);
  assert.equal(nullAttempts, 2);

  let stderrAttempts = 0;
  const afterStderr = await inspectWindowsProcess(async () => {
    stderrAttempts += 1;
    if (stderrAttempts === 1) {
      return { stdout: 'null', stderr: 'Get-Process: Cannot find a process with the process identifier 95.' };
    }
    return { stdout: JSON.stringify({
      ProcessId: 95,
      Name: config.windows.processName,
      ExecutablePath: config.windows.exePath,
      MainWindowHandle: 789
    }), stderr: '' };
  }, { ...config, windows: { ...config.windows, launchTimeoutMs: 100 } }, { pid: 95 }, { sleep: async () => {} });
  assert.equal(afterStderr.pid, 95);
  assert.equal(stderrAttempts, 2);

  await assert.rejects(
    inspectWindowsProcess(async () => ({ stdout: JSON.stringify({
      ProcessId: 999,
      Name: config.windows.processName,
      ExecutablePath: config.windows.exePath,
      MainWindowHandle: 1
    }), stderr: '' }), { ...config, windows: { ...config.windows, launchTimeoutMs: 100 } }, { pid: 94 }),
    /PID provenance mismatch/
  );
});

test('deletion proof accepts ENOENT only', async () => {
  await assert.doesNotReject(assertPathAbsent({
    access: async () => {
      const error = new Error('missing');
      error.code = 'ENOENT';
      throw error;
    }
  }, 'C:\\isolated\\download.bin', 'download'));
  await assert.rejects(assertPathAbsent({
    access: async () => {
      const error = new Error('denied');
      error.code = 'EACCES';
      throw error;
    }
  }, 'C:\\isolated\\download.bin', 'download'), /failed with EACCES/);
});

test('preflight binds APK version and signing identity to installed dumpsys', async () => {
  const { root, config } = await localConfig();
  const log = [];
  const result = await preflight(config, {
    command: commandMock(config, log),
    fetch: endpointFetch(config),
    fs: regularFs
  }, 'preflight-run');
  assert.equal(result.android.apk.signingSha256, signerSha256);
  assert.equal(result.android.apk.versionCode, result.android.installed.versionCode);
  assert.equal(result.android.apk.versionName, result.android.installed.versionName);
  await rm(root, { recursive: true, force: true });
});

test('preflight fails closed on APK/install version mutation', async () => {
  const { root, config } = await localConfig();
  const base = commandMock(config, []);
  const command = async (file, args) => {
    if (file === 'aapt') return { stdout: "package: name='network.xpoint.deep.e2e' versionCode='8' versionName='1.2.3'" };
    return base(file, args);
  };
  await assert.rejects(preflight(config, {
    command,
    fetch: endpointFetch(config)
  }, 'mismatch-run'), /versionCode differs/);
  await rm(root, { recursive: true, force: true });
});

test('preflight rejects a source symlink before its referent can be hard-linked into Downloads', async () => {
  const { root, config } = await localConfig();
  const wrappedFs = {
    ...fsPromises,
    lstat: async path => path === config.attachmentPath
      ? { isSymbolicLink: () => true }
      : fsPromises.lstat(path)
  };
  await assert.rejects(preflight(config, {
    command: commandMock(config, []),
    fetch: endpointFetch(config),
    fs: wrappedFs
  }, 'source-symlink-run'), /source cannot be a symlink\/reparse/);
  assert.equal(await fsPromises.access(config.windows.appDataRoot).then(() => true, () => false), false);
  await rm(root, { recursive: true, force: true });
});

test('mocked runner proves initial hash, deletion, distinct restart PID, driver binding, and cleanup', async () => {
  const h = await harness();
  const baseCommand = h.dependencies.command;
  let zeroHandleOnce = true;
  h.dependencies.command = async (file, args) => {
    const result = await baseCommand(file, args);
    if (file === 'powershell.exe' && zeroHandleOnce) {
      zeroHandleOnce = false;
      const metadata = JSON.parse(result.stdout);
      metadata.MainWindowHandle = 0;
      return { stdout: JSON.stringify(metadata) };
    }
    return result;
  };
  h.config.chaos = {
    enabled: true,
    expectedRouteNode: 'route-node-001',
    healthTimeoutMs: 5000,
    healthPollMs: 250,
    routeMarker: {
      target: 'windows',
      type: 'captureRouteMarker',
      selector: { using: 'accessibility id', value: 'RouteNodeMarker' },
      saveAs: 'observedRouteNode',
      expected: '{{expectedRouteNode}}'
    },
    routeBindings: [{ routeNode: 'route-node-001', composeService: 'router' }],
    actions: [{ type: 'restartComposeService', routeRef: '{{observedRouteNode}}' }]
  };
  const evidence = await runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies
  });
  assert.equal(evidence.status, 'passed');
  assert.equal(evidence.cleanup.succeeded, true);
  assert.equal(evidence.chaos.deterministicFailoverClaim, false);
  assert.match(evidence.chaos.observedRouteNodeSha256, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(evidence.chaos).includes('route-node-001'), false);
  assert.equal(evidence.chaos.actions[0].health.service, 'router');
  assert.deepEqual(evidence.processes.map(item => item.pid), [4101, 4102]);
  assert.equal(h.downloadWrites.length, 2);
  assert.deepEqual(evidence.files.filter(item => item.sha256).map(item => item.phase), ['initial', 'afterRestart']);
  const driverBodies = h.webdriverLog.filter(item => item.url.endsWith('/session') && item.method === 'POST').map(item => JSON.parse(item.body).capabilities.alwaysMatch);
  assert.ok(driverBodies.some(caps => caps['deep:signingSha256'] === signerSha256 && caps['appium:appPackage'] === ANDROID_PACKAGE));
  assert.ok(driverBodies.some(caps => caps['deep:processId'] === 4101));
  assert.ok(driverBodies.some(caps => caps['deep:processId'] === 4102));
  const forceStops = h.commandLog.filter(item => item.file === 'adb' && item.args.includes('force-stop'));
  assert.ok(forceStops.length >= 2);
  assert.equal(h.commandLog.filter(item => item.file === 'powershell.exe').length, 3);
  assert.ok(h.commandLog.some(item => item.file === 'docker' && item.args.includes('restart') && item.args.includes('router')));
  assert.ok(h.webdriverLog.filter(item => item.endpointService === 'router').length >= 2);
  await assert.rejects(stat(join(h.config.windows.appDataRoot, `physical-e2e-${h.runId}`)));
  const artifact = JSON.parse(await readFile(join(h.artifactsDir, 'physical-deep-e2e.json'), 'utf8'));
  assert.equal(artifact.status, 'passed');
  assert.equal(JSON.stringify(artifact).includes(h.config.windows.exePath), false);
  await rm(h.root, { recursive: true, force: true });
});

test('artifact write failure occurs after mandatory cleanup', async () => {
  const h = await harness('artifact-failure-0001');
  h.dependencies.artifactWrite = async () => {
    throw new Error('artifact disk failure');
  };
  await assert.rejects(runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies
  }), /artifact disk failure/);
  await assert.rejects(stat(join(h.config.windows.appDataRoot, `physical-e2e-${h.runId}`)));
  assert.ok(h.commandLog.some(item => item.file === 'adb' && item.args.includes('force-stop')));
  assert.ok(h.commandLog.some(item => item.file === 'taskkill' && item.args.includes('4102')));
  await rm(h.root, { recursive: true, force: true });
});

test('one cleanup failure cannot skip later cleanup and prevents passed status', async () => {
  const h = await harness('cleanup-failure-0001');
  const baseCommand = h.dependencies.command;
  h.dependencies.command = async (file, args) => {
    if (file === 'taskkill' && args.includes('4102')) throw new Error('simulated process cleanup failure');
    return baseCommand(file, args);
  };
  await assert.rejects(runPhysicalE2E(h.config, {
    runId: h.runId,
    artifactsDir: h.artifactsDir,
    dependencies: h.dependencies
  }), /cleanup did not complete/);
  await assert.rejects(stat(join(h.config.windows.appDataRoot, `physical-e2e-${h.runId}`)));
  const artifact = JSON.parse(await readFile(join(h.artifactsDir, 'physical-deep-e2e.json'), 'utf8'));
  assert.equal(artifact.status, 'failed');
  assert.equal(artifact.cleanup.succeeded, false);
  assert.ok(artifact.cleanup.steps.some(step => step.name === 'isolated-appdata' && step.succeeded));
  await rm(h.root, { recursive: true, force: true });
});
