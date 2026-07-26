import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback, spawn } from 'node:child_process';
import { access, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { isAbsolute, join, resolve } from 'node:path';

const execFile = promisify(execFileCallback);

export const ANDROID_SERIAL = '192.168.1.45:36969';
export const ANDROID_PACKAGE = 'network.xpoint.deep.e2e';
export const REQUIRED_FLOWS = Object.freeze([
  'invalidIdentity',
  'mutualIdentity',
  'windowsToAndroidText',
  'androidToWindowsText',
  'androidToWindowsAttachment',
  'coldRestartVerify'
]);

const SECRET_KEY = /(?:password|secret|token|api[_-]?key|authorization)/i;
const SEMANTIC_LOCATORS = new Set(['accessibility id', 'id']);

export function createMarkers(runId = randomUUID()) {
  const compact = runId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 20);
  return {
    runId,
    invalidIdentity: `deep-e2e-invalid-${compact}`,
    identityWindows: `deep-e2e-win-${compact}`,
    identityAndroid: `deep-e2e-android-${compact}`,
    windowsToAndroidMessage: `deep-e2e W>A ${compact}`,
    androidToWindowsMessage: `deep-e2e A>W ${compact}`,
    attachmentName: `deep-e2e-attachment-${compact}.bin`
  };
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function assertArm64WindowsExecutable(bytes) {
  const pe = Buffer.from(bytes);
  assert.ok(pe.length >= 0x40 && pe.subarray(0, 2).toString('ascii') === 'MZ', 'Windows executable is not a PE file');
  const headerOffset = pe.readUInt32LE(0x3c);
  assert.ok(pe.length >= headerOffset + 6 && pe.subarray(headerOffset, headerOffset + 4).toString('ascii') === 'PE\0\0', 'Windows executable has no PE header');
  assert.equal(pe.readUInt16LE(headerOffset + 4), 0xaa64, 'Windows executable must target ARM64 (PE machine 0xAA64)');
}

export function parseComposePs(stdout) {
  const trimmed = String(stdout).trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return trimmed.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  }
}

export function interpolate(value, variables) {
  if (typeof value !== 'string') return value;
  return value.replace(/{{([A-Za-z][A-Za-z0-9]*)}}/g, (_, key) => {
    assert.ok(Object.hasOwn(variables, key), `Unknown physical E2E template variable '{{${key}}}'`);
    return String(variables[key]);
  });
}

function required(value, message) {
  assert.ok(value, message);
  return value;
}

function rejectSecrets(value, path = 'config') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSecrets(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, nested] of Object.entries(value)) {
    assert.equal(SECRET_KEY.test(key), false, `${path}.${key} must not contain a secret; use a locally authenticated driver instead`);
    rejectSecrets(nested, `${path}.${key}`);
  }
}

function validateAction(action, name) {
  required(action && typeof action === 'object', `${name} must contain action objects`);
  required(['click', 'setValue', 'assertText', 'assertPresent', 'captureRouteMarker', 'assertFileSha256'].includes(action.type), `${name} has unsupported action '${action.type}'`);
  if (action.type === 'assertFileSha256') {
    required(['android', 'windows'].includes(action.target), `${name} file assertion needs target android or windows`);
    required(typeof action.path === 'string', `${name} file assertion needs path`);
    required(['attachment', 'explicit'].includes(action.expected), `${name} file assertion expected must be attachment or explicit`);
    if (action.expected === 'explicit') required(typeof action.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(action.sha256), `${name} explicit SHA-256 is invalid`);
    return;
  }
  required(['android', 'windows'].includes(action.target), `${name} needs target android or windows`);
  required(action.selector && typeof action.selector === 'object', `${name} needs a semantic selector`);
  required(SEMANTIC_LOCATORS.has(action.selector.using), `${name} selector must use accessibility id or id, never coordinates`);
  required(typeof action.selector.value === 'string' && action.selector.value.length > 0, `${name} selector value is required`);
  if (action.type === 'setValue') required(typeof action.value === 'string', `${name} setValue needs value`);
  if (action.type === 'assertText' || action.type === 'captureRouteMarker') required(typeof action.contains === 'string', `${name} ${action.type} needs contains`);
}

export function validateConfig(config) {
  required(config?.version === 1, 'physical E2E config.version must be 1');
  rejectSecrets(config);
  const compose = required(config.compose, 'compose configuration is required');
  required(typeof compose.file === 'string' && isAbsolute(compose.file), 'compose.file must be an absolute path');
  required(typeof compose.project === 'string' && compose.project.length > 0, 'compose.project is required');
  required(Array.isArray(compose.services) && compose.services.length > 0, 'compose.services is required');
  required(Array.isArray(compose.endpointPins) && compose.endpointPins.length > 0, 'compose.endpointPins are required (no unpinned stack)');
  for (const pin of compose.endpointPins) {
    required(compose.services.includes(pin.service), `endpoint pin service '${pin.service}' is not in compose.services`);
    required(typeof pin.url === 'string' && /^https?:\/\//.test(pin.url), `endpoint pin '${pin.service}' needs an http(s) URL`);
    required(Number.isInteger(pin.expectedStatus), `endpoint pin '${pin.service}' needs expectedStatus`);
  }

  const android = required(config.android, 'android configuration is required');
  assert.equal(android.serial, ANDROID_SERIAL, `android.serial must pin ${ANDROID_SERIAL}`);
  assert.equal(android.packageName, ANDROID_PACKAGE, `android.packageName must pin ${ANDROID_PACKAGE}`);
  required(typeof android.apkPath === 'string' && isAbsolute(android.apkPath), 'android.apkPath must be an absolute path');
  required(android.driver?.url, 'android.driver.url is required for semantic Appium automation');

  const windows = required(config.windows, 'windows configuration is required');
  required(typeof windows.exePath === 'string' && isAbsolute(windows.exePath), 'windows.exePath must be an absolute path');
  required(typeof windows.processName === 'string' && windows.processName.length > 0, 'windows.processName is required for a cold restart');
  required(typeof windows.appDataRoot === 'string' && isAbsolute(windows.appDataRoot), 'windows.appDataRoot must be an absolute path');
  required(windows.driver?.url, 'windows.driver.url is required for semantic UI Automation');
  required(typeof config.attachmentPath === 'string' && isAbsolute(config.attachmentPath), 'attachmentPath must be an absolute local fixture path');

  const flows = required(config.flows, 'flows are required');
  for (const flow of REQUIRED_FLOWS) {
    required(Array.isArray(flows[flow]) && flows[flow].length > 0, `required flow '${flow}' is missing`);
    flows[flow].forEach((action, index) => validateAction(action, `flows.${flow}[${index}]`));
  }
  for (const flow of ['windowsToAndroidText', 'androidToWindowsText']) {
    const variable = flow === 'windowsToAndroidText' ? '{{windowsToAndroidMessage}}' : '{{androidToWindowsMessage}}';
    const sender = flow === 'windowsToAndroidText' ? 'windows' : 'android';
    const receiver = flow === 'windowsToAndroidText' ? 'android' : 'windows';
    assert.ok(flows[flow].some(action => action.target === sender && action.type === 'setValue' && action.value.includes(variable)), `${flow} must inject ${variable} from ${sender}`);
    assert.ok(flows[flow].some(action => action.target === receiver && action.type === 'assertText' && action.contains.includes(variable)), `${flow} must assert receipt on ${receiver}`);
  }
  assert.ok(flows.mutualIdentity.some(action => action.type === 'setValue' && action.value.includes('{{identityWindows}}')) && flows.mutualIdentity.some(action => action.type === 'setValue' && action.value.includes('{{identityAndroid}}')), 'mutualIdentity must add both unique identities');
  assert.ok(flows.androidToWindowsAttachment.some(action => action.target === 'android' && action.type === 'setValue' && action.value.includes('{{attachmentPath}}')), 'attachment flow must select the attachment on Android semantically');
  assert.ok(flows.androidToWindowsAttachment.some(action => action.type === 'assertFileSha256' && action.expected === 'attachment'), 'attachment flow must assert decrypted attachment SHA-256');
  assert.ok(flows.coldRestartVerify.some(action => action.type === 'assertFileSha256' && action.expected === 'attachment'), 'cold restart flow must re-assert attachment SHA-256');
  if (config.chaos?.enabled) {
    required(Array.isArray(config.chaos.actions) && config.chaos.actions.length > 0, 'enabled chaos needs actions');
    validateAction(config.chaos.routeMarker, 'chaos.routeMarker');
    assert.equal(config.chaos.routeMarker.type, 'captureRouteMarker', 'chaos.routeMarker must capture an actual route marker from a semantic UI element');
    config.chaos.actions.forEach((action, index) => validateAction(action, `chaos.actions[${index}]`));
  }
  return config;
}

async function defaultCommand(command, args, options = {}) {
  const result = await execFile(command, args, { windowsHide: true, ...options });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

async function endpointProbe(pin, fetchImpl) {
  const response = await fetchImpl(pin.url, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
  assert.equal(response.status, pin.expectedStatus, `Endpoint pin ${pin.service} returned ${response.status}, expected ${pin.expectedStatus}`);
  const body = await response.text();
  if (pin.bodyIncludes) assert.ok(body.includes(pin.bodyIncludes), `Endpoint pin ${pin.service} response lacks required body marker`);
  return { service: pin.service, url: pin.url, status: response.status, bodySha256: sha256(body) };
}

function parsePackageMetadata(stdout) {
  const versionName = stdout.match(/versionName=([^\s]+)/)?.[1];
  const versionCode = stdout.match(/versionCode=(\d+)/)?.[1];
  assert.ok(versionName && versionCode, 'Installed Android package metadata is incomplete (versionName/versionCode)');
  return { versionName, versionCode: Number(versionCode) };
}

export async function preflight(config, dependencies = {}) {
  validateConfig(config);
  const command = dependencies.command ?? defaultCommand;
  const fetchImpl = dependencies.fetch ?? fetch;
  const fs = dependencies.fs ?? { access, mkdir, readFile, stat, writeFile };
  await fs.access(config.compose.file);
  const composeResult = await command('docker', ['compose', '-p', config.compose.project, '-f', config.compose.file, 'ps', '--format', 'json']);
  const containers = parseComposePs(composeResult.stdout);
  for (const service of config.compose.services) {
    const container = containers.find(item => item.Service === service);
    assert.ok(container, `Compose service '${service}' is absent; refusing physical run`);
    assert.equal(String(container.State).toLowerCase(), 'running', `Compose service '${service}' is not running`);
    assert.equal(String(container.Health).toLowerCase(), 'healthy', `Compose service '${service}' is not healthy`);
  }
  const endpoints = await Promise.all(config.compose.endpointPins.map(pin => endpointProbe(pin, fetchImpl)));

  const adbState = await command('adb', ['-s', config.android.serial, 'get-state']);
  assert.equal(adbState.stdout.trim(), 'device', `ADB serial ${config.android.serial} is not an authorized device`);
  const installedPath = await command('adb', ['-s', config.android.serial, 'shell', 'pm', 'path', config.android.packageName]);
  assert.match(installedPath.stdout, /^package:/m, `Android package ${config.android.packageName} is not installed`);
  const installedDump = await command('adb', ['-s', config.android.serial, 'shell', 'dumpsys', 'package', config.android.packageName]);
  const installed = parsePackageMetadata(installedDump.stdout);
  await fs.access(config.android.apkPath);
  const apkStats = await fs.stat(config.android.apkPath);
  const apkBytes = await fs.readFile(config.android.apkPath);
  const badging = await command('aapt', ['dump', 'badging', config.android.apkPath]);
  assert.match(badging.stdout, new RegExp(`package: name='${ANDROID_PACKAGE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`), 'APK package does not match pinned Android package');

  await fs.access(config.windows.exePath);
  const runAppData = join(resolve(config.windows.appDataRoot), `physical-e2e-${createMarkers().runId}`);
  await fs.mkdir(runAppData, { recursive: true });
  await fs.writeFile(join(runAppData, '.deep-e2e-isolated'), 'physical-e2e isolated appdata\n', 'utf8');
  const windowsStats = await fs.stat(config.windows.exePath);
  assertArm64WindowsExecutable(await fs.readFile(config.windows.exePath));
  await fs.access(config.attachmentPath);
  const attachment = await fs.readFile(config.attachmentPath);
  return {
    compose: { services: config.compose.services, endpoints },
    android: { serial: config.android.serial, packageName: config.android.packageName, installedPath: installedPath.stdout.trim(), installed, apk: { path: config.android.apkPath, bytes: apkStats.size, sha256: sha256(apkBytes) } },
    windows: { exePath: config.windows.exePath, bytes: windowsStats.size, isolatedAppData: runAppData },
    attachment: { path: config.attachmentPath, bytes: attachment.length, sha256: sha256(attachment) }
  };
}

async function webdriverRequest(url, path, init = {}) {
  const response = await fetch(new URL(path, url), { ...init, headers: { 'content-type': 'application/json', ...(init.headers ?? {}) }, signal: AbortSignal.timeout(20_000) });
  const body = await response.json().catch(() => ({}));
  assert.ok(response.ok && !body.value?.error, `WebDriver ${init.method ?? 'GET'} ${path} failed: ${JSON.stringify(body.value ?? body)}`);
  return body.value ?? body;
}

async function startDriver(target) {
  const capabilities = structuredClone(target.driver.capabilities ?? {});
  capabilities.alwaysMatch ??= {};
  const value = await webdriverRequest(target.driver.url, '/session', { method: 'POST', body: JSON.stringify({ capabilities }) });
  return { url: target.driver.url, id: value.sessionId ?? value.capabilities?.sessionId ?? value }; 
}

async function element(driver, selector) {
  const value = await webdriverRequest(driver.url, `/session/${driver.id}/element`, { method: 'POST', body: JSON.stringify({ using: selector.using, value: selector.value }) });
  const id = value['element-6066-11e4-a52e-4f735466cecf'] ?? value.ELEMENT;
  assert.ok(id, `WebDriver did not return an element for ${selector.using}:${selector.value}`);
  return id;
}

async function executeActions(drivers, actions, variables, evidence) {
  for (const definition of actions) {
    if (definition.type === 'assertFileSha256') {
      const filePath = interpolate(definition.path, variables);
      const actual = sha256(await readFile(filePath));
      const expected = definition.expected === 'attachment' ? variables.attachmentSha256 : interpolate(definition.sha256, variables);
      assert.equal(actual, expected, `Decrypted file SHA-256 differs: ${filePath}`);
      evidence.files.push({ path: filePath, sha256: actual });
      continue;
    }
    const driver = drivers[definition.target];
    assert.ok(driver, `No active ${definition.target} driver for semantic action`);
    const selector = { using: definition.selector.using, value: interpolate(definition.selector.value, variables) };
    const id = await element(driver, selector);
    if (definition.type === 'click') await webdriverRequest(driver.url, `/session/${driver.id}/element/${id}/click`, { method: 'POST', body: '{}' });
    if (definition.type === 'setValue') await webdriverRequest(driver.url, `/session/${driver.id}/element/${id}/value`, { method: 'POST', body: JSON.stringify({ text: interpolate(definition.value, variables) }) });
    if (definition.type === 'assertText' || definition.type === 'captureRouteMarker') {
      const text = await webdriverRequest(driver.url, `/session/${driver.id}/element/${id}/text`);
      assert.ok(String(text).includes(interpolate(definition.contains, variables)), `Expected semantic element ${selector.value} to contain correlated marker`);
      if (definition.type === 'captureRouteMarker') evidence.routeMarkers ??= [], evidence.routeMarkers.push(String(text));
    }
    evidence.actions.push({ type: definition.type, selector });
  }
}

async function stopDriver(driver) {
  if (driver) await fetch(new URL(`/session/${driver.id}`, driver.url), { method: 'DELETE', signal: AbortSignal.timeout(10_000) }).catch(() => {});
}

export async function runPhysicalE2E(config, options = {}) {
  const artifactsDir = required(options.artifactsDir, 'artifactsDir is required');
  const start = new Date().toISOString();
  const markers = createMarkers(options.runId);
  const preflightEvidence = await preflight(config, options.dependencies);
  const variables = { ...markers, attachmentPath: config.attachmentPath, attachmentSha256: preflightEvidence.attachment.sha256, runAppData: preflightEvidence.windows.isolatedAppData };
  const evidence = { schemaVersion: 1, startedAt: start, status: 'failed', markers, preflight: preflightEvidence, flows: [], files: [] };
  await mkdir(artifactsDir, { recursive: true });
  let android;
  let windows;
  let windowsProcess;
  const command = options.dependencies?.command ?? defaultCommand;
  const launchWindows = () => {
    const env = {
      ...process.env,
      APPDATA: join(preflightEvidence.windows.isolatedAppData, 'Roaming'),
      LOCALAPPDATA: join(preflightEvidence.windows.isolatedAppData, 'Local'),
      TEMP: join(preflightEvidence.windows.isolatedAppData, 'Temp'),
      TMP: join(preflightEvidence.windows.isolatedAppData, 'Temp')
    };
    return spawn(config.windows.exePath, config.windows.arguments ?? [], { detached: true, env, stdio: 'ignore', windowsHide: true });
  };
  const restartBothClients = async () => {
    await stopDriver(android);
    await stopDriver(windows);
    if (windowsProcess?.pid) await command('taskkill', ['/pid', String(windowsProcess.pid), '/t', '/f']);
    await command('adb', ['-s', config.android.serial, 'shell', 'am', 'force-stop', config.android.packageName]);
    await command('adb', ['-s', config.android.serial, 'shell', 'monkey', '-p', config.android.packageName, '1']);
    windowsProcess = launchWindows();
    android = await startDriver(config.android);
    windows = await startDriver(config.windows);
  };
  try {
    windowsProcess = launchWindows();
    android = await startDriver(config.android);
    windows = await startDriver(config.windows);
    for (const name of REQUIRED_FLOWS) {
      if (name === 'coldRestartVerify') {
        await restartBothClients();
      }
      const flowEvidence = { name, actions: [], files: [] };
      await executeActions({ android, windows }, config.flows[name], variables, flowEvidence);
      evidence.flows.push(flowEvidence);
      evidence.files.push(...flowEvidence.files);
    }
    if (config.chaos?.enabled) {
      const chaosEvidence = { executed: false, deterministicFailoverClaim: false };
      const markerAction = config.chaos.routeMarker;
      const routeEvidence = { actions: [], files: [] };
      await executeActions({ android, windows }, [markerAction], variables, routeEvidence);
      assert.ok(routeEvidence.routeMarkers?.length, 'Actual route marker was not found; chaos is refused');
      await executeActions({ android, windows }, config.chaos.actions, variables, routeEvidence);
      Object.assign(chaosEvidence, { executed: true, routeMarkers: routeEvidence.routeMarkers, routeMarkerSelector: markerAction.selector });
      evidence.chaos = chaosEvidence;
    }
    evidence.status = 'passed';
    return evidence;
  } finally {
    evidence.finishedAt = new Date().toISOString();
    await writeFile(join(artifactsDir, 'physical-deep-e2e.json'), JSON.stringify(evidence, null, 2));
    await Promise.all([stopDriver(android), stopDriver(windows)]);
    if (windowsProcess?.pid) await command('taskkill', ['/pid', String(windowsProcess.pid), '/t', '/f']).catch(() => {});
  }
}
