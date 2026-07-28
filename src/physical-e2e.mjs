import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback, spawn as spawnProcess } from 'node:child_process';
import {
  access,
  lstat,
  mkdir,
  readFile,
  realpath,
  rm,
  stat,
  unlink,
  writeFile
} from 'node:fs/promises';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';

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
const UI_ACTIONS = new Set([
  'setValue',
  'click',
  'assertText',
  'waitText',
  'assertNotTextStable',
  'captureIdentity',
  'captureRouteMarker',
  'assertDownloadedAttachment'
]);
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

// The adapter is injectable through `fs.isReparsePoint` for portable hosts and
// test doubles. Node exposes a native reparse predicate in some runtimes and
// the Windows attribute in others; callers can provide the same adapter when
// their host exposes neither representation.
export async function isWindowsReparsePoint(_path, info) {
  return Boolean(
    info?.isReparsePoint?.() ||
    (Number(info?.attributes) & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) !== 0
  );
}

const fsDefault = { access, isReparsePoint: isWindowsReparsePoint, lstat, mkdir, readFile, realpath, rm, stat, unlink, writeFile };

export function createMarkers(runId = randomUUID()) {
  assert.match(runId, /^[A-Za-z0-9][A-Za-z0-9-]{3,79}$/, 'runId must be a safe 4-80 character identifier');
  const compact = sha256(runId).slice(0, 20);
  return {
    runId,
    invalidIdentity: `deep-e2e-invalid-${compact}`,
    contactMarkerWindows: `deep-e2e-contact-win-${compact}`,
    contactMarkerAndroid: `deep-e2e-contact-android-${compact}`,
    windowsToAndroidMessage: `deep-e2e W>A ${compact}`,
    androidToWindowsMessage: `deep-e2e A>W ${compact}`,
    attachmentName: `deep-e2e-attachment-${compact}.bin`
  };
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function pathFingerprint(path) {
  return { basename: basename(path), pathSha256: sha256(resolve(path).toLowerCase()) };
}

function normalizeEndpointUrl(value) {
  const url = new URL(value);
  assert.ok(['http:', 'https:'].includes(url.protocol), 'endpoint pin must use HTTP(S)');
  assert.equal(url.username, '', 'endpoint pin cannot contain credentials');
  assert.equal(url.password, '', 'endpoint pin cannot contain credentials');
  assert.equal(url.search, '', 'endpoint pin cannot contain a query string');
  assert.equal(url.hash, '', 'endpoint pin cannot contain a fragment');
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, '');
  return `${url.origin}${url.pathname}`;
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
    assert.equal(SECRET_KEY.test(key), false, `${path}.${key} must not contain a secret`);
    rejectSecrets(nested, `${path}.${key}`);
  }
}

function hasAction(actions, predicate) {
  return actions.some(predicate);
}

function validateSelector(action, name) {
  required(action.selector && typeof action.selector === 'object', `${name} needs a semantic selector`);
  required(SEMANTIC_LOCATORS.has(action.selector.using), `${name} selector must use accessibility id or id, never coordinates`);
  required(typeof action.selector.value === 'string' && action.selector.value.length > 0, `${name} selector value is required`);
}

function validateAction(action, name) {
  required(action && typeof action === 'object', `${name} must be an action object`);
  required(UI_ACTIONS.has(action.type), `${name} has unsupported action '${action.type}'`);
  assert.ok(['android', 'windows'].includes(action.target), `${name} needs target android or windows`);
  if (action.type === 'assertDownloadedAttachment') {
    assert.equal(action.target, 'windows', `${name} decrypted attachment assertion must target Windows`);
    assert.ok(['initial', 'afterRestart'].includes(action.phase), `${name} needs initial or afterRestart phase`);
    return;
  }
  validateSelector(action, name);
  if (action.type === 'setValue') required(typeof action.value === 'string', `${name} setValue needs value`);
  if (['assertText', 'waitText', 'assertNotTextStable'].includes(action.type)) {
    required(typeof action.contains === 'string' && action.contains.length > 0, `${name} ${action.type} needs contains`);
  }
  if (action.type === 'assertNotTextStable') {
    assert.ok(Number.isInteger(action.stabilityMs) && action.stabilityMs >= 1_000 && action.stabilityMs <= 60_000, `${name} stabilityMs must be 1000-60000`);
  }
  if (action.type === 'captureIdentity') {
    assert.ok(['actualIdentityWindows', 'actualIdentityAndroid'].includes(action.saveAs), `${name} has invalid identity destination`);
  }
  if (action.type === 'captureRouteMarker') {
    assert.equal(action.saveAs, 'observedRouteNode', `${name} must save observedRouteNode`);
    required(action.expected === '{{expectedRouteNode}}', `${name} must match the exact expected route node`);
  }
}

function requirePurpose(actions, purpose, predicate = () => true) {
  assert.ok(hasAction(actions, action => action.purpose === purpose && predicate(action)), `flow is missing required '${purpose}' evidence`);
}

function requireOrderedPurposes(flowName, actions, purposes) {
  const positions = purposes.map(purpose => actions.findIndex(action => action.purpose === purpose));
  assert.ok(positions.every(position => position >= 0), `${flowName} is missing an ordered purpose`);
  for (let index = 1; index < positions.length; index += 1) {
    assert.ok(positions[index] > positions[index - 1], `${flowName} purposes must follow strict order: ${purposes.join(' -> ')}`);
  }
}

export function validateConfig(config) {
  assert.equal(config?.version, 2, 'physical E2E config.version must be 2');
  rejectSecrets(config);

  const compose = required(config.compose, 'compose configuration is required');
  assert.ok(typeof compose.file === 'string' && isAbsolute(compose.file), 'compose.file must be an absolute path');
  required(typeof compose.project === 'string' && compose.project.length > 0, 'compose.project is required');
  assert.ok(Array.isArray(compose.services) && compose.services.length > 0, 'compose.services is required');
  assert.equal(new Set(compose.services).size, compose.services.length, 'compose.services must be unique');
  assert.equal(compose.endpointPins?.length, compose.services.length, 'every compose service needs exactly one successful endpoint pin');
  const normalizedEndpointUrls = new Set();
  for (const service of compose.services) {
    const pins = compose.endpointPins.filter(pin => pin.service === service);
    assert.equal(pins.length, 1, `compose service '${service}' needs exactly one endpoint pin`);
    const [pin] = pins;
    const normalizedUrl = normalizeEndpointUrl(pin.url);
    assert.equal(normalizedEndpointUrls.has(normalizedUrl), false, `endpoint pin '${service}' reuses another service URL`);
    normalizedEndpointUrls.add(normalizedUrl);
    assert.equal(pin.expectedStatus, 200, `endpoint pin '${service}' must require HTTP 200`);
    assert.equal(Object.hasOwn(pin, 'bodyIncludes'), false, `endpoint pin '${service}' must not use a substring body marker`);
  }

  const android = required(config.android, 'android configuration is required');
  assert.equal(android.serial, ANDROID_SERIAL, `android.serial must pin ${ANDROID_SERIAL}`);
  assert.equal(android.packageName, ANDROID_PACKAGE, `android.packageName must pin ${ANDROID_PACKAGE}`);
  assert.ok(typeof android.apkPath === 'string' && isAbsolute(android.apkPath), 'android.apkPath must be absolute');
  assert.match(android.attachmentDirectory, /^\/sdcard\/[A-Za-z0-9_./-]+$/, 'android.attachmentDirectory must be an absolute /sdcard path');
  assert.equal(android.attachmentDirectory.split('/').some(part => part === '.' || part === '..'), false, 'android.attachmentDirectory cannot traverse directories');
  assert.equal(android.driver?.capabilities?.alwaysMatch?.platformName, 'Android', 'Android driver platformName must be Android');
  assert.equal(android.driver.capabilities.alwaysMatch['appium:automationName'], 'UiAutomator2', 'Android driver must use UiAutomator2');
  for (const managed of ['appium:app', 'appium:udid', 'appium:appPackage']) {
    assert.equal(Object.hasOwn(android.driver.capabilities.alwaysMatch, managed), false, `runner exclusively manages Android capability '${managed}'`);
  }
  required(android.driver.url, 'android.driver.url is required');
  assert.equal(android.identityPattern, '^05[0-9a-fA-F]{64}$', 'android.identityPattern must enforce a full Deep identity');

  const windows = required(config.windows, 'windows configuration is required');
  assert.ok(typeof windows.exePath === 'string' && isAbsolute(windows.exePath), 'windows.exePath must be absolute');
  required(typeof windows.processName === 'string' && windows.processName.length > 0, 'windows.processName is required');
  assert.ok(typeof windows.appDataRoot === 'string' && isAbsolute(windows.appDataRoot), 'windows.appDataRoot must be absolute');
  assert.ok(Number.isInteger(windows.launchTimeoutMs) && windows.launchTimeoutMs >= 1_000 && windows.launchTimeoutMs <= 60_000, 'windows.launchTimeoutMs must be 1000-60000');
  assert.ok(Number.isInteger(windows.launchPollMs) && windows.launchPollMs >= 50 && windows.launchPollMs <= 1_000, 'windows.launchPollMs must be 50-1000');
  assert.equal(windows.driver?.capabilities?.alwaysMatch?.platformName, 'Windows', 'Windows driver platformName must be Windows');
  for (const managed of ['appium:app', 'appium:appTopLevelWindow', 'deep:processId', 'deep:executableSha256']) {
    assert.equal(Object.hasOwn(windows.driver.capabilities.alwaysMatch, managed), false, `runner exclusively manages Windows capability '${managed}'`);
  }
  required(windows.driver.url, 'windows.driver.url is required');
  assert.equal(windows.identityPattern, '^05[0-9a-fA-F]{64}$', 'windows.identityPattern must enforce a full Deep identity');
  assert.ok(typeof config.attachmentPath === 'string' && isAbsolute(config.attachmentPath), 'attachmentPath must be an absolute local fixture path');

  const flows = required(config.flows, 'flows are required');
  for (const flow of REQUIRED_FLOWS) {
    assert.ok(Array.isArray(flows[flow]) && flows[flow].length > 0, `required flow '${flow}' is missing`);
    flows[flow].forEach((action, index) => validateAction(action, `flows.${flow}[${index}]`));
    const purposes = flows[flow].map(action => action.purpose);
    assert.ok(purposes.every(purpose => typeof purpose === 'string' && purpose.length > 0), `${flow} actions need explicit purposes`);
    assert.equal(new Set(purposes).size, purposes.length, `${flow} action purposes must be unique`);
  }

  const invalid = flows.invalidIdentity;
  const invalidTarget = invalid.find(action => action.purpose === 'invalidIdentityEntry')?.target;
  requirePurpose(invalid, 'invalidIdentityEntry', action => action.type === 'setValue' && action.value.includes('{{invalidIdentity}}'));
  requirePurpose(invalid, 'invalidIdentitySubmit', action => action.target === invalidTarget && action.type === 'click');
  requirePurpose(invalid, 'invalidIdentityRejection', action => action.target === invalidTarget && action.type === 'assertText');
  requirePurpose(invalid, 'invalidIdentityContactAbsent', action => action.target === invalidTarget && action.type === 'assertNotTextStable' && action.contains.includes('{{invalidIdentity}}'));
  requireOrderedPurposes('invalidIdentity', invalid, [
    'invalidIdentityEntry',
    'invalidIdentitySubmit',
    'invalidIdentityRejection',
    'invalidIdentityContactAbsent'
  ]);

  const mutual = flows.mutualIdentity;
  requirePurpose(mutual, 'captureWindowsIdentity', action => action.type === 'captureIdentity' && action.target === 'windows' && action.saveAs === 'actualIdentityWindows');
  requirePurpose(mutual, 'captureAndroidIdentity', action => action.type === 'captureIdentity' && action.target === 'android' && action.saveAs === 'actualIdentityAndroid');
  for (const [target, identity, marker] of [
    ['windows', '{{actualIdentityAndroid}}', '{{contactMarkerAndroid}}'],
    ['android', '{{actualIdentityWindows}}', '{{contactMarkerWindows}}']
  ]) {
    requirePurpose(mutual, `addIdentityOn${target}`, action => action.target === target && action.type === 'setValue' && action.value.includes(identity));
    requirePurpose(mutual, `setMarkerOn${target}`, action => action.target === target && action.type === 'setValue' && action.value.includes(marker));
    requirePurpose(mutual, `submitContactOn${target}`, action => action.target === target && action.type === 'click');
    requirePurpose(mutual, `contactPresentOn${target}`, action => action.target === target && action.type === 'waitText' && action.contains.includes(marker));
  }
  requireOrderedPurposes('mutualIdentity', mutual, [
    'captureWindowsIdentity',
    'captureAndroidIdentity',
    'addIdentityOnwindows',
    'setMarkerOnwindows',
    'submitContactOnwindows',
    'contactPresentOnwindows',
    'addIdentityOnandroid',
    'setMarkerOnandroid',
    'submitContactOnandroid',
    'contactPresentOnandroid'
  ]);

  for (const [flow, sender, receiver, marker] of [
    ['windowsToAndroidText', 'windows', 'android', '{{windowsToAndroidMessage}}'],
    ['androidToWindowsText', 'android', 'windows', '{{androidToWindowsMessage}}']
  ]) {
    requirePurpose(flows[flow], 'messageEntry', action => action.target === sender && action.type === 'setValue' && action.value.includes(marker));
    requirePurpose(flows[flow], 'messageSend', action => action.target === sender && action.type === 'click');
    requirePurpose(flows[flow], 'messageReceive', action => action.target === receiver && action.type === 'waitText' && action.contains.includes(marker));
    requireOrderedPurposes(flow, flows[flow], ['messageEntry', 'messageSend', 'messageReceive']);
  }

  const attachment = flows.androidToWindowsAttachment;
  requirePurpose(attachment, 'attachmentPick', action => action.target === 'android' && action.type === 'setValue' && action.value.includes('{{androidAttachmentPath}}'));
  requirePurpose(attachment, 'attachmentSend', action => action.target === 'android' && action.type === 'click');
  requirePurpose(attachment, 'attachmentListed', action => action.target === 'windows' && action.type === 'waitText' && action.contains.includes('{{attachmentName}}'));
  requirePurpose(attachment, 'attachmentDownload', action => action.target === 'windows' && action.type === 'click');
  requirePurpose(attachment, 'attachmentInitialHash', action => action.type === 'assertDownloadedAttachment' && action.phase === 'initial');
  requireOrderedPurposes('androidToWindowsAttachment', attachment, [
    'attachmentPick',
    'attachmentSend',
    'attachmentListed',
    'attachmentDownload',
    'attachmentInitialHash'
  ]);

  const restart = flows.coldRestartVerify;
  requirePurpose(restart, 'reopenConversation', action => action.target === 'windows' && action.type === 'click');
  requirePurpose(restart, 'attachmentListedAfterRestart', action => action.target === 'windows' && action.type === 'waitText' && action.contains.includes('{{attachmentName}}'));
  requirePurpose(restart, 'attachmentRedownload', action => action.target === 'windows' && action.type === 'click');
  requirePurpose(restart, 'attachmentRestartHash', action => action.type === 'assertDownloadedAttachment' && action.phase === 'afterRestart');
  requireOrderedPurposes('coldRestartVerify', restart, [
    'reopenConversation',
    'attachmentListedAfterRestart',
    'attachmentRedownload',
    'attachmentRestartHash'
  ]);

  if (config.chaos?.enabled) {
    assert.ok(typeof config.chaos.expectedRouteNode === 'string' && config.chaos.expectedRouteNode.length > 0, 'chaos.expectedRouteNode is required');
    assert.ok(Number.isInteger(config.chaos.healthTimeoutMs) && config.chaos.healthTimeoutMs >= 1_000 && config.chaos.healthTimeoutMs <= 120_000, 'chaos.healthTimeoutMs must be 1000-120000');
    assert.ok(Number.isInteger(config.chaos.healthPollMs) && config.chaos.healthPollMs >= 100 && config.chaos.healthPollMs <= 5_000, 'chaos.healthPollMs must be 100-5000');
    validateAction(config.chaos.routeMarker, 'chaos.routeMarker');
    assert.equal(config.chaos.routeMarker.type, 'captureRouteMarker', 'chaos.routeMarker must capture an actual route marker');
    assert.ok(Array.isArray(config.chaos.routeBindings) && config.chaos.routeBindings.length > 0, 'chaos routeNode-to-composeService bindings are required');
    assert.equal(new Set(config.chaos.routeBindings.map(binding => binding.routeNode)).size, config.chaos.routeBindings.length, 'chaos routeNode bindings must be unique');
    for (const binding of config.chaos.routeBindings) {
      assert.ok(typeof binding.routeNode === 'string' && binding.routeNode.length > 0, 'chaos binding routeNode is required');
      assert.ok(compose.services.includes(binding.composeService), `chaos binding service '${binding.composeService}' is not a compose service`);
    }
    assert.equal(config.chaos.routeBindings.filter(binding => binding.routeNode === config.chaos.expectedRouteNode).length, 1, 'expected route node must have exactly one compose service binding');
    assert.ok(Array.isArray(config.chaos.actions) && config.chaos.actions.length > 0, 'enabled chaos needs actions');
    for (const action of config.chaos.actions) {
      assert.equal(action.type, 'restartComposeService', 'only restartComposeService is allowlisted');
      assert.equal(action.routeRef, '{{observedRouteNode}}', 'chaos action must reference captured route');
      assert.equal(Object.hasOwn(action, 'service'), false, 'chaos action service must be derived from the route binding');
      assert.equal(Object.hasOwn(action, 'routeNode'), false, 'chaos action route must use the captured route reference');
    }
  }
  return config;
}

async function defaultCommand(command, args, options = {}) {
  const result = await execFile(command, args, { windowsHide: true, maxBuffer: 16 * 1024 * 1024, ...options });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function now(dependencies = {}) {
  return (dependencies.now ?? Date.now)();
}

async function beforeDeadline(work, deadline, label, dependencies = {}) {
  const remaining = deadline - now(dependencies);
  assert.ok(remaining > 0, `${label} exceeded its deadline`);
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} exceeded its deadline`)), remaining);
    });
    const result = await Promise.race([work(remaining), timeout]);
    assert.ok(now(dependencies) < deadline, `${label} completed after its deadline`);
    return result;
  } finally {
    clearTimeout(timer);
  }
}

export async function endpointProbe(pin, fetchImpl, deadline = now() + 10_000, dependencies = {}) {
  const startedAt = now(dependencies);
  const response = await beforeDeadline(
    remaining => fetchImpl(pin.url, { redirect: 'error', signal: AbortSignal.timeout(remaining) }),
    deadline,
    `Endpoint pin ${pin.service} fetch`,
    dependencies
  );
  assert.equal(response.ok, true, `Endpoint pin ${pin.service} did not return success`);
  assert.equal(response.status, 200, `Endpoint pin ${pin.service} did not return HTTP 200`);
  const body = await beforeDeadline(
    () => response.json(),
    deadline,
    `Endpoint pin ${pin.service} body`,
    dependencies
  ).catch(error => {
    if (String(error?.message).includes('deadline')) throw error;
    assert.fail(`Endpoint pin ${pin.service} response must be JSON`);
  });
  assert.ok(body && typeof body === 'object' && !Array.isArray(body), `Endpoint pin ${pin.service} response must be a JSON object`);
  assert.equal(body.service, pin.service, `Endpoint pin ${pin.service} response service provenance mismatch`);
  return {
    service: pin.service,
    status: response.status,
    urlSha256: sha256(normalizeEndpointUrl(pin.url)),
    bodySha256: sha256(JSON.stringify(body)),
    elapsedMs: now(dependencies) - startedAt
  };
}

export async function waitForEndpointPin(pin, fetchImpl, timeoutMs, pollMs, sleep = ms => new Promise(resolveWait => setTimeout(resolveWait, ms)), dependencies = {}) {
  const startedAt = now(dependencies);
  const deadline = startedAt + timeoutMs;
  let latestError;
  while (now(dependencies) < deadline) {
    try {
      const result = await endpointProbe(pin, fetchImpl, deadline, dependencies);
      assert.ok(now(dependencies) < deadline, `Endpoint pin ${pin.service} completed after its deadline`);
      return { ...result, elapsedMs: now(dependencies) - startedAt };
    } catch (error) {
      latestError = error;
      const remaining = deadline - now(dependencies);
      if (remaining <= 0) break;
      await sleep(Math.min(pollMs, remaining));
    }
  }
  throw latestError ?? new Error(`Endpoint pin ${pin.service} exceeded its deadline`);
}

function parseAaptBadging(stdout) {
  const match = String(stdout).match(/package:\s+name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']+)'/);
  assert.ok(match, 'aapt badging lacks package/version metadata');
  return { packageName: match[1], versionCode: match[2], versionName: match[3] };
}

function parseSigner(stdout) {
  const digest = String(stdout).match(/certificate SHA-256 digest:\s*([0-9a-f:]{64,95})/i)?.[1]?.replaceAll(':', '').toLowerCase();
  assert.match(digest ?? '', /^[0-9a-f]{64}$/, 'APK signer SHA-256 is missing');
  return digest;
}

function parseInstalledPackage(stdout) {
  const text = String(stdout);
  const versionName = text.match(/versionName=([^\s]+)/)?.[1];
  const versionCode = text.match(/versionCode=(\d+)/)?.[1];
  const signatureHex = text.match(/signatures[=:]\s*\[([0-9a-f]+)\]/i)?.[1];
  assert.ok(versionName && versionCode && signatureHex, 'installed dumpsys metadata lacks version or signing identity');
  return {
    versionName,
    versionCode,
    signingSha256: sha256(Buffer.from(signatureHex, 'hex'))
  };
}

function safeUnder(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel.length > 0 && !rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel);
}

async function assertNotReparsePoint(path, info, fs, context) {
  assert.equal(info.isSymbolicLink(), false, `${context} cannot be a symlink/reparse point`);
  const check = fs.isReparsePoint ?? isWindowsReparsePoint;
  assert.equal(await check(path, info), false, `${context} cannot have the Windows ReparsePoint attribute`);
}

async function assertCanonicalDirectory(path, fs) {
  const info = await fs.lstat(path);
  await assertNotReparsePoint(path, info, fs, `directory '${basename(path)}'`);
  assert.equal((await fs.realpath(path)).toLowerCase(), resolve(path).toLowerCase(), `directory is redirected outside its canonical path: ${basename(path)}`);
}

export async function preflight(config, dependencies = {}, runId = randomUUID()) {
  validateConfig(config);
  const command = dependencies.command ?? defaultCommand;
  const fetchImpl = dependencies.fetch ?? fetch;
  const fs = dependencies.fs ?? fsDefault;

  await fs.access(config.compose.file);
  const composeResult = await command('docker', ['compose', '-p', config.compose.project, '-f', config.compose.file, 'ps', '--format', 'json']);
  const containers = parseComposePs(composeResult.stdout);
  for (const service of config.compose.services) {
    const matching = containers.filter(item => item.Service === service);
    assert.equal(matching.length, 1, `Compose service '${service}' must resolve to exactly one container`);
    assert.equal(String(matching[0].State).toLowerCase(), 'running', `Compose service '${service}' is not running`);
    assert.equal(String(matching[0].Health).toLowerCase(), 'healthy', `Compose service '${service}' is not healthy`);
  }
  const endpoints = await Promise.all(config.compose.endpointPins.map(pin => endpointProbe(pin, fetchImpl)));

  const adbState = await command('adb', ['-s', config.android.serial, 'get-state']);
  assert.equal(String(adbState.stdout).trim(), 'device', `ADB serial ${config.android.serial} is not authorized`);
  const installedPathResult = await command('adb', ['-s', config.android.serial, 'shell', 'pm', 'path', config.android.packageName]);
  const installedPath = String(installedPathResult.stdout).match(/^package:(.+base\.apk)$/m)?.[1];
  assert.ok(installedPath, `Android package ${config.android.packageName} base APK is not installed`);
  const installedDump = await command('adb', ['-s', config.android.serial, 'shell', 'dumpsys', 'package', config.android.packageName]);
  const installed = parseInstalledPackage(installedDump.stdout);

  await fs.access(config.android.apkPath);
  const apkBytes = await fs.readFile(config.android.apkPath);
  const badging = parseAaptBadging((await command('aapt', ['dump', 'badging', config.android.apkPath])).stdout);
  const signingSha256 = parseSigner((await command('apksigner', ['verify', '--print-certs', config.android.apkPath])).stdout);
  assert.equal(badging.packageName, config.android.packageName, 'APK package differs from installed package');
  assert.equal(badging.versionCode, installed.versionCode, 'APK versionCode differs from installed package');
  assert.equal(badging.versionName, installed.versionName, 'APK versionName differs from installed package');
  assert.equal(signingSha256, installed.signingSha256, 'APK signing identity differs from installed package');

  await fs.access(config.windows.exePath);
  const windowsBytes = await fs.readFile(config.windows.exePath);
  assertArm64WindowsExecutable(windowsBytes);
  await fs.access(config.attachmentPath);
  const attachmentLinkInfo = await fs.lstat(config.attachmentPath);
  await assertNotReparsePoint(config.attachmentPath, attachmentLinkInfo, fs, 'attachment source');
  const canonicalAttachmentPath = await fs.realpath(config.attachmentPath);
  assert.equal(canonicalAttachmentPath.toLowerCase(), resolve(config.attachmentPath).toLowerCase(), 'attachment source path is not canonical');
  const attachmentInfo = await fs.stat(canonicalAttachmentPath);
  assert.equal(attachmentInfo.isFile(), true, 'attachment source must be a regular file');
  const attachment = await fs.readFile(canonicalAttachmentPath);

  const appDataParent = resolve(config.windows.appDataRoot);
  await fs.mkdir(appDataParent, { recursive: true });
  await assertCanonicalDirectory(appDataParent, fs);
  const runAppData = join(appDataParent, `physical-e2e-${runId}`);
  assert.ok(safeUnder(appDataParent, runAppData), 'unique AppData escaped configured root');
  assert.equal(resolve(runAppData), join(appDataParent, basename(runAppData)), 'unique AppData must be a direct child of configured root');
  const downloadRoot = join(runAppData, 'Downloads');
  let appDataCreated = false;
  try {
    await fs.mkdir(runAppData, { recursive: false });
    appDataCreated = true;
    await fs.mkdir(downloadRoot, { recursive: false });
    await assertCanonicalDirectory(runAppData, fs);
    await assertCanonicalDirectory(downloadRoot, fs);
    await fs.writeFile(join(runAppData, '.deep-e2e-isolated'), 'physical-e2e isolated appdata\n', 'utf8');
  } catch (error) {
    if (appDataCreated) await fs.rm(runAppData, { recursive: true, force: true }).catch(() => {});
    throw error;
  }

  return {
    compose: { services: [...config.compose.services], endpoints },
    android: {
      serial: config.android.serial,
      packageName: config.android.packageName,
      installedPath,
      installed,
      apk: { ...badging, signingSha256, bytes: apkBytes.length, sha256: sha256(apkBytes), path: config.android.apkPath }
    },
    windows: {
      exePath: config.windows.exePath,
      exeSha256: sha256(windowsBytes),
      bytes: windowsBytes.length,
      isolatedAppData: runAppData,
      downloadRoot
    },
    attachment: {
      path: canonicalAttachmentPath,
      bytes: attachment.length,
      sha256: sha256(attachment),
      sourceIdentity: { dev: attachmentInfo.dev, ino: attachmentInfo.ino }
    }
  };
}

async function webdriverRequest(fetchImpl, url, path, init = {}) {
  const response = await fetchImpl(new URL(path, url), {
    ...init,
    headers: { 'content-type': 'application/json', ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(20_000)
  });
  const body = await response.json().catch(() => ({}));
  assert.ok(response.ok && !body.value?.error, `WebDriver ${init.method ?? 'GET'} request failed`);
  return body.value ?? body;
}

async function startDriver(target, requiredCaps, fetchImpl) {
  const capabilities = structuredClone(target.driver.capabilities);
  Object.assign(capabilities.alwaysMatch, requiredCaps);
  const value = await webdriverRequest(fetchImpl, target.driver.url, '/session', {
    method: 'POST',
    body: JSON.stringify({ capabilities })
  });
  const sessionId = value.sessionId;
  assert.ok(sessionId, 'WebDriver session ID is missing');
  for (const [key, expected] of Object.entries(requiredCaps)) {
    assert.equal(value.capabilities?.[key], expected, `WebDriver did not bind capability '${key}'`);
  }
  return { url: target.driver.url, id: sessionId, binding: requiredCaps };
}

async function stopDriver(driver, fetchImpl) {
  if (!driver) return;
  const response = await fetchImpl(new URL(`/session/${driver.id}`, driver.url), {
    method: 'DELETE',
    signal: AbortSignal.timeout(10_000)
  });
  assert.equal(response.ok, true, 'WebDriver session cleanup failed');
}

async function findElement(driver, selector, fetchImpl) {
  const value = await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element`, {
    method: 'POST',
    body: JSON.stringify(selector)
  });
  const id = value['element-6066-11e4-a52e-4f735466cecf'] ?? value.ELEMENT;
  assert.ok(id, `semantic element '${selector.value}' was not found`);
  return id;
}

async function readElementText(driver, elementId, fetchImpl) {
  return String(await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${elementId}/text`));
}

async function waitForText(driver, selector, expected, fetchImpl, timeoutMs = 20_000, sleep = ms => new Promise(resolveWait => setTimeout(resolveWait, ms))) {
  const deadline = Date.now() + timeoutMs;
  let latest = '';
  do {
    try {
      const id = await findElement(driver, selector, fetchImpl);
      latest = await readElementText(driver, id, fetchImpl);
      if (latest.includes(expected)) return latest;
    } catch {
      // The semantic element may not have reached the accessibility tree yet.
    }
    await sleep(200);
  } while (Date.now() < deadline);
  assert.fail(`semantic element '${selector.value}' did not receive its correlated marker`);
}

async function assertTextAbsentForWindow(driver, selector, forbidden, fetchImpl, stabilityMs, sleep = ms => new Promise(resolveWait => setTimeout(resolveWait, ms))) {
  const intervalMs = 200;
  const polls = Math.max(2, Math.ceil(stabilityMs / intervalMs) + 1);
  for (let poll = 0; poll < polls; poll += 1) {
    const id = await findElement(driver, selector, fetchImpl);
    const text = await readElementText(driver, id, fetchImpl);
    assert.equal(text.includes(forbidden), false, 'invalid identity appeared during the contact-state stability window');
    if (poll + 1 < polls) await sleep(intervalMs);
  }
}

export async function verifyDownloadedAttachment(path, downloadRoot, expectedSha256, fs = fsDefault, sourceIdentity) {
  assert.ok(safeUnder(downloadRoot, path), 'decrypted destination escaped the unique download root');
  assert.equal(resolve(path), join(resolve(downloadRoot), basename(path)), 'decrypted destination must be a direct child of the unique download root');
  await assertCanonicalDirectory(downloadRoot, fs);
  const info = await fs.lstat(path);
  await assertNotReparsePoint(path, info, fs, 'decrypted destination');
  assert.equal(info.isFile(), true, 'decrypted destination must be a regular file');
  assert.equal((await fs.realpath(path)).toLowerCase(), resolve(path).toLowerCase(), 'decrypted destination canonical path mismatch');
  const followedInfo = await fs.stat(path);
  if (sourceIdentity) {
    assert.equal(
      followedInfo.dev === sourceIdentity.dev && followedInfo.ino === sourceIdentity.ino,
      false,
      'decrypted destination cannot be the source referent or its hard link'
    );
  }
  const actual = sha256(await fs.readFile(path));
  assert.equal(actual, expectedSha256, 'decrypted attachment SHA-256 differs from source');
  return { name: basename(path), sha256: actual, bytes: info.size };
}

async function waitForDownloadedAttachment(fileContext, expectedSha256, dependencies, timeoutMs = 30_000) {
  const fs = dependencies.fs ?? fsDefault;
  const sleep = dependencies.sleep ?? (ms => new Promise(resolveWait => setTimeout(resolveWait, ms)));
  const deadline = Date.now() + timeoutMs;
  do {
    try {
      return await verifyDownloadedAttachment(
        fileContext.downloadPath,
        fileContext.downloadRoot,
        expectedSha256,
        fs,
        fileContext.sourceIdentity
      );
    } catch (error) {
      const retryable = error?.code === 'ENOENT' || String(error?.message).includes('SHA-256 differs');
      if (!retryable || Date.now() >= deadline) throw error;
      await sleep(200);
    }
  } while (Date.now() < deadline);
  assert.fail('decrypted attachment did not appear before timeout');
}

async function executeActions(drivers, actions, variables, evidence, dependencies, fileContext) {
  const fetchImpl = dependencies.fetch ?? fetch;
  for (const definition of actions) {
    if (definition.type === 'assertDownloadedAttachment') {
      const proof = await waitForDownloadedAttachment(
        fileContext,
        variables.attachmentSha256,
        dependencies,
        definition.timeoutMs
      );
      evidence.files.push({ ...proof, phase: definition.phase });
      continue;
    }
    const driver = drivers[definition.target];
    assert.ok(driver, `No active ${definition.target} driver`);
    const selector = {
      using: definition.selector.using,
      value: interpolate(definition.selector.value, variables)
    };
    if (definition.type === 'waitText') {
      await waitForText(
        driver,
        selector,
        interpolate(definition.contains, variables),
        fetchImpl,
        definition.timeoutMs,
        dependencies.sleep
      );
      evidence.actions.push({
        type: definition.type,
        target: definition.target,
        selectorSha256: sha256(`${selector.using}:${selector.value}`),
        purpose: definition.purpose
      });
      continue;
    }
    const id = await findElement(driver, selector, fetchImpl);
    if (definition.type === 'click') {
      await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${id}/click`, { method: 'POST', body: '{}' });
    } else if (definition.type === 'setValue') {
      await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${id}/value`, {
        method: 'POST',
        body: JSON.stringify({ text: interpolate(definition.value, variables) })
      });
    } else if (definition.type === 'assertText') {
      const text = await readElementText(driver, id, fetchImpl);
      assert.ok(text.includes(interpolate(definition.contains, variables)), `semantic rejection evidence '${selector.value}' is missing`);
    } else if (definition.type === 'assertNotTextStable') {
      await assertTextAbsentForWindow(
        driver,
        selector,
        interpolate(definition.contains, variables),
        fetchImpl,
        definition.stabilityMs,
        dependencies.sleep
      );
    } else if (definition.type === 'captureIdentity') {
      const identity = (await readElementText(driver, id, fetchImpl)).trim();
      const pattern = definition.target === 'windows' ? variables.windowsIdentityPattern : variables.androidIdentityPattern;
      assert.match(identity, new RegExp(pattern), `${definition.target} identity did not match configured format`);
      variables[definition.saveAs] = identity;
      evidence.identities.push({ target: definition.target, sha256: sha256(identity) });
    } else if (definition.type === 'captureRouteMarker') {
      const observed = (await readElementText(driver, id, fetchImpl)).trim();
      assert.ok(observed.length > 0, 'route marker is empty');
      assert.equal(observed, interpolate(definition.expected, variables), 'observed route node does not match configured route');
      variables[definition.saveAs] = observed;
      evidence.routeMarkerSha256 = sha256(observed);
    }
    evidence.actions.push({ type: definition.type, target: definition.target, selectorSha256: sha256(`${selector.using}:${selector.value}`), purpose: definition.purpose });
  }
}

function isTransientWindowsProcessError(error) {
  const message = `${error?.message ?? ''}\n${error?.stderr ?? ''}`.toLowerCase();
  return /cannot find (a )?process|process (?:was )?not found|no process with (?:the )?(?:process )?identifier|process id .* does not exist/.test(message);
}

export async function inspectWindowsProcess(command, config, process, dependencies = {}) {
  assert.ok(Number.isInteger(process?.pid) && process.pid > 0, 'Windows launch did not return a PID');
  const script = `$p=Get-CimInstance Win32_Process -Filter "ProcessId=${process.pid}";$g=Get-Process -Id ${process.pid};[pscustomobject]@{ProcessId=$p.ProcessId;Name=$p.Name;ExecutablePath=$p.ExecutablePath;MainWindowHandle=[int64]$g.MainWindowHandle}|ConvertTo-Json -Compress`;
  const startedAt = now(dependencies);
  const deadline = startedAt + config.windows.launchTimeoutMs;
  const sleep = dependencies.sleep ?? (ms => new Promise(resolveWait => setTimeout(resolveWait, ms)));
  let latestError;
  while (now(dependencies) < deadline) {
    try {
      const result = await beforeDeadline(
        remaining => command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { timeout: remaining }),
        deadline,
        'Windows process inspection',
        dependencies
      );
      const metadata = JSON.parse(String(result.stdout));
      assert.equal(Number(metadata.ProcessId), process.pid, 'Windows PID provenance mismatch');
      assert.equal(String(metadata.Name).toLowerCase(), config.windows.processName.toLowerCase(), 'Windows process name mismatch');
      assert.equal(resolve(metadata.ExecutablePath).toLowerCase(), resolve(config.windows.exePath).toLowerCase(), 'Windows executable provenance mismatch');
      if (Number(metadata.MainWindowHandle) > 0) {
        assert.ok(now(dependencies) < deadline, 'Windows process inspection completed after its deadline');
        return {
          pid: process.pid,
          handle: Number(metadata.MainWindowHandle),
          executablePathSha256: sha256(resolve(metadata.ExecutablePath).toLowerCase()),
          elapsedMs: now(dependencies) - startedAt
        };
      }
      latestError = new Error('Windows process has no top-level window yet');
    } catch (error) {
      if (!isTransientWindowsProcessError(error)) throw error;
      latestError = error;
    }
    const remaining = deadline - now(dependencies);
    if (remaining <= 0) break;
    await sleep(Math.min(config.windows.launchPollMs, remaining));
  }
  assert.fail(`Windows process did not expose a top-level window within ${config.windows.launchTimeoutMs}ms${latestError ? `: ${latestError.message}` : ''}`);
}

function sanitizedPreflight(preflightEvidence) {
  return {
    compose: preflightEvidence.compose,
    android: {
      serial: preflightEvidence.android.serial,
      packageName: preflightEvidence.android.packageName,
      installed: preflightEvidence.android.installed,
      apk: {
        packageName: preflightEvidence.android.apk.packageName,
        versionCode: preflightEvidence.android.apk.versionCode,
        versionName: preflightEvidence.android.apk.versionName,
        signingSha256: preflightEvidence.android.apk.signingSha256,
        bytes: preflightEvidence.android.apk.bytes,
        sha256: preflightEvidence.android.apk.sha256,
        path: pathFingerprint(preflightEvidence.android.apk.path)
      }
    },
    windows: {
      executable: pathFingerprint(preflightEvidence.windows.exePath),
      exeSha256: preflightEvidence.windows.exeSha256,
      bytes: preflightEvidence.windows.bytes,
      isolatedAppData: pathFingerprint(preflightEvidence.windows.isolatedAppData)
    },
    attachment: {
      source: pathFingerprint(preflightEvidence.attachment.path),
      bytes: preflightEvidence.attachment.bytes,
      sha256: preflightEvidence.attachment.sha256
    }
  };
}

async function cleanupStep(cleanup, name, action) {
  try {
    await action();
    cleanup.steps.push({ name, succeeded: true });
  } catch {
    cleanup.steps.push({ name, succeeded: false });
    cleanup.succeeded = false;
  }
}

export async function assertPathAbsent(fs, path, context) {
  try {
    await fs.access(path);
  } catch (error) {
    assert.equal(error?.code, 'ENOENT', `${context} absence check failed with ${error?.code ?? 'unknown error'}`);
    return;
  }
  assert.fail(`${context} still exists`);
}

export async function runPhysicalE2E(config, options = {}) {
  validateConfig(config);
  const artifactsDir = resolve(required(options.artifactsDir, 'artifactsDir is required'));
  const markers = createMarkers(options.runId);
  const dependencies = options.dependencies ?? {};
  const command = dependencies.command ?? defaultCommand;
  const fetchImpl = dependencies.fetch ?? fetch;
  const fs = dependencies.fs ?? fsDefault;
  const launch = dependencies.spawn ?? ((file, args, spawnOptions) => spawnProcess(file, args, spawnOptions));
  const artifactWrite = dependencies.artifactWrite ?? ((path, value) => fs.writeFile(path, value, 'utf8'));
  assert.equal(safeUnder(config.windows.appDataRoot, artifactsDir), false, 'artifactsDir cannot be inside disposable AppData');
  await fs.mkdir(artifactsDir, { recursive: true });
  const preflightEvidence = await preflight(config, dependencies, markers.runId);
  assert.equal(safeUnder(preflightEvidence.windows.isolatedAppData, artifactsDir), false, 'artifactsDir cannot be inside disposable AppData');

  const androidAttachmentPath = `${config.android.attachmentDirectory.replace(/\/$/, '')}/${markers.attachmentName}`;
  const downloadPath = join(preflightEvidence.windows.downloadRoot, markers.attachmentName);
  const variables = {
    ...markers,
    androidAttachmentPath,
    attachmentSha256: preflightEvidence.attachment.sha256,
    windowsIdentityPattern: config.windows.identityPattern,
    androidIdentityPattern: config.android.identityPattern,
    expectedRouteNode: config.chaos?.expectedRouteNode
  };
  const evidence = {
    schemaVersion: 2,
    startedAt: new Date().toISOString(),
    status: 'failed',
    markers: {
      runId: markers.runId,
      invalidIdentity: markers.invalidIdentity,
      contactMarkerWindows: markers.contactMarkerWindows,
      contactMarkerAndroid: markers.contactMarkerAndroid,
      windowsToAndroidMessage: markers.windowsToAndroidMessage,
      androidToWindowsMessage: markers.androidToWindowsMessage,
      attachmentName: markers.attachmentName
    },
    preflight: sanitizedPreflight(preflightEvidence),
    processes: [],
    flows: [],
    files: [],
    cleanup: { attempted: false, succeeded: true, steps: [] }
  };
  const drivers = { android: undefined, windows: undefined };
  let activeWindowsProcess;
  let mainError;
  let cleanupError;
  let artifactError;
  let runSucceeded = false;
  let initialPid;

  const launchWindows = async phase => {
    const isolated = preflightEvidence.windows.isolatedAppData;
    const child = launch(config.windows.exePath, config.windows.arguments ?? [], {
      detached: false,
      stdio: 'ignore',
      windowsHide: true,
      env: {
        ...process.env,
        APPDATA: join(isolated, 'Roaming'),
        LOCALAPPDATA: join(isolated, 'Local'),
        TEMP: join(isolated, 'Temp'),
        TMP: join(isolated, 'Temp')
      }
    });
    activeWindowsProcess = child;
    const provenance = await inspectWindowsProcess(command, config, child, dependencies);
    if (phase === 'restart') assert.notEqual(provenance.pid, initialPid, 'cold restart reused the original Windows PID');
    if (phase === 'initial') initialPid = provenance.pid;
    evidence.processes.push({
      phase,
      pid: provenance.pid,
      executablePathSha256: provenance.executablePathSha256,
      handleSha256: sha256(String(provenance.handle)),
      elapsedMs: provenance.elapsedMs
    });
    return provenance;
  };

  const startDrivers = async windowsProvenance => {
    const apk = preflightEvidence.android.apk;
    drivers.android = await startDriver(config.android, {
      'appium:udid': config.android.serial,
      'appium:appPackage': config.android.packageName,
      'deep:versionCode': apk.versionCode,
      'deep:versionName': apk.versionName,
      'deep:signingSha256': apk.signingSha256
    }, fetchImpl);
    const handle = `0x${windowsProvenance.handle.toString(16)}`;
    drivers.windows = await startDriver(config.windows, {
      'appium:appTopLevelWindow': handle,
      'deep:processId': windowsProvenance.pid,
      'deep:executableSha256': preflightEvidence.windows.exeSha256
    }, fetchImpl);
  };

  const stopActiveClients = async () => {
    if (drivers.android) await stopDriver(drivers.android, fetchImpl);
    drivers.android = undefined;
    if (drivers.windows) await stopDriver(drivers.windows, fetchImpl);
    drivers.windows = undefined;
    await command('adb', ['-s', config.android.serial, 'shell', 'am', 'force-stop', config.android.packageName]);
    if (activeWindowsProcess?.pid) {
      await command('taskkill', ['/pid', String(activeWindowsProcess.pid), '/t', '/f']);
      activeWindowsProcess = undefined;
    }
  };

  try {
    await command('adb', ['-s', config.android.serial, 'push', config.attachmentPath, androidAttachmentPath]);
    const initialWindows = await launchWindows('initial');
    await command('adb', ['-s', config.android.serial, 'shell', 'monkey', '-p', config.android.packageName, '1']);
    await startDrivers(initialWindows);

    for (const name of REQUIRED_FLOWS) {
      if (name === 'coldRestartVerify') {
        await stopActiveClients();
        await command('adb', ['-s', config.android.serial, 'shell', 'monkey', '-p', config.android.packageName, '1']);
        const restartedWindows = await launchWindows('restart');
        await startDrivers(restartedWindows);
      }
      const flowEvidence = { name, actions: [], files: [], identities: [] };
      await executeActions(drivers, config.flows[name], variables, flowEvidence, dependencies, {
        downloadPath,
        downloadRoot: preflightEvidence.windows.downloadRoot,
        sourceIdentity: preflightEvidence.attachment.sourceIdentity
      });
      evidence.flows.push(flowEvidence);
      evidence.files.push(...flowEvidence.files);
      if (name === 'mutualIdentity') {
        assert.ok(variables.actualIdentityWindows && variables.actualIdentityAndroid, 'both actual client identities must be captured');
        assert.notEqual(variables.actualIdentityWindows, variables.actualIdentityAndroid, 'client identities must be distinct');
      }
      if (name === 'androidToWindowsAttachment') {
        await fs.unlink(downloadPath);
        await assertPathAbsent(fs, downloadPath, 'initial decrypted download');
        evidence.files.push({ phase: 'betweenRestarts', name: markers.attachmentName, deleted: true });
      }
    }

    if (config.chaos?.enabled) {
      const routeEvidence = { name: 'routeChaos', actions: [], files: [], identities: [] };
      await executeActions(drivers, [config.chaos.routeMarker], variables, routeEvidence, dependencies, {
        downloadPath,
        downloadRoot: preflightEvidence.windows.downloadRoot,
        sourceIdentity: preflightEvidence.attachment.sourceIdentity
      });
      assert.equal(variables.observedRouteNode, config.chaos.expectedRouteNode, 'route correlation changed before chaos');
      const binding = config.chaos.routeBindings.find(item => item.routeNode === variables.observedRouteNode);
      assert.ok(binding, 'captured route node has no compose service binding');
      const endpointPin = config.compose.endpointPins.find(pin => pin.service === binding.composeService);
      assert.ok(endpointPin, 'bound compose service has no endpoint pin');
      const actions = [];
      for (const action of config.chaos.actions) {
        assert.equal(interpolate(action.routeRef, variables), variables.observedRouteNode, 'chaos action lost captured route correlation');
        await command('docker', [
          'compose',
          '-p',
          config.compose.project,
          '-f',
          config.compose.file,
          'restart',
          binding.composeService
        ]);
        const health = await waitForEndpointPin(
          endpointPin,
          fetchImpl,
          config.chaos.healthTimeoutMs,
          config.chaos.healthPollMs,
          dependencies.sleep,
          dependencies
        );
        actions.push({
          type: action.type,
          service: binding.composeService,
          routeNodeSha256: sha256(variables.observedRouteNode),
          health
        });
      }
      evidence.chaos = {
        executed: true,
        deterministicFailoverClaim: false,
        observedRouteNodeSha256: sha256(variables.observedRouteNode),
        actions
      };
    } else {
      evidence.chaos = { executed: false, deterministicFailoverClaim: false };
    }
    runSucceeded = true;
  } catch (error) {
    mainError = error;
    evidence.failure = { name: error.name, message: 'physical E2E execution failed' };
  } finally {
    evidence.cleanup.attempted = true;
    await cleanupStep(evidence.cleanup, 'android-driver', async () => {
      if (drivers.android) await stopDriver(drivers.android, fetchImpl);
      drivers.android = undefined;
    });
    await cleanupStep(evidence.cleanup, 'windows-driver', async () => {
      if (drivers.windows) await stopDriver(drivers.windows, fetchImpl);
      drivers.windows = undefined;
    });
    await cleanupStep(evidence.cleanup, 'android-force-stop', async () => {
      await command('adb', ['-s', config.android.serial, 'shell', 'am', 'force-stop', config.android.packageName]);
    });
    await cleanupStep(evidence.cleanup, 'windows-process', async () => {
      if (activeWindowsProcess?.pid) await command('taskkill', ['/pid', String(activeWindowsProcess.pid), '/t', '/f']);
      activeWindowsProcess = undefined;
    });
    await cleanupStep(evidence.cleanup, 'android-attachment', async () => {
      await command('adb', ['-s', config.android.serial, 'shell', 'rm', '-f', androidAttachmentPath]);
    });
    await cleanupStep(evidence.cleanup, 'isolated-appdata', async () => {
      assert.ok(safeUnder(config.windows.appDataRoot, preflightEvidence.windows.isolatedAppData), 'cleanup target escaped AppData root');
      await fs.rm(preflightEvidence.windows.isolatedAppData, { recursive: true, force: false });
      await assertPathAbsent(fs, preflightEvidence.windows.isolatedAppData, 'isolated AppData');
    });
    if (!evidence.cleanup.succeeded) cleanupError = new Error('physical E2E cleanup did not complete');
    evidence.status = runSucceeded && evidence.cleanup.succeeded ? 'passed' : 'failed';
    evidence.finishedAt = new Date().toISOString();
    try {
      await artifactWrite(join(artifactsDir, 'physical-deep-e2e.json'), JSON.stringify(evidence, null, 2));
    } catch (error) {
      artifactError = error;
    }
  }

  if (mainError) throw mainError;
  if (cleanupError) throw cleanupError;
  if (artifactError) throw artifactError;
  return evidence;
}
