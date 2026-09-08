import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback, spawn as spawnProcess } from 'node:child_process';
import { access, lstat, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);

export const ANDROID_SERIAL = '192.168.1.45:43337';
export const ANDROID_PACKAGE = 'network.xpoint.deep.e2e';
export const ANDROID_LAUNCH_ACTIVITY = 'network.xpoint.deep.DeepLauncher';
export const CONFIG_VERSION = 4;
export const EVIDENCE_SCHEMA_VERSION = 4;
export const DEEP_ID_PATTERN = '^deep1[023456789acdefghjklmnpqrstuvwxyz]{85}$';
export const REQUIRED_FLOWS = Object.freeze([
  'offlineAccountCreate',
  'offlineAccountRestore',
  'reciprocalContact',
  'windowsToAndroidText',
  'androidToWindowsText',
  'smallClosedGroup',
  'coldRestartVerify',
  'longOfflineRetry'
]);

const SECRET_KEY = /(?:password|secret|token|api[_-]?key|authorization|recoveryMaterial)/i;
const LEGACY_SESSION_SURFACE = /(?:SessionId|Settings\.Session|NewConversation\.Session|\^05\[)/i;
const SEMANTIC_LOCATORS = new Set(['accessibility id', 'id']);
const UI_ACTIONS = new Set([
  'waitVisible', 'setValue', 'click', 'clickText', 'waitText', 'assertExactText',
  'assertNotTextStable', 'captureIdentity', 'captureRecoveryPhrase', 'assertIdentityMatches'
]);
const SYSTEM_ACTIONS = new Set([
  'resetWindowsProfile', 'restoreServicesOnline', 'takeServicesOffline',
  'waitLongOffline', 'restartClients'
]);
const PLATFORM_SELECTOR_ROLES = Object.freeze({
  android: Object.freeze([
    'pageConversations', 'profileSettings', 'ownIdentity', 'settingsBack',
    'newConversation', 'newMessage', 'identityInput', 'aliasInput', 'identitySubmit',
    'conversationRow', 'contactPending', 'contactVerified', 'chatBack',
    'messageComposer', 'messageSend', 'messageBody', 'deliveryPending', 'deliveryDelivered',
    'groups', 'groupInviteRow', 'groupInviteAccept', 'groupStateActive',
    'groupStateRemoved', 'groupMessageComposer', 'groupMessageSend', 'groupMessageBody'
  ]),
  windows: Object.freeze([
    'welcomeDisplayName', 'welcomeCreate', 'welcomeRestore', 'welcomeRestorePhrase',
    'welcomeRestoreSubmit', 'conversationsRoot', 'networkCallbackCount',
    'profileSettings', 'ownIdentity', 'recoveryPhraseReveal', 'recoveryPhraseValue',
    'settingsBack', 'newConversation', 'newMessage', 'identityInput', 'aliasInput',
    'identitySubmit', 'conversationRow', 'contactPending', 'contactVerified',
    'messageComposer', 'messageSend', 'messageBody', 'deliveryPending',
    'deliveryDelivered', 'groups', 'groupCreate', 'groupNameInput',
    'groupMemberDeepIdInput', 'groupAddMember', 'groupSubmit', 'groupStatePending',
    'groupStateActive', 'groupRow', 'groupMessageComposer', 'groupMessageSend',
    'groupMessageBody', 'groupMembers', 'groupMemberRow', 'groupRemove',
    'groupRemoveConfirm', 'groupMemberStateRemoved'
  ])
});
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
const RECOVERY_PHRASE_PATTERN = /^[a-z]+(?: [a-z]+){23}$/;
const EVIDENCE_RECOVERY_PHRASE = /(?:^|[^a-z])(?:[a-z]+ ){23}[a-z]+(?:$|[^a-z])/;
const EVIDENCE_DIGEST = /^[0-9a-f]{64}$/;
const EXAMPLE_BUILD_SHA256S = new Set(['1', '2', '3', '4', '5'].map(value => value.repeat(64)));
const REQUIRED_EVIDENCE_PURPOSES = Object.freeze({
  offlineAccountCreate: Object.freeze([
    'offlineNoCallbackBeforeCreate', 'windowsCreateIdentity', 'offlineNoCallbackAfterCreate',
    'captureWindowsIdentity', 'captureWindowsRecoveryPhrase'
  ]),
  offlineAccountRestore: Object.freeze([
    'resetWindowsProfile', 'offlineNoCallbackBeforeRestore', 'restorePhraseEntry',
    'restoreSubmit', 'offlineNoCallbackAfterRestore', 'assertRestoredWindowsIdentity',
    'offlineServicesRestore'
  ]),
  reciprocalContact: Object.freeze([
    'captureAndroidIdentity', 'windowsImportAndroidDeepId', 'windowsContactPending',
    'androidImportWindowsDeepId', 'androidContactPending', 'windowsContactVerified',
    'androidContactVerified'
  ]),
  windowsToAndroidText: Object.freeze(['messageEntry', 'messageSend', 'messageReceive']),
  androidToWindowsText: Object.freeze(['messageEntry', 'messageSend', 'messageReceive']),
  smallClosedGroup: Object.freeze([
    'groupNameEntry', 'groupInviteDeepIdEntry', 'groupInvitePending', 'groupInviteAccept',
    'groupActiveOnAndroid', 'groupActiveOnWindows', 'groupMessageEntry',
    'groupMessageReceive', 'groupRemoveMember', 'groupMemberRemovedOnWindows',
    'groupRemovedOnAndroid', 'postRemovalMessageEntry', 'removedDeviceExcluded'
  ]),
  coldRestartVerify: Object.freeze([
    'coldRestartClients', 'coldWindowsIdentity', 'coldAndroidIdentity',
    'coldWindowsContactVerified', 'coldAndroidContactVerified', 'coldRemovedMemberState',
    'coldDirectHistoryWindows', 'coldDirectHistoryAndroid'
  ]),
  longOfflineRetry: Object.freeze([
    'longOfflineServicesStop', 'longOfflineMessageEntry', 'longOfflineMessageSend',
    'longOfflineQueued', 'longOfflineRestartClients', 'longOfflineWindow',
    'longOfflineServicesRestore', 'longOfflineDeliveryObserved', 'longOfflineDelivered'
  ])
});

const fsDefault = {
  access, isReparsePoint: isWindowsReparsePoint, lstat, mkdir, readFile, realpath, rm, writeFile
};

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function required(value, message) {
  assert.ok(value, message);
  return value;
}

function exactKeys(value, expected, context) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${context} fields must match the v4 schema exactly`);
}

function pathFingerprint(path) {
  return { basename: basename(path), pathSha256: sha256(resolve(path).toLowerCase()) };
}

function safeUnder(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel.length > 0 && !rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel);
}

function now(dependencies = {}) {
  return (dependencies.now ?? Date.now)();
}

function sleepDefault(milliseconds) {
  return new Promise(resolveWait => setTimeout(resolveWait, milliseconds));
}

export function createMarkers(runId = randomUUID()) {
  assert.match(runId, /^[A-Za-z0-9][A-Za-z0-9-]{3,79}$/, 'runId must be a safe 4-80 character identifier');
  const compact = sha256(runId).slice(0, 20);
  return {
    runId,
    bootstrapWindowsName: `deep-e2e-windows-${compact}`,
    contactMarkerWindows: `deep-e2e-contact-win-${compact}`,
    contactMarkerAndroid: `deep-e2e-contact-android-${compact}`,
    windowsToAndroidMessage: `deep-e2e W>A ${compact}`,
    androidToWindowsMessage: `deep-e2e A>W ${compact}`,
    groupName: `deep-e2e-group-${compact}`,
    groupMessage: `deep-e2e group ${compact}`,
    removedExclusionMessage: `deep-e2e removed-exclusion ${compact}`,
    longOfflineMessage: `deep-e2e long-offline ${compact}`
  };
}

export function interpolate(value, variables) {
  if (typeof value !== 'string') return value;
  return value.replace(/{{([A-Za-z][A-Za-z0-9]*)}}/g, (_, key) => {
    assert.ok(Object.hasOwn(variables, key), `Unknown physical E2E template variable '{{${key}}}'`);
    return String(variables[key]);
  });
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

function normalizeEndpointUrl(value) {
  const url = new URL(value);
  assert.ok(['http:', 'https:'].includes(url.protocol), 'endpoint pin must use HTTP(S)');
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), 'endpoint pin must target the local physical harness');
  assert.equal(url.username, '', 'endpoint pin cannot contain credentials');
  assert.equal(url.password, '', 'endpoint pin cannot contain credentials');
  assert.equal(url.search, '', 'endpoint pin cannot contain a query string');
  assert.equal(url.hash, '', 'endpoint pin cannot contain a fragment');
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, '');
  return `${url.origin}${url.pathname}`;
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

export function assertArm64WindowsExecutable(bytes) {
  const pe = Buffer.from(bytes);
  assert.ok(pe.length >= 0x40 && pe.subarray(0, 2).toString('ascii') === 'MZ', 'Windows executable is not a PE file');
  const headerOffset = pe.readUInt32LE(0x3c);
  assert.ok(pe.length >= headerOffset + 6 && pe.subarray(headerOffset, headerOffset + 4).toString('ascii') === 'PE\0\0', 'Windows executable has no PE header');
  assert.equal(pe.readUInt16LE(headerOffset + 4), 0xaa64, 'Windows executable must target ARM64 (PE machine 0xAA64)');
}

export async function isWindowsReparsePoint(path, _info, options = {}) {
  assert.ok(process.platform === 'win32' || options.command, 'Windows ReparsePoint inspection requires Windows or an injected adapter');
  assert.equal(isAbsolute(path), true, 'Windows ReparsePoint inspection requires an absolute path');
  const absolutePath = resolve(path);
  const escapedPath = absolutePath.replaceAll("'", "''");
  const script = `$ErrorActionPreference='Stop';[int][IO.File]::GetAttributes('${escapedPath}')`;
  const command = options.command ?? defaultCommand;
  const timeoutMs = options.timeoutMs ?? 10_000;
  assert.ok(Number.isInteger(timeoutMs) && timeoutMs > 0, 'Windows ReparsePoint inspection timeout must be positive');
  const result = await command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { timeout: timeoutMs });
  assert.equal(String(result.stderr ?? '').trim(), '', 'Windows ReparsePoint inspection wrote to stderr');
  const output = String(result.stdout).trim();
  assert.match(output, /^\d+$/, 'Windows ReparsePoint inspection returned invalid attributes');
  return (Number(output) & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) !== 0;
}

function validateSelector(action, name, selectors) {
  required(action.selector && typeof action.selector === 'object', `${name} needs a semantic selector`);
  exactKeys(action.selector, ['role'], `${name}.selector`);
  const role = required(action.selector.role, `${name} selector role is required`);
  required(selectors[action.target]?.[role], `${name} references missing ${action.target} selector role '${role}'`);
}

function validateAction(action, name, selectors) {
  required(action && typeof action === 'object', `${name} must be an action object`);
  required(UI_ACTIONS.has(action.type) || SYSTEM_ACTIONS.has(action.type), `${name} has unsupported action '${action.type}'`);
  required(typeof action.purpose === 'string' && /^[A-Za-z][A-Za-z0-9]{2,79}$/.test(action.purpose), `${name} needs a bounded semantic purpose`);
  if (SYSTEM_ACTIONS.has(action.type)) {
    exactKeys(action, ['target', 'type', 'purpose'], name);
    assert.equal(action.target, 'system', `${name} system action must target system`);
    return;
  }
  assert.ok(['android', 'windows'].includes(action.target), `${name} needs target android or windows`);
  const keys = ['target', 'type', 'purpose', 'selector'];
  if (Object.hasOwn(action, 'timeoutMs')) {
    keys.push('timeoutMs');
    assert.ok(Number.isInteger(action.timeoutMs) && action.timeoutMs >= 1_000 && action.timeoutMs <= 120_000, `${name} timeoutMs must be 1000-120000`);
  }
  if (action.type === 'setValue') {
    keys.push('value');
    assert.ok(typeof action.value === 'string' && action.value.length > 0 && action.value.length <= 256, `${name} setValue needs a bounded value`);
  }
  if (['clickText', 'waitText', 'assertExactText', 'assertNotTextStable'].includes(action.type)) {
    keys.push('contains');
    assert.ok(typeof action.contains === 'string' && action.contains.length > 0 && action.contains.length <= 256, `${name} ${action.type} needs bounded text`);
  }
  if (action.type === 'assertNotTextStable') {
    keys.push('stabilityMs');
    assert.ok(Number.isInteger(action.stabilityMs) && action.stabilityMs >= 1_000 && action.stabilityMs <= 60_000, `${name} stabilityMs must be 1000-60000`);
  }
  if (action.type === 'captureIdentity') {
    keys.push('saveAs');
    assert.ok(['actualIdentityWindows', 'actualIdentityAndroid'].includes(action.saveAs), `${name} has invalid identity destination`);
  }
  if (action.type === 'captureRecoveryPhrase') {
    keys.push('saveAs');
    assert.equal(action.target, 'windows', `${name} recovery phrase capture must target Windows`);
    assert.equal(action.saveAs, 'windowsRecoveryPhrase', `${name} has invalid recovery destination`);
  }
  if (action.type === 'assertIdentityMatches') {
    keys.push('matches');
    assert.ok(['{{actualIdentityWindows}}', '{{actualIdentityAndroid}}'].includes(action.matches), `${name} identity comparison must use a captured identity`);
  }
  exactKeys(action, keys, name);
  validateSelector(action, name, selectors);
}

function hasAction(actions, predicate) {
  return actions.some(predicate);
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

function requireExactState(actions, purpose, target, selectorRole, state) {
  requirePurpose(actions, purpose, action => action.target === target && action.type === 'assertExactText' && action.selector.role === selectorRole && action.contains === state);
}

export function validateConfig(config) {
  required(config && typeof config === 'object' && !Array.isArray(config), 'physical E2E config must be an object');
  exactKeys(config, ['version', 'compose', 'android', 'windows', 'limits', 'selectors', 'flows'], 'physical E2E config');
  assert.equal(config.version, CONFIG_VERSION, `physical E2E config.version must be ${CONFIG_VERSION}`);
  rejectSecrets(config);
  assert.equal(LEGACY_SESSION_SURFACE.test(JSON.stringify(config)), false, 'physical E2E config must not contain Session identity semantics');

  const compose = required(config.compose, 'compose configuration is required');
  exactKeys(compose, ['file', 'project', 'services', 'endpointPins'], 'compose');
  assert.ok(typeof compose.file === 'string' && isAbsolute(compose.file), 'compose.file must be an absolute path');
  assert.match(compose.project, /^[a-z0-9][a-z0-9_-]{2,62}$/, 'compose.project must be a safe local project name');
  assert.ok(Array.isArray(compose.services) && compose.services.length >= 1 && compose.services.length <= 16, 'compose.services must contain 1-16 services');
  assert.equal(new Set(compose.services).size, compose.services.length, 'compose.services must be unique');
  assert.ok(compose.services.every(service => /^[a-z0-9][a-z0-9_-]{1,62}$/.test(service)), 'compose.services contains an invalid service name');
  assert.equal(compose.endpointPins?.length, compose.services.length, 'every compose service needs exactly one successful endpoint pin');
  const normalizedEndpointUrls = new Set();
  for (const service of compose.services) {
    const pins = compose.endpointPins.filter(pin => pin.service === service);
    assert.equal(pins.length, 1, `compose service '${service}' needs exactly one endpoint pin`);
    const [pin] = pins;
    exactKeys(pin, ['service', 'url', 'expectedStatus', 'expectedBuildSha256'], `endpoint pin '${service}'`);
    const normalizedUrl = normalizeEndpointUrl(pin.url);
    assert.equal(normalizedEndpointUrls.has(normalizedUrl), false, `endpoint pin '${service}' reuses another service URL`);
    normalizedEndpointUrls.add(normalizedUrl);
    assert.equal(pin.expectedStatus, 200, `endpoint pin '${service}' must require HTTP 200`);
    assert.match(pin.expectedBuildSha256, EVIDENCE_DIGEST, `endpoint pin '${service}' must pin a build SHA-256`);
    assert.notEqual(pin.expectedBuildSha256, '0'.repeat(64), `endpoint pin '${service}' build SHA-256 cannot be empty`);
  }

  const android = required(config.android, 'android configuration is required');
  exactKeys(android, ['serial', 'packageName', 'launchActivity', 'apkPath', 'identityPattern', 'driver'], 'android');
  assert.equal(android.serial, ANDROID_SERIAL, `android.serial must pin ${ANDROID_SERIAL}`);
  assert.equal(android.packageName, ANDROID_PACKAGE, `android.packageName must pin ${ANDROID_PACKAGE}`);
  assert.equal(android.launchActivity, ANDROID_LAUNCH_ACTIVITY, `android.launchActivity must pin ${ANDROID_LAUNCH_ACTIVITY}`);
  assert.ok(typeof android.apkPath === 'string' && isAbsolute(android.apkPath), 'android.apkPath must be absolute');
  assert.equal(android.identityPattern, DEEP_ID_PATTERN, 'android.identityPattern must enforce one canonical permanent Deep ID');
  exactKeys(android.driver, ['url', 'capabilities'], 'android.driver');
  exactKeys(android.driver.capabilities, ['alwaysMatch'], 'android.driver.capabilities');
  exactKeys(android.driver.capabilities.alwaysMatch, ['platformName', 'appium:automationName'], 'android.driver.capabilities.alwaysMatch');
  assert.equal(android.driver.capabilities.alwaysMatch.platformName, 'Android', 'Android driver platformName must be Android');
  assert.equal(android.driver.capabilities.alwaysMatch['appium:automationName'], 'UiAutomator2', 'Android driver must use UiAutomator2');
  normalizeEndpointUrl(android.driver.url);

  const windows = required(config.windows, 'windows configuration is required');
  exactKeys(windows, ['exePath', 'processName', 'appDataRoot', 'launchTimeoutMs', 'launchPollMs', 'identityPattern', 'driver'], 'windows');
  assert.ok(typeof windows.exePath === 'string' && isAbsolute(windows.exePath), 'windows.exePath must be absolute');
  assert.match(windows.processName, /^[A-Za-z0-9_.-]+\.exe$/, 'windows.processName must be a bounded executable name');
  assert.ok(typeof windows.appDataRoot === 'string' && isAbsolute(windows.appDataRoot), 'windows.appDataRoot must be absolute');
  assert.match(basename(windows.appDataRoot), /e2e/i, 'windows.appDataRoot must be a dedicated E2E root');
  assert.ok(Number.isInteger(windows.launchTimeoutMs) && windows.launchTimeoutMs >= 1_000 && windows.launchTimeoutMs <= 60_000, 'windows.launchTimeoutMs must be 1000-60000');
  assert.ok(Number.isInteger(windows.launchPollMs) && windows.launchPollMs >= 50 && windows.launchPollMs <= 1_000, 'windows.launchPollMs must be 50-1000');
  assert.equal(windows.identityPattern, DEEP_ID_PATTERN, 'windows.identityPattern must enforce one canonical permanent Deep ID');
  exactKeys(windows.driver, ['url', 'capabilities'], 'windows.driver');
  exactKeys(windows.driver.capabilities, ['alwaysMatch'], 'windows.driver.capabilities');
  exactKeys(windows.driver.capabilities.alwaysMatch, ['platformName'], 'windows.driver.capabilities.alwaysMatch');
  assert.equal(windows.driver.capabilities.alwaysMatch.platformName, 'Windows', 'Windows driver platformName must be Windows');
  normalizeEndpointUrl(windows.driver.url);

  const limits = required(config.limits, 'limits are required');
  exactKeys(limits, ['runTimeoutMs', 'cleanupTimeoutMs', 'maxActionsPerFlow', 'maxTotalActions', 'maxEvidenceBytes', 'offlineProbeTimeoutMs', 'offlineProbePollMs', 'longOfflineMs'], 'limits');
  assert.ok(Number.isInteger(limits.runTimeoutMs) && limits.runTimeoutMs >= 60_000 && limits.runTimeoutMs <= 1_800_000, 'limits.runTimeoutMs must be 60000-1800000');
  assert.ok(Number.isInteger(limits.cleanupTimeoutMs) && limits.cleanupTimeoutMs >= 10_000 && limits.cleanupTimeoutMs <= 120_000, 'limits.cleanupTimeoutMs must be 10000-120000');
  assert.ok(Number.isInteger(limits.maxActionsPerFlow) && limits.maxActionsPerFlow >= 8 && limits.maxActionsPerFlow <= 64, 'limits.maxActionsPerFlow must be 8-64');
  assert.ok(Number.isInteger(limits.maxTotalActions) && limits.maxTotalActions >= 64 && limits.maxTotalActions <= 256, 'limits.maxTotalActions must be 64-256');
  assert.ok(Number.isInteger(limits.maxEvidenceBytes) && limits.maxEvidenceBytes >= 16_384 && limits.maxEvidenceBytes <= 262_144, 'limits.maxEvidenceBytes must be 16384-262144');
  assert.ok(Number.isInteger(limits.offlineProbeTimeoutMs) && limits.offlineProbeTimeoutMs >= 1_000 && limits.offlineProbeTimeoutMs <= 60_000, 'limits.offlineProbeTimeoutMs must be 1000-60000');
  assert.ok(Number.isInteger(limits.offlineProbePollMs) && limits.offlineProbePollMs >= 100 && limits.offlineProbePollMs <= 5_000, 'limits.offlineProbePollMs must be 100-5000');
  assert.ok(Number.isInteger(limits.longOfflineMs) && limits.longOfflineMs >= 30_000 && limits.longOfflineMs <= 600_000, 'limits.longOfflineMs must be 30000-600000');

  const selectors = required(config.selectors, 'platform selector maps are required');
  exactKeys(selectors, ['android', 'windows'], 'selectors');
  for (const platform of ['android', 'windows']) {
    const map = required(selectors[platform], `${platform} selector map is required`);
    assert.deepEqual(Object.keys(map).sort(), [...PLATFORM_SELECTOR_ROLES[platform]].sort(), `${platform} selector roles must match the v4 schema exactly`);
    for (const [role, selector] of Object.entries(map)) {
      assert.match(role, /^[A-Za-z][A-Za-z0-9]*$/, `${platform} selector role is invalid`);
      required(selector && typeof selector === 'object', `${platform}.${role} selector is invalid`);
      exactKeys(selector, ['using', 'value'], `${platform}.${role}`);
      required(SEMANTIC_LOCATORS.has(selector.using), `${platform}.${role} must use accessibility id or id`);
      assert.ok(typeof selector.value === 'string' && selector.value.length > 0 && selector.value.length <= 160, `${platform}.${role} selector value is required and bounded`);
    }
  }

  const flows = required(config.flows, 'flows are required');
  assert.deepEqual(Object.keys(flows).sort(), [...REQUIRED_FLOWS].sort(), 'physical E2E flows must match the v4 schema exactly');
  let totalActions = 0;
  for (const flow of REQUIRED_FLOWS) {
    assert.ok(Array.isArray(flows[flow]) && flows[flow].length > 0, `required flow '${flow}' is missing`);
    assert.ok(flows[flow].length <= limits.maxActionsPerFlow, `${flow} exceeds limits.maxActionsPerFlow`);
    flows[flow].forEach((action, index) => validateAction(action, `flows.${flow}[${index}]`, selectors));
    const purposes = flows[flow].map(action => action.purpose);
    assert.equal(new Set(purposes).size, purposes.length, `${flow} action purposes must be unique`);
    totalActions += flows[flow].length;
  }
  assert.ok(totalActions <= limits.maxTotalActions, 'physical E2E flows exceed limits.maxTotalActions');

  const create = flows.offlineAccountCreate;
  requireExactState(create, 'offlineNoCallbackBeforeCreate', 'windows', 'networkCallbackCount', '0');
  requirePurpose(create, 'windowsDisplayName', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{bootstrapWindowsName}}');
  requirePurpose(create, 'windowsCreateIdentity', action => action.target === 'windows' && action.type === 'click');
  requirePurpose(create, 'windowsConversationsReady', action => action.target === 'windows' && action.type === 'waitVisible');
  requireExactState(create, 'offlineNoCallbackAfterCreate', 'windows', 'networkCallbackCount', '0');
  requirePurpose(create, 'captureWindowsIdentity', action => action.type === 'captureIdentity' && action.saveAs === 'actualIdentityWindows');
  requirePurpose(create, 'captureWindowsRecoveryPhrase', action => action.type === 'captureRecoveryPhrase' && action.saveAs === 'windowsRecoveryPhrase');
  requireOrderedPurposes('offlineAccountCreate', create, [
    'offlineNoCallbackBeforeCreate', 'windowsDisplayName', 'windowsCreateIdentity',
    'windowsConversationsReady', 'offlineNoCallbackAfterCreate', 'captureWindowsIdentity',
    'captureWindowsRecoveryPhrase'
  ]);

  const restore = flows.offlineAccountRestore;
  requirePurpose(restore, 'resetWindowsProfile', action => action.type === 'resetWindowsProfile');
  requireExactState(restore, 'offlineNoCallbackBeforeRestore', 'windows', 'networkCallbackCount', '0');
  requirePurpose(restore, 'restorePhraseEntry', action => action.type === 'setValue' && action.value === '{{windowsRecoveryPhrase}}');
  requirePurpose(restore, 'restoreSubmit', action => action.type === 'click');
  requirePurpose(restore, 'restoreConversationsReady', action => action.type === 'waitVisible');
  requireExactState(restore, 'offlineNoCallbackAfterRestore', 'windows', 'networkCallbackCount', '0');
  requirePurpose(restore, 'assertRestoredWindowsIdentity', action => action.type === 'assertIdentityMatches' && action.matches === '{{actualIdentityWindows}}');
  requirePurpose(restore, 'offlineServicesRestore', action => action.type === 'restoreServicesOnline');
  requireOrderedPurposes('offlineAccountRestore', restore, [
    'resetWindowsProfile', 'offlineNoCallbackBeforeRestore', 'restorePhraseEntry',
    'restoreSubmit', 'restoreConversationsReady', 'offlineNoCallbackAfterRestore',
    'assertRestoredWindowsIdentity', 'offlineServicesRestore'
  ]);

  const contact = flows.reciprocalContact;
  requirePurpose(contact, 'captureAndroidIdentity', action => action.type === 'captureIdentity' && action.saveAs === 'actualIdentityAndroid');
  requirePurpose(contact, 'windowsImportAndroidDeepId', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{actualIdentityAndroid}}');
  requireExactState(contact, 'windowsContactPending', 'windows', 'contactPending', 'Pending');
  requirePurpose(contact, 'androidImportWindowsDeepId', action => action.target === 'android' && action.type === 'setValue' && action.value === '{{actualIdentityWindows}}');
  requireExactState(contact, 'androidContactPending', 'android', 'contactPending', 'Pending');
  requireExactState(contact, 'windowsContactVerified', 'windows', 'contactVerified', 'Verified');
  requireExactState(contact, 'androidContactVerified', 'android', 'contactVerified', 'Verified');
  requireOrderedPurposes('reciprocalContact', contact, [
    'captureAndroidIdentity', 'windowsImportAndroidDeepId', 'windowsContactPending',
    'androidImportWindowsDeepId', 'androidContactPending', 'windowsContactVerified',
    'androidContactVerified'
  ]);

  for (const [flow, sender, receiver, marker] of [
    ['windowsToAndroidText', 'windows', 'android', '{{windowsToAndroidMessage}}'],
    ['androidToWindowsText', 'android', 'windows', '{{androidToWindowsMessage}}']
  ]) {
    requirePurpose(flows[flow], 'messageEntry', action => action.target === sender && action.type === 'setValue' && action.value === marker);
    requirePurpose(flows[flow], 'messageSend', action => action.target === sender && action.type === 'click');
    requirePurpose(flows[flow], 'messageReceive', action => action.target === receiver && action.type === 'waitText' && action.contains === marker);
    requireOrderedPurposes(flow, flows[flow], ['messageEntry', 'messageSend', 'messageReceive']);
  }

  const group = flows.smallClosedGroup;
  requirePurpose(group, 'groupNameEntry', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{groupName}}');
  requirePurpose(group, 'groupInviteDeepIdEntry', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{actualIdentityAndroid}}');
  requireExactState(group, 'groupInvitePending', 'windows', 'groupStatePending', 'Pending');
  requirePurpose(group, 'groupInviteAccept', action => action.target === 'android' && action.type === 'click');
  requireExactState(group, 'groupActiveOnAndroid', 'android', 'groupStateActive', 'Active');
  requireExactState(group, 'groupActiveOnWindows', 'windows', 'groupStateActive', 'Active');
  requirePurpose(group, 'groupMessageEntry', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{groupMessage}}');
  requirePurpose(group, 'groupMessageReceive', action => action.target === 'android' && action.type === 'waitText' && action.contains === '{{groupMessage}}');
  requirePurpose(group, 'groupRemoveMember', action => action.target === 'windows' && action.type === 'click');
  requireExactState(group, 'groupMemberRemovedOnWindows', 'windows', 'groupMemberStateRemoved', 'Removed');
  requireExactState(group, 'groupRemovedOnAndroid', 'android', 'groupStateRemoved', 'Removed');
  requirePurpose(group, 'postRemovalMessageEntry', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{removedExclusionMessage}}');
  requirePurpose(group, 'removedDeviceExcluded', action => action.target === 'android' && action.type === 'assertNotTextStable' && action.contains === '{{removedExclusionMessage}}');
  requireOrderedPurposes('smallClosedGroup', group, [
    'groupNameEntry', 'groupInviteDeepIdEntry', 'groupInvitePending', 'groupInviteAccept',
    'groupActiveOnAndroid', 'groupActiveOnWindows', 'groupMessageEntry',
    'groupMessageReceive', 'groupRemoveMember', 'groupMemberRemovedOnWindows',
    'groupRemovedOnAndroid', 'postRemovalMessageEntry', 'removedDeviceExcluded'
  ]);

  const restart = flows.coldRestartVerify;
  requirePurpose(restart, 'coldRestartClients', action => action.type === 'restartClients');
  requirePurpose(restart, 'coldWindowsIdentity', action => action.target === 'windows' && action.type === 'assertIdentityMatches' && action.matches === '{{actualIdentityWindows}}');
  requirePurpose(restart, 'coldAndroidIdentity', action => action.target === 'android' && action.type === 'assertIdentityMatches' && action.matches === '{{actualIdentityAndroid}}');
  requireExactState(restart, 'coldWindowsContactVerified', 'windows', 'contactVerified', 'Verified');
  requireExactState(restart, 'coldAndroidContactVerified', 'android', 'contactVerified', 'Verified');
  requireExactState(restart, 'coldRemovedMemberState', 'windows', 'groupMemberStateRemoved', 'Removed');
  requirePurpose(restart, 'coldDirectHistoryWindows', action => action.target === 'windows' && action.type === 'waitText' && action.contains === '{{androidToWindowsMessage}}');
  requirePurpose(restart, 'coldDirectHistoryAndroid', action => action.target === 'android' && action.type === 'waitText' && action.contains === '{{windowsToAndroidMessage}}');
  requireOrderedPurposes('coldRestartVerify', restart, [
    'coldRestartClients', 'coldWindowsIdentity', 'coldAndroidIdentity',
    'coldWindowsContactVerified', 'coldAndroidContactVerified', 'coldRemovedMemberState',
    'coldDirectHistoryWindows', 'coldDirectHistoryAndroid'
  ]);

  const offline = flows.longOfflineRetry;
  requirePurpose(offline, 'longOfflineServicesStop', action => action.type === 'takeServicesOffline');
  requirePurpose(offline, 'longOfflineMessageEntry', action => action.target === 'windows' && action.type === 'setValue' && action.value === '{{longOfflineMessage}}');
  requirePurpose(offline, 'longOfflineMessageSend', action => action.target === 'windows' && action.type === 'click');
  requireExactState(offline, 'longOfflineQueued', 'windows', 'deliveryPending', 'Queued');
  requirePurpose(offline, 'longOfflineRestartClients', action => action.type === 'restartClients');
  requirePurpose(offline, 'longOfflineWindow', action => action.type === 'waitLongOffline');
  requirePurpose(offline, 'longOfflineServicesRestore', action => action.type === 'restoreServicesOnline');
  requirePurpose(offline, 'longOfflineDeliveryObserved', action => action.target === 'android' && action.type === 'waitText' && action.contains === '{{longOfflineMessage}}');
  requireExactState(offline, 'longOfflineDelivered', 'windows', 'deliveryDelivered', 'Delivered');
  assert.equal(hasAction(offline, action => /retry/i.test(action.selector?.role ?? '')), false, 'long-offline retry must not use a manual retry selector');
  requireOrderedPurposes('longOfflineRetry', offline, [
    'longOfflineServicesStop', 'longOfflineMessageEntry', 'longOfflineMessageSend',
    'longOfflineQueued', 'longOfflineRestartClients', 'longOfflineWindow',
    'longOfflineServicesRestore', 'longOfflineDeliveryObserved', 'longOfflineDelivered'
  ]);
  return config;
}

async function defaultCommand(command, args, options = {}) {
  const result = await execFile(command, args, { windowsHide: true, maxBuffer: 16 * 1024 * 1024, ...options });
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
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
    assert.ok(now(dependencies) <= deadline, `${label} completed after its deadline`);
    return result;
  } finally {
    clearTimeout(timer);
  }
}

export async function endpointProbe(pin, fetchImpl, deadline, dependencies = {}) {
  const startedAt = now(dependencies);
  const effectiveDeadline = deadline ?? startedAt + 10_000;
  const response = await beforeDeadline(
    remaining => fetchImpl(pin.url, { redirect: 'error', signal: AbortSignal.timeout(Math.max(1, remaining)) }),
    effectiveDeadline,
    `Endpoint pin ${pin.service} fetch`,
    dependencies
  );
  assert.equal(response.status, 200, `Endpoint pin ${pin.service} did not return HTTP 200`);
  const body = await beforeDeadline(() => response.json(), effectiveDeadline, `Endpoint pin ${pin.service} body`, dependencies)
    .catch(error => {
      if (String(error?.message).includes('deadline')) throw error;
      assert.fail(`Endpoint pin ${pin.service} response must be JSON`);
    });
  assert.ok(body && typeof body === 'object' && !Array.isArray(body), `Endpoint pin ${pin.service} response must be a JSON object`);
  assert.equal(body.service, pin.service, `Endpoint pin ${pin.service} response service provenance mismatch`);
  assert.equal(body.buildSha256, pin.expectedBuildSha256, `Endpoint pin ${pin.service} response build provenance mismatch`);
  return {
    service: pin.service,
    status: response.status,
    buildSha256: body.buildSha256,
    urlSha256: sha256(normalizeEndpointUrl(pin.url)),
    bodySha256: sha256(JSON.stringify(body)),
    elapsedMs: now(dependencies) - startedAt
  };
}

export async function waitForEndpointPin(pin, fetchImpl, timeoutMs, pollMs, sleep = sleepDefault, dependencies = {}) {
  const startedAt = now(dependencies);
  const deadline = startedAt + timeoutMs;
  let latestError;
  while (now(dependencies) < deadline) {
    try {
      return { ...(await endpointProbe(pin, fetchImpl, deadline, dependencies)), elapsedMs: now(dependencies) - startedAt };
    } catch (error) {
      latestError = error;
      const remaining = deadline - now(dependencies);
      if (remaining <= 0) break;
      await sleep(Math.min(pollMs, remaining));
    }
  }
  throw latestError ?? new Error(`Endpoint pin ${pin.service} exceeded its deadline`);
}

export async function waitForEndpointUnavailable(pin, fetchImpl, timeoutMs, pollMs, sleep = sleepDefault, dependencies = {}) {
  const startedAt = now(dependencies);
  const deadline = startedAt + timeoutMs;
  while (now(dependencies) < deadline) {
    try {
      await beforeDeadline(
        remaining => fetchImpl(pin.url, { redirect: 'error', signal: AbortSignal.timeout(Math.max(1, remaining)) }),
        deadline,
        `Offline endpoint ${pin.service}`,
        dependencies
      );
    } catch {
      return { service: pin.service, urlSha256: sha256(normalizeEndpointUrl(pin.url)), unavailable: true, elapsedMs: now(dependencies) - startedAt };
    }
    const remaining = deadline - now(dependencies);
    if (remaining <= 0) break;
    await sleep(Math.min(pollMs, remaining));
  }
  assert.fail(`Endpoint pin ${pin.service} remained reachable during the offline gate`);
}

function parseAaptBadging(stdout) {
  const match = String(stdout).match(/package:\s+name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']+)'/);
  assert.ok(match, 'aapt badging lacks package/version metadata');
  return { packageName: match[1], versionCode: match[2], versionName: match[3] };
}

function parseSigner(stdout) {
  const digest = String(stdout).match(/certificate SHA-256 digest:\s*([0-9a-f:]{64,95})/i)?.[1]?.replaceAll(':', '').toLowerCase();
  assert.match(digest ?? '', EVIDENCE_DIGEST, 'APK signer SHA-256 is missing');
  return digest;
}

function parseInstalledPackage(stdout) {
  const text = String(stdout);
  const versionName = text.match(/versionName=([^\s]+)/)?.[1];
  const versionCode = text.match(/versionCode=(\d+)/)?.[1];
  const signatureHex = text.match(/signatures[=:]\s*\[([0-9a-f]+)\]/i)?.[1];
  assert.ok(versionName && versionCode && signatureHex, 'installed dumpsys metadata lacks version or signing identity');
  return { versionName, versionCode, signingSha256: sha256(Buffer.from(signatureHex, 'hex')) };
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
  for (const pin of config.compose.endpointPins) {
    assert.equal(EXAMPLE_BUILD_SHA256S.has(pin.expectedBuildSha256), false, `endpoint pin '${pin.service}' still uses the checked-in example build SHA-256`);
  }
  await fs.access(config.compose.file);
  const composeResult = await command('docker', ['compose', '-p', config.compose.project, '-f', config.compose.file, 'ps', '--format', 'json']);
  const containers = parseComposePs(composeResult.stdout);
  for (const service of config.compose.services) {
    const matching = containers.filter(item => item.Service === service);
    assert.equal(matching.length, 1, `Compose service '${service}' must resolve to exactly one container`);
    assert.equal(String(matching[0].State).toLowerCase(), 'running', `Compose service '${service}' is not running`);
    assert.equal(String(matching[0].Health).toLowerCase(), 'healthy', `Compose service '${service}' is not healthy`);
  }
  const endpoints = await Promise.all(config.compose.endpointPins.map(pin => endpointProbe(pin, fetchImpl, undefined, dependencies)));

  const adbState = await command('adb', ['-s', config.android.serial, 'get-state']);
  assert.equal(String(adbState.stdout).trim(), 'device', `ADB serial ${config.android.serial} is not authorized`);
  const installedPathResult = await command('adb', ['-s', config.android.serial, 'shell', 'pm', 'path', config.android.packageName]);
  const installedPath = String(installedPathResult.stdout).match(/^package:(.+base\.apk)$/m)?.[1];
  assert.ok(installedPath, `Android package ${config.android.packageName} base APK is not installed`);
  const installedDump = await command('adb', ['-s', config.android.serial, 'shell', 'dumpsys', 'package', config.android.packageName]);
  const installed = parseInstalledPackage(installedDump.stdout);
  const resolvedActivity = String((await command('adb', [
    '-s', config.android.serial, 'shell', 'cmd', 'package', 'resolve-activity', '--brief', config.android.packageName
  ])).stdout).trim();
  assert.equal(resolvedActivity, `${config.android.packageName}/${config.android.launchActivity}`, 'installed Android launcher activity mismatch');

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
  const appDataParent = resolve(config.windows.appDataRoot);
  await fs.mkdir(appDataParent, { recursive: true });
  await assertCanonicalDirectory(appDataParent, fs);
  const runAppData = join(appDataParent, `physical-e2e-${runId}`);
  assert.ok(safeUnder(appDataParent, runAppData), 'unique AppData escaped configured root');
  assert.equal(resolve(runAppData), join(appDataParent, basename(runAppData)), 'unique AppData must be a direct child of configured root');
  let appDataCreated = false;
  try {
    await fs.mkdir(runAppData, { recursive: false });
    appDataCreated = true;
    await assertCanonicalDirectory(runAppData, fs);
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
      launchActivity: config.android.launchActivity,
      installedPath,
      installed,
      apk: { ...badging, signingSha256, bytes: apkBytes.length, sha256: sha256(apkBytes), path: config.android.apkPath }
    },
    windows: { exePath: config.windows.exePath, exeSha256: sha256(windowsBytes), bytes: windowsBytes.length, isolatedAppData: runAppData }
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
    method: 'POST', body: JSON.stringify({ capabilities })
  });
  assert.ok(value.sessionId, 'WebDriver session ID is missing');
  for (const [key, expected] of Object.entries(requiredCaps)) {
    assert.equal(value.capabilities?.[key], expected, `WebDriver did not bind capability '${key}'`);
  }
  return { url: target.driver.url, id: value.sessionId };
}

async function stopDriver(driver, fetchImpl) {
  if (!driver) return;
  const response = await fetchImpl(new URL(`/session/${driver.id}`, driver.url), { method: 'DELETE', signal: AbortSignal.timeout(10_000) });
  assert.equal(response.ok, true, 'WebDriver session cleanup failed');
}

async function findElements(driver, selector, fetchImpl) {
  const values = await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/elements`, {
    method: 'POST', body: JSON.stringify(selector)
  });
  assert.ok(Array.isArray(values), `semantic elements '${selector.value}' returned an invalid collection`);
  const ids = values.map(value => value['element-6066-11e4-a52e-4f735466cecf'] ?? value.ELEMENT).filter(Boolean);
  const visible = [];
  for (const id of ids) {
    if (await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${id}/displayed`) === true) visible.push(id);
  }
  return visible;
}

async function readElementText(driver, elementId, fetchImpl) {
  return String(await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${elementId}/text`));
}

async function waitForExactlyOneElement(driver, selector, fetchImpl, timeoutMs, dependencies) {
  const deadline = now(dependencies) + (timeoutMs ?? 20_000);
  let latestCount = 0;
  do {
    const ids = await findElements(driver, selector, fetchImpl).catch(() => []);
    latestCount = ids.length;
    if (ids.length === 1) return ids[0];
    assert.ok(ids.length <= 1, `semantic selector '${selector.value}' is ambiguous (${ids.length} visible elements)`);
    await (dependencies.sleep ?? sleepDefault)(200);
  } while (now(dependencies) < deadline);
  assert.fail(`semantic selector '${selector.value}' did not resolve to one visible element (last count ${latestCount})`);
}

async function waitForElementContainingText(driver, selector, expected, fetchImpl, timeoutMs, dependencies) {
  const deadline = now(dependencies) + (timeoutMs ?? 20_000);
  do {
    const ids = await findElements(driver, selector, fetchImpl);
    const matches = [];
    for (const id of ids) {
      if ((await readElementText(driver, id, fetchImpl)).includes(expected)) matches.push(id);
    }
    assert.ok(matches.length <= 1, `semantic selector '${selector.value}' produced duplicate correlated markers`);
    if (matches.length === 1) return matches[0];
    await (dependencies.sleep ?? sleepDefault)(200);
  } while (now(dependencies) < deadline);
  assert.fail(`semantic selector '${selector.value}' did not expose one element containing its correlated marker`);
}

async function assertTextAbsentForWindow(driver, selector, forbidden, fetchImpl, stabilityMs, dependencies) {
  const intervalMs = 200;
  const deadline = now(dependencies) + stabilityMs;
  let polls = 0;
  do {
    const ids = await findElements(driver, selector, fetchImpl);
    for (const id of ids) {
      assert.equal((await readElementText(driver, id, fetchImpl)).includes(forbidden), false, 'excluded content appeared during the stability window');
    }
    polls += 1;
    if (now(dependencies) < deadline) await (dependencies.sleep ?? sleepDefault)(Math.min(intervalMs, deadline - now(dependencies)));
  } while (now(dependencies) < deadline || polls < 2);
}

function resolveSelector(config, definition, variables) {
  const selected = config.selectors[definition.target][definition.selector.role];
  return { using: selected.using, value: interpolate(selected.value, variables) };
}

async function executeActions(drivers, actions, variables, evidence, dependencies, config, systemActions, runDeadline) {
  const fetchImpl = dependencies.fetch ?? fetch;
  for (const definition of actions) {
    const actionStarted = now(dependencies);
    await beforeDeadline(async () => {
      if (SYSTEM_ACTIONS.has(definition.type)) {
        const action = systemActions[definition.type];
        assert.equal(typeof action, 'function', `System action '${definition.type}' is unavailable`);
        await action(definition);
        return;
      }
      const driver = required(drivers[definition.target], `No active ${definition.target} driver`);
      const selector = resolveSelector(config, definition, variables);
      if (definition.type === 'waitVisible') {
        await waitForExactlyOneElement(driver, selector, fetchImpl, definition.timeoutMs, dependencies);
        return;
      }
      if (definition.type === 'waitText') {
        await waitForElementContainingText(driver, selector, interpolate(definition.contains, variables), fetchImpl, definition.timeoutMs, dependencies);
        return;
      }
      if (definition.type === 'assertNotTextStable') {
        await assertTextAbsentForWindow(driver, selector, interpolate(definition.contains, variables), fetchImpl, definition.stabilityMs, dependencies);
        return;
      }
      const id = definition.type === 'clickText'
        ? await waitForElementContainingText(driver, selector, interpolate(definition.contains, variables), fetchImpl, definition.timeoutMs, dependencies)
        : await waitForExactlyOneElement(driver, selector, fetchImpl, definition.timeoutMs, dependencies);
      if (definition.type === 'click' || definition.type === 'clickText') {
        await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${id}/click`, { method: 'POST', body: '{}' });
      } else if (definition.type === 'setValue') {
        await webdriverRequest(fetchImpl, driver.url, `/session/${driver.id}/element/${id}/value`, {
          method: 'POST', body: JSON.stringify({ text: interpolate(definition.value, variables) })
        });
      } else if (definition.type === 'assertExactText') {
        assert.equal((await readElementText(driver, id, fetchImpl)).trim(), interpolate(definition.contains, variables), `${definition.purpose} state mismatch`);
      } else if (definition.type === 'captureIdentity') {
        const identity = (await readElementText(driver, id, fetchImpl)).trim();
        assert.match(identity, new RegExp(DEEP_ID_PATTERN), `${definition.target} identity is not a canonical Deep ID`);
        variables[definition.saveAs] = identity;
        evidence.identityProofs.push({ target: definition.target, deepIdSha256: sha256(identity) });
      } else if (definition.type === 'captureRecoveryPhrase') {
        const phrase = (await readElementText(driver, id, fetchImpl)).trim();
        assert.ok(phrase.length <= 256 && RECOVERY_PHRASE_PATTERN.test(phrase), 'Windows recovery phrase must contain exactly 24 lowercase words');
        variables[definition.saveAs] = phrase;
      } else if (definition.type === 'assertIdentityMatches') {
        const identity = (await readElementText(driver, id, fetchImpl)).trim();
        assert.match(identity, new RegExp(DEEP_ID_PATTERN), `${definition.target} identity is not a canonical Deep ID`);
        assert.equal(identity, interpolate(definition.matches, variables), `${definition.target} restored identity changed`);
        evidence.identityProofs.push({ target: definition.target, deepIdSha256: sha256(identity) });
      }
    }, runDeadline, `${evidence.name}.${definition.purpose}`, dependencies);
    const actionEvidence = {
      type: definition.type,
      target: definition.target,
      purpose: definition.purpose,
      elapsedMs: now(dependencies) - actionStarted
    };
    if (definition.selector) {
      const selector = resolveSelector(config, definition, variables);
      actionEvidence.selectorSha256 = sha256(`${selector.using}:${selector.value}`);
    }
    evidence.actions.push(actionEvidence);
  }
}

function isTransientWindowsProcessError(error) {
  const text = String(error?.stderr ?? error?.message ?? error);
  return /cannot find a process|no process|main window|not ready/i.test(text);
}

export async function inspectWindowsProcess(command, config, process, dependencies = {}) {
  assert.ok(Number.isInteger(process?.pid) && process.pid > 0, 'spawned Windows process has no PID');
  const startedAt = now(dependencies);
  const deadline = startedAt + config.windows.launchTimeoutMs;
  const sleep = dependencies.sleep ?? sleepDefault;
  let latestError;
  while (now(dependencies) < deadline) {
    const script = `$ErrorActionPreference='Stop';$p=Get-CimInstance Win32_Process -Filter \"ProcessId=${process.pid}\";if($null -eq $p){throw 'process not ready'};$g=Get-Process -Id ${process.pid};[pscustomobject]@{ProcessId=$p.ProcessId;Name=$p.Name;ExecutablePath=$p.ExecutablePath;MainWindowHandle=$g.MainWindowHandle}|ConvertTo-Json -Compress`;
    try {
      const result = await beforeDeadline(
        remaining => command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { timeout: remaining }),
        deadline,
        'Windows process inspection',
        dependencies
      );
      assert.equal(String(result.stderr ?? '').trim(), '', 'Windows process inspection wrote to stderr');
      const metadata = JSON.parse(String(result.stdout));
      if (!metadata?.ProcessId || !metadata?.ExecutablePath || Number(metadata.MainWindowHandle) <= 0) throw new Error('Windows main window not ready');
      assert.equal(Number(metadata.ProcessId), process.pid, 'Windows PID provenance mismatch');
      assert.equal(String(metadata.Name).toLowerCase(), config.windows.processName.toLowerCase(), 'Windows process name mismatch');
      assert.equal(resolve(metadata.ExecutablePath).toLowerCase(), resolve(config.windows.exePath).toLowerCase(), 'Windows executable path mismatch');
      return {
        pid: process.pid,
        handle: Number(metadata.MainWindowHandle),
        executablePathSha256: sha256(resolve(metadata.ExecutablePath).toLowerCase()),
        elapsedMs: now(dependencies) - startedAt
      };
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

function sanitizedPreflight(value) {
  return {
    compose: value.compose,
    android: {
      serial: value.android.serial,
      packageName: value.android.packageName,
      launchActivity: value.android.launchActivity,
      installed: value.android.installed,
      apk: {
        packageName: value.android.apk.packageName,
        versionCode: value.android.apk.versionCode,
        versionName: value.android.apk.versionName,
        signingSha256: value.android.apk.signingSha256,
        bytes: value.android.apk.bytes,
        sha256: value.android.apk.sha256,
        path: pathFingerprint(value.android.apk.path)
      }
    },
    windows: {
      executable: pathFingerprint(value.windows.exePath),
      exeSha256: value.windows.exeSha256,
      bytes: value.windows.bytes,
      isolatedAppData: pathFingerprint(value.windows.isolatedAppData)
    }
  };
}

async function cleanupStep(cleanup, name, action, deadline, dependencies) {
  try {
    await beforeDeadline(() => action(), deadline, `Cleanup ${name}`, dependencies);
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

function evidenceCorrelations(markers) {
  return Object.fromEntries(Object.entries(markers)
    .filter(([key]) => key !== 'runId')
    .map(([key, value]) => [key, sha256(value)]));
}

function visitStrings(value, visitor) {
  if (typeof value === 'string') {
    visitor(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(item => visitStrings(item, visitor));
    return;
  }
  if (value && typeof value === 'object') Object.values(value).forEach(item => visitStrings(item, visitor));
}

export function validateEvidence(evidence, maxEvidenceBytes) {
  visitStrings(evidence, value => {
    assert.equal(/deep1[023456789acdefghjklmnpqrstuvwxyz]{85}/.test(value), false, 'physical evidence contains a plaintext Deep ID');
    assert.equal(EVIDENCE_RECOVERY_PHRASE.test(value), false, 'physical evidence contains recovery material');
  });
  const topLevelFields = ['schemaVersion', 'contract', 'startedAt', 'finishedAt', 'status', 'releaseEligible', 'provenance', 'correlations', 'processes', 'networkPeriods', 'flows', 'cleanup'];
  if (Object.hasOwn(evidence, 'failure')) topLevelFields.push('failure');
  exactKeys(evidence, topLevelFields, 'physical evidence');
  exactKeys(evidence.provenance, ['mode', 'preflight'], 'physical evidence provenance');
  const preflight = evidence.provenance.preflight;
  exactKeys(preflight, ['compose', 'android', 'windows'], 'physical evidence preflight');
  exactKeys(preflight.compose, ['services', 'endpoints'], 'physical evidence compose provenance');
  assert.ok(Array.isArray(preflight.compose.services) && preflight.compose.services.length >= 1 && preflight.compose.services.length <= 16, 'physical evidence service provenance is unbounded');
  assert.equal(new Set(preflight.compose.services).size, preflight.compose.services.length, 'physical evidence service provenance is duplicated');
  assert.equal(preflight.compose.endpoints.length, preflight.compose.services.length, 'physical evidence endpoint provenance is incomplete');
  const endpointServices = preflight.compose.endpoints.map(endpoint => endpoint.service);
  assert.deepEqual(endpointServices, preflight.compose.services, 'physical evidence endpoint provenance is reordered or duplicated');
  for (const endpoint of preflight.compose.endpoints) {
    exactKeys(endpoint, ['service', 'status', 'buildSha256', 'urlSha256', 'bodySha256', 'elapsedMs'], 'physical evidence endpoint provenance');
    assert.ok(preflight.compose.services.includes(endpoint.service), 'physical evidence endpoint service is unbound');
    assert.equal(endpoint.status, 200, 'physical evidence endpoint status is not 200');
    assert.match(endpoint.buildSha256, EVIDENCE_DIGEST, 'physical evidence endpoint build digest is invalid');
    assert.match(endpoint.urlSha256, EVIDENCE_DIGEST, 'physical evidence endpoint URL digest is invalid');
    assert.match(endpoint.bodySha256, EVIDENCE_DIGEST, 'physical evidence endpoint body digest is invalid');
  }
  exactKeys(preflight.android, ['serial', 'packageName', 'launchActivity', 'installed', 'apk'], 'physical evidence Android provenance');
  assert.equal(preflight.android.serial, ANDROID_SERIAL, 'physical evidence Android serial provenance mismatch');
  assert.equal(preflight.android.packageName, ANDROID_PACKAGE, 'physical evidence Android package provenance mismatch');
  assert.equal(preflight.android.launchActivity, ANDROID_LAUNCH_ACTIVITY, 'physical evidence Android launcher provenance mismatch');
  exactKeys(preflight.android.installed, ['versionName', 'versionCode', 'signingSha256'], 'physical evidence installed Android provenance');
  exactKeys(preflight.android.apk, ['packageName', 'versionCode', 'versionName', 'signingSha256', 'bytes', 'sha256', 'path'], 'physical evidence APK provenance');
  assert.equal(preflight.android.installed.versionCode, preflight.android.apk.versionCode, 'physical evidence Android versionCode provenance mismatch');
  assert.equal(preflight.android.installed.versionName, preflight.android.apk.versionName, 'physical evidence Android versionName provenance mismatch');
  assert.equal(preflight.android.installed.signingSha256, preflight.android.apk.signingSha256, 'physical evidence Android signer provenance mismatch');
  assert.match(preflight.android.apk.sha256, EVIDENCE_DIGEST, 'physical evidence APK digest is invalid');
  exactKeys(preflight.android.apk.path, ['basename', 'pathSha256'], 'physical evidence APK path provenance');
  exactKeys(preflight.windows, ['executable', 'exeSha256', 'bytes', 'isolatedAppData'], 'physical evidence Windows provenance');
  assert.match(preflight.windows.exeSha256, EVIDENCE_DIGEST, 'physical evidence Windows executable digest is invalid');
  exactKeys(preflight.windows.executable, ['basename', 'pathSha256'], 'physical evidence Windows path provenance');
  exactKeys(preflight.windows.isolatedAppData, ['basename', 'pathSha256'], 'physical evidence AppData provenance');
  assert.equal(evidence.schemaVersion, EVIDENCE_SCHEMA_VERSION, 'physical evidence schema version mismatch');
  assert.equal(evidence.contract, 'deep-physical-release-critical-v1', 'physical evidence contract mismatch');
  assert.ok(['passed', 'failed', 'test-only-passed', 'test-only-failed'].includes(evidence.status), 'physical evidence status is invalid');
  assert.equal(evidence.releaseEligible, evidence.provenance.mode === 'physical', 'release eligibility must derive from physical provenance');
  if (evidence.releaseEligible) assert.ok(['passed', 'failed'].includes(evidence.status), 'physical evidence must use a physical status');
  else assert.ok(evidence.status.startsWith('test-only-'), 'test-double evidence cannot use a release status');
  assert.deepEqual(evidence.flows.map(flow => flow.name), [...REQUIRED_FLOWS], 'physical evidence flows are incomplete or reordered');
  assert.ok(evidence.flows.every(flow => ['passed', 'failed', 'not-run'].includes(flow.status)), 'physical evidence flow status is invalid');
  if (evidence.status.endsWith('passed')) assert.ok(evidence.flows.every(flow => flow.status === 'passed'), 'passed evidence contains an incomplete flow');
  for (const flow of evidence.flows) {
    exactKeys(flow, ['name', 'status', 'actions', 'identityProofs'], `physical evidence flow '${flow.name}'`);
    assert.ok(Array.isArray(flow.actions) && flow.actions.length <= 64, `physical evidence flow '${flow.name}' actions are unbounded`);
    assert.equal(new Set(flow.actions.map(action => action.purpose)).size, flow.actions.length, `physical evidence flow '${flow.name}' action purposes are duplicated`);
    for (const action of flow.actions) {
      const fields = ['type', 'target', 'purpose', 'elapsedMs'];
      if (Object.hasOwn(action, 'selectorSha256')) fields.push('selectorSha256');
      exactKeys(action, fields, `physical evidence action '${action.purpose}'`);
      assert.ok(UI_ACTIONS.has(action.type) || SYSTEM_ACTIONS.has(action.type), 'physical evidence action type is invalid');
      assert.ok(['android', 'windows', 'system'].includes(action.target), 'physical evidence action target is invalid');
      assert.match(action.purpose, /^[A-Za-z][A-Za-z0-9]{2,79}$/, 'physical evidence action purpose is invalid');
      assert.ok(Number.isInteger(action.elapsedMs) && action.elapsedMs >= 0, 'physical evidence action elapsedMs is invalid');
      if (action.selectorSha256) assert.match(action.selectorSha256, EVIDENCE_DIGEST, 'physical evidence selector digest is invalid');
    }
    if (flow.status === 'passed') requireOrderedPurposes(flow.name, flow.actions, REQUIRED_EVIDENCE_PURPOSES[flow.name]);
    assert.ok(Array.isArray(flow.identityProofs) && flow.identityProofs.length <= 4, `physical evidence flow '${flow.name}' identity proofs are unbounded`);
    for (const proof of flow.identityProofs) {
      exactKeys(proof, ['target', 'deepIdSha256'], 'physical evidence identity proof');
      assert.ok(['android', 'windows'].includes(proof.target), 'physical evidence identity target is invalid');
      assert.match(proof.deepIdSha256, EVIDENCE_DIGEST, 'physical evidence identity digest is invalid');
    }
  }
  assert.ok(Array.isArray(evidence.processes) && evidence.processes.length <= 16, 'physical evidence process list is unbounded');
  for (const process of evidence.processes) {
    exactKeys(process, ['phase', 'pid', 'executablePathSha256', 'handleSha256', 'elapsedMs'], 'physical evidence process provenance');
    assert.ok(['initial', 'restore', 'restart'].includes(process.phase), 'physical evidence process phase is invalid');
    assert.ok(Number.isInteger(process.pid) && process.pid > 0, 'physical evidence process PID is invalid');
    assert.match(process.executablePathSha256, EVIDENCE_DIGEST, 'physical evidence process path digest is invalid');
    assert.match(process.handleSha256, EVIDENCE_DIGEST, 'physical evidence process handle digest is invalid');
  }
  assert.ok(Array.isArray(evidence.networkPeriods) && evidence.networkPeriods.length <= 4, 'physical evidence network periods are unbounded');
  for (const period of evidence.networkPeriods) {
    exactKeys(period, ['purpose', 'offlineElapsedMs', 'unavailable', 'restored', 'restoredBy'], 'physical evidence network period');
    assert.ok(Number.isInteger(period.offlineElapsedMs) && period.offlineElapsedMs >= 0, 'physical evidence offline duration is invalid');
    assert.equal(period.unavailable.length, preflight.compose.services.length, 'physical evidence unavailable-service proof is incomplete');
    assert.equal(period.restored.length, preflight.compose.services.length, 'physical evidence restored-service proof is incomplete');
    assert.deepEqual(period.unavailable.map(endpoint => endpoint.service), preflight.compose.services, 'physical evidence unavailable-service proof is reordered or duplicated');
    assert.deepEqual(period.restored.map(endpoint => endpoint.service), preflight.compose.services, 'physical evidence restored-service proof is reordered or duplicated');
    for (const unavailable of period.unavailable) {
      exactKeys(unavailable, ['service', 'urlSha256', 'unavailable', 'elapsedMs'], 'physical evidence unavailable endpoint');
      assert.equal(unavailable.unavailable, true, 'physical evidence endpoint was not proven unavailable');
      assert.ok(preflight.compose.services.includes(unavailable.service), 'physical evidence unavailable endpoint is unbound');
      assert.match(unavailable.urlSha256, EVIDENCE_DIGEST, 'physical evidence unavailable URL digest is invalid');
    }
    for (const restored of period.restored) {
      exactKeys(restored, ['service', 'status', 'buildSha256', 'urlSha256', 'bodySha256', 'elapsedMs'], 'physical evidence restored endpoint');
      assert.ok(preflight.compose.services.includes(restored.service), 'physical evidence restored endpoint is unbound');
      assert.equal(restored.status, 200, 'physical evidence restored endpoint status is not 200');
      assert.match(restored.buildSha256, EVIDENCE_DIGEST, 'physical evidence restored build digest is invalid');
      assert.match(restored.urlSha256, EVIDENCE_DIGEST, 'physical evidence restored URL digest is invalid');
      assert.match(restored.bodySha256, EVIDENCE_DIGEST, 'physical evidence restored body digest is invalid');
    }
  }
  exactKeys(evidence.cleanup, ['attempted', 'succeeded', 'steps'], 'physical evidence cleanup');
  assert.equal(evidence.cleanup.attempted, true, 'physical evidence cleanup was not attempted');
  assert.ok(Array.isArray(evidence.cleanup.steps) && evidence.cleanup.steps.length <= 8, 'physical evidence cleanup steps are unbounded');
  for (const step of evidence.cleanup.steps) exactKeys(step, ['name', 'succeeded'], 'physical evidence cleanup step');
  if (evidence.status.endsWith('passed')) {
    assert.equal(evidence.cleanup.succeeded, true, 'passed physical evidence requires successful cleanup');
    assert.ok(evidence.cleanup.steps.every(step => step.succeeded), 'passed physical evidence contains a failed cleanup step');
    assert.deepEqual(evidence.networkPeriods.map(period => period.purpose), ['offlineAccountCreateRestore', 'longOfflineServicesStop'], 'passed physical evidence has incomplete or reordered offline periods');
    assert.deepEqual(evidence.processes.map(process => process.phase), ['initial', 'restore', 'restart', 'restart'], 'passed physical evidence has incomplete or reordered process provenance');
  }
  if (evidence.failure) exactKeys(evidence.failure, ['name', 'message'], 'physical evidence failure');
  assert.ok(Object.values(evidence.correlations).every(value => EVIDENCE_DIGEST.test(value)), 'correlation evidence must contain only SHA-256 digests');
  const serialized = JSON.stringify(evidence);
  assert.ok(Buffer.byteLength(serialized) <= maxEvidenceBytes, 'physical evidence exceeds limits.maxEvidenceBytes');
  return evidence;
}

export function verifyReleaseEvidence(config, evidence) {
  validateConfig(config);
  validateEvidence(evidence, config.limits.maxEvidenceBytes);
  assert.equal(evidence.status, 'passed', 'release gate requires passed physical evidence');
  assert.equal(evidence.releaseEligible, true, 'release gate requires release-eligible evidence');
  assert.equal(evidence.provenance.mode, 'physical', 'release gate requires physical provenance');
  const preflight = evidence.provenance.preflight;
  assert.deepEqual(preflight.compose.services, config.compose.services, 'release evidence Compose services differ from config');
  for (let index = 0; index < config.compose.endpointPins.length; index += 1) {
    const pin = config.compose.endpointPins[index];
    const endpoint = preflight.compose.endpoints[index];
    assert.equal(endpoint.service, pin.service, 'release evidence endpoint service differs from config');
    assert.equal(endpoint.buildSha256, pin.expectedBuildSha256, `release evidence build pin differs for '${pin.service}'`);
    assert.equal(endpoint.urlSha256, sha256(normalizeEndpointUrl(pin.url)), `release evidence endpoint URL differs for '${pin.service}'`);
  }
  assert.equal(preflight.android.apk.path.basename, basename(config.android.apkPath), 'release evidence APK basename differs from config');
  assert.equal(preflight.android.apk.path.pathSha256, pathFingerprint(config.android.apkPath).pathSha256, 'release evidence APK path differs from config');
  assert.equal(preflight.windows.executable.basename, basename(config.windows.exePath), 'release evidence Windows executable basename differs from config');
  assert.equal(preflight.windows.executable.pathSha256, pathFingerprint(config.windows.exePath).pathSha256, 'release evidence Windows executable path differs from config');
  return evidence;
}

export async function runPhysicalE2E(config, options = {}) {
  validateConfig(config);
  const artifactsDir = resolve(required(options.artifactsDir, 'artifactsDir is required'));
  const markers = createMarkers(options.runId);
  const dependencies = options.dependencies ?? {};
  const injected = Object.keys(dependencies).length > 0;
  assert.equal(Boolean(options.testOnly), injected, 'injected dependencies require testOnly=true and physical runs forbid testOnly');
  const rawCommand = dependencies.command ?? defaultCommand;
  const fetchImpl = dependencies.fetch ?? fetch;
  const fs = dependencies.fs ?? fsDefault;
  const launch = dependencies.spawn ?? ((file, args, spawnOptions) => spawnProcess(file, args, spawnOptions));
  const artifactWrite = dependencies.artifactWrite ?? ((path, value) => fs.writeFile(path, value, 'utf8'));
  const startedMs = now(dependencies);
  const runDeadline = startedMs + config.limits.runTimeoutMs;
  let commandDeadline = runDeadline;
  const command = (file, args, commandOptions = {}) => beforeDeadline(
    remaining => rawCommand(file, args, { ...commandOptions, timeout: Math.min(commandOptions.timeout ?? remaining, remaining) }),
    commandDeadline,
    `Command ${basename(file)}`,
    dependencies
  );
  const boundedDependencies = { ...dependencies, command };
  assert.equal(safeUnder(config.windows.appDataRoot, artifactsDir), false, 'artifactsDir cannot be inside disposable AppData');
  await fs.mkdir(artifactsDir, { recursive: true });
  const preflightEvidence = await preflight(config, boundedDependencies, markers.runId);
  assert.equal(safeUnder(preflightEvidence.windows.isolatedAppData, artifactsDir), false, 'artifactsDir cannot be inside disposable AppData');

  const variables = { ...markers };
  const evidence = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    contract: 'deep-physical-release-critical-v1',
    startedAt: new Date().toISOString(),
    finishedAt: null,
    status: options.testOnly ? 'test-only-failed' : 'failed',
    releaseEligible: !options.testOnly,
    provenance: { mode: options.testOnly ? 'test-double' : 'physical', preflight: sanitizedPreflight(preflightEvidence) },
    correlations: evidenceCorrelations(markers),
    processes: [],
    networkPeriods: [],
    flows: REQUIRED_FLOWS.map(name => ({ name, status: 'not-run', actions: [], identityProofs: [] })),
    cleanup: { attempted: false, succeeded: true, steps: [] }
  };
  const drivers = { android: undefined, windows: undefined };
  const stoppedServices = new Set();
  let activeWindowsProcess;
  let previousPid;
  let activeOfflinePeriod;
  let mainError;
  let cleanupError;
  let artifactError;
  let runSucceeded = false;

  const launchWindows = async phase => {
    const isolated = preflightEvidence.windows.isolatedAppData;
    const child = launch(config.windows.exePath, [], {
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
    if (previousPid !== undefined) assert.notEqual(provenance.pid, previousPid, 'client restart reused the active Windows PID');
    previousPid = provenance.pid;
    evidence.processes.push({
      phase,
      pid: provenance.pid,
      executablePathSha256: provenance.executablePathSha256,
      handleSha256: sha256(String(provenance.handle)),
      elapsedMs: provenance.elapsedMs
    });
    return provenance;
  };

  const startAndroidDriver = async () => {
    const apk = preflightEvidence.android.apk;
    drivers.android = await startDriver(config.android, {
      'appium:udid': config.android.serial,
      'appium:appPackage': config.android.packageName,
      'appium:appActivity': config.android.launchActivity,
      'deep:versionCode': apk.versionCode,
      'deep:versionName': apk.versionName,
      'deep:signingSha256': apk.signingSha256
    }, fetchImpl);
  };

  const startWindowsDriver = async provenance => {
    drivers.windows = await startDriver(config.windows, {
      'appium:appTopLevelWindow': `0x${provenance.handle.toString(16)}`,
      'deep:processId': provenance.pid,
      'deep:executableSha256': preflightEvidence.windows.exeSha256
    }, fetchImpl);
  };

  const stopWindowsClient = async () => {
    if (drivers.windows) await stopDriver(drivers.windows, fetchImpl);
    drivers.windows = undefined;
    if (activeWindowsProcess?.pid) await command('taskkill', ['/pid', String(activeWindowsProcess.pid), '/t', '/f']);
    activeWindowsProcess = undefined;
  };

  const stopActiveClients = async () => {
    if (drivers.android) await stopDriver(drivers.android, fetchImpl);
    drivers.android = undefined;
    await stopWindowsClient();
    await command('adb', ['-s', config.android.serial, 'shell', 'am', 'force-stop', config.android.packageName]);
  };

  const startClients = async phase => {
    const windows = await launchWindows(phase);
    await command('adb', ['-s', config.android.serial, 'shell', 'am', 'start', '-W', '-n', `${config.android.packageName}/${config.android.launchActivity}`]);
    await startAndroidDriver();
    await startWindowsDriver(windows);
  };

  const restartClients = async () => {
    await stopActiveClients();
    await startClients('restart');
  };

  const resetWindowsProfile = async () => {
    await stopWindowsClient();
    const isolated = preflightEvidence.windows.isolatedAppData;
    assert.ok(safeUnder(config.windows.appDataRoot, isolated), 'profile reset target escaped AppData root');
    assert.equal(await fs.readFile(join(isolated, '.deep-e2e-isolated'), 'utf8'), 'physical-e2e isolated appdata\n', 'profile reset sentinel mismatch');
    await fs.rm(isolated, { recursive: true, force: false });
    await fs.mkdir(isolated, { recursive: false });
    await assertCanonicalDirectory(isolated, fs);
    await fs.writeFile(join(isolated, '.deep-e2e-isolated'), 'physical-e2e isolated appdata\n', 'utf8');
    const windows = await launchWindows('restore');
    await startWindowsDriver(windows);
  };

  const takeServicesOffline = async definition => {
    assert.equal(activeOfflinePeriod, undefined, 'services are already in an offline period');
    const purpose = definition?.purpose ?? 'offlineAccountCreateRestore';
    const periodStarted = now(dependencies);
    config.compose.services.forEach(service => stoppedServices.add(service));
    const endpoints = [];
    activeOfflinePeriod = { purpose, startedMs: periodStarted, endpoints };
    await command('docker', ['compose', '-p', config.compose.project, '-f', config.compose.file, 'stop', ...config.compose.services]);
    for (const pin of config.compose.endpointPins) {
      endpoints.push(await waitForEndpointUnavailable(
        pin,
        fetchImpl,
        config.limits.offlineProbeTimeoutMs,
        config.limits.offlineProbePollMs,
        dependencies.sleep,
        dependencies
      ));
    }
  };

  const restoreServicesOnline = async definition => {
    required(activeOfflinePeriod, 'no active offline period can be restored');
    await command('docker', ['compose', '-p', config.compose.project, '-f', config.compose.file, 'start', ...config.compose.services]);
    const endpoints = [];
    for (const pin of config.compose.endpointPins) {
      endpoints.push(await waitForEndpointPin(
        pin,
        fetchImpl,
        config.limits.offlineProbeTimeoutMs,
        config.limits.offlineProbePollMs,
        dependencies.sleep,
        dependencies
      ));
    }
    stoppedServices.clear();
    evidence.networkPeriods.push({
      purpose: activeOfflinePeriod.purpose,
      offlineElapsedMs: now(dependencies) - activeOfflinePeriod.startedMs,
      unavailable: activeOfflinePeriod.endpoints,
      restored: endpoints,
      restoredBy: definition?.purpose ?? 'runner'
    });
    activeOfflinePeriod = undefined;
  };

  const waitLongOffline = async () => {
    required(activeOfflinePeriod, 'long-offline wait requires an active offline period');
    assert.equal(activeOfflinePeriod.purpose, 'longOfflineServicesStop', 'long-offline wait is bound to the wrong outage');
    const remaining = config.limits.longOfflineMs - (now(dependencies) - activeOfflinePeriod.startedMs);
    if (remaining > 0) await (dependencies.sleep ?? sleepDefault)(remaining);
    assert.ok(now(dependencies) - activeOfflinePeriod.startedMs >= config.limits.longOfflineMs, 'long-offline window was not reached');
  };

  const systemActions = { resetWindowsProfile, restoreServicesOnline, takeServicesOffline, waitLongOffline, restartClients };

  try {
    await takeServicesOffline({ purpose: 'offlineAccountCreateRestore' });
    await startClients('initial');
    for (const name of REQUIRED_FLOWS) {
      const flowEvidence = evidence.flows.find(flow => flow.name === name);
      flowEvidence.status = 'failed';
      await executeActions(drivers, config.flows[name], variables, flowEvidence, dependencies, config, systemActions, runDeadline);
      flowEvidence.status = 'passed';
      if (name === 'reciprocalContact') {
        assert.ok(variables.actualIdentityWindows && variables.actualIdentityAndroid, 'both actual client identities must be captured');
        assert.notEqual(variables.actualIdentityWindows, variables.actualIdentityAndroid, 'client identities must be distinct');
      }
    }
    runSucceeded = true;
  } catch (error) {
    mainError = error;
    evidence.failure = { name: error.name, message: 'physical E2E execution failed' };
  } finally {
    const cleanupDeadline = now(dependencies) + config.limits.cleanupTimeoutMs;
    commandDeadline = cleanupDeadline;
    evidence.cleanup.attempted = true;
    await cleanupStep(evidence.cleanup, 'android-driver', async () => {
      if (drivers.android) await stopDriver(drivers.android, fetchImpl);
      drivers.android = undefined;
    }, cleanupDeadline, dependencies);
    await cleanupStep(evidence.cleanup, 'windows-driver', async () => {
      if (drivers.windows) await stopDriver(drivers.windows, fetchImpl);
      drivers.windows = undefined;
    }, cleanupDeadline, dependencies);
    await cleanupStep(evidence.cleanup, 'android-force-stop', async () => {
      await command('adb', ['-s', config.android.serial, 'shell', 'am', 'force-stop', config.android.packageName]);
    }, cleanupDeadline, dependencies);
    await cleanupStep(evidence.cleanup, 'windows-process', async () => {
      if (activeWindowsProcess?.pid) await command('taskkill', ['/pid', String(activeWindowsProcess.pid), '/t', '/f']);
      activeWindowsProcess = undefined;
    }, cleanupDeadline, dependencies);
    await cleanupStep(evidence.cleanup, 'compose-services', async () => {
      if (stoppedServices.size === 0) return;
      await restoreServicesOnline({ purpose: 'cleanup' });
    }, cleanupDeadline, dependencies);
    await cleanupStep(evidence.cleanup, 'isolated-appdata', async () => {
      const isolated = preflightEvidence.windows.isolatedAppData;
      assert.ok(safeUnder(config.windows.appDataRoot, isolated), 'cleanup target escaped AppData root');
      assert.equal(await fs.readFile(join(isolated, '.deep-e2e-isolated'), 'utf8'), 'physical-e2e isolated appdata\n', 'cleanup sentinel mismatch');
      await fs.rm(isolated, { recursive: true, force: false });
      await assertPathAbsent(fs, isolated, 'isolated AppData');
    }, cleanupDeadline, dependencies);
    if (!evidence.cleanup.succeeded) cleanupError = new Error('physical E2E cleanup did not complete');
    evidence.status = runSucceeded && evidence.cleanup.succeeded
      ? (options.testOnly ? 'test-only-passed' : 'passed')
      : (options.testOnly ? 'test-only-failed' : 'failed');
    evidence.finishedAt = new Date().toISOString();
    try {
      validateEvidence(evidence, config.limits.maxEvidenceBytes);
      await beforeDeadline(
        () => artifactWrite(join(artifactsDir, 'physical-deep-e2e.json'), JSON.stringify(evidence, null, 2)),
        cleanupDeadline,
        'Evidence write',
        dependencies
      );
    } catch (error) {
      artifactError = error;
    }
  }

  if (mainError) throw mainError;
  if (cleanupError) throw cleanupError;
  if (artifactError) throw artifactError;
  return evidence;
}
