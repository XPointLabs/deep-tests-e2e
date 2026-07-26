import assert from 'node:assert/strict';
import test from 'node:test';
import { assertArm64WindowsExecutable, createMarkers, interpolate, parseComposePs, preflight, validateConfig } from '../../src/physical-e2e.mjs';

function config() {
  const selector = { using: 'accessibility id', value: 'DeepSemanticControl' };
  return {
    version: 1,
    compose: {
      file: 'C:\\compose\\docker-compose.yml', project: 'physical-deep', services: ['router', 'file'],
      endpointPins: [
        { service: 'router', url: 'http://127.0.0.1:18081/health/ready', expectedStatus: 200, bodyIncludes: 'ok' },
        { service: 'file', url: 'http://127.0.0.1:18101/health/ready', expectedStatus: 200 }
      ]
    },
    android: { serial: '192.168.1.45:36969', packageName: 'network.xpoint.deep.e2e', apkPath: 'C:\\builds\\deep.apk', driver: { url: 'http://127.0.0.1:4723' } },
    windows: { exePath: 'C:\\builds\\deep.exe', processName: 'deep.exe', appDataRoot: 'C:\\evidence\\appdata', driver: { url: 'http://127.0.0.1:4723' } },
    attachmentPath: 'C:\\fixtures\\attachment.bin',
    flows: {
      invalidIdentity: [{ target: 'windows', type: 'setValue', selector, value: '{{invalidIdentity}}' }],
      mutualIdentity: [{ target: 'windows', type: 'setValue', selector, value: '{{identityAndroid}}' }, { target: 'android', type: 'setValue', selector, value: '{{identityWindows}}' }],
      windowsToAndroidText: [{ target: 'windows', type: 'setValue', selector, value: '{{windowsToAndroidMessage}}' }, { target: 'android', type: 'assertText', selector, contains: '{{windowsToAndroidMessage}}' }],
      androidToWindowsText: [{ target: 'android', type: 'setValue', selector, value: '{{androidToWindowsMessage}}' }, { target: 'windows', type: 'assertText', selector, contains: '{{androidToWindowsMessage}}' }],
      androidToWindowsAttachment: [{ target: 'android', type: 'setValue', selector, value: '{{attachmentPath}}' }, { target: 'windows', type: 'assertFileSha256', path: '{{runAppData}}\\attachment.bin', expected: 'attachment' }],
      coldRestartVerify: [{ target: 'windows', type: 'assertFileSha256', path: '{{runAppData}}\\attachment.bin', expected: 'attachment' }]
    },
    chaos: { enabled: false }
  };
}

test('physical markers are unique and interpolated without leaking unknown fields', () => {
  const first = createMarkers('run-1');
  const second = createMarkers('run-2');
  assert.notEqual(first.windowsToAndroidMessage, second.windowsToAndroidMessage);
  assert.equal(interpolate('{{windowsToAndroidMessage}}', first), first.windowsToAndroidMessage);
  assert.throws(() => interpolate('{{unknown}}', first), /Unknown physical E2E template/);
});

test('compose ps parser accepts Docker array and line formats', () => {
  assert.equal(parseComposePs('[{"Service":"router"}]').length, 1);
  assert.equal(parseComposePs('{"Service":"router"}\n{"Service":"file"}').length, 2);
});

test('Windows executable evidence is restricted to ARM64 PE binaries', () => {
  const arm64 = Buffer.alloc(128);
  arm64.write('MZ'); arm64.writeUInt32LE(64, 0x3c); arm64.write('PE\0\0', 64); arm64.writeUInt16LE(0xaa64, 68);
  assert.doesNotThrow(() => assertArm64WindowsExecutable(arm64));
  arm64.writeUInt16LE(0x8664, 68);
  assert.throws(() => assertArm64WindowsExecutable(arm64), /ARM64/);
});

test('config rejects coordinate automation and missing cross-client evidence', () => {
  const invalid = config();
  invalid.flows.windowsToAndroidText[0].selector.using = 'xpath';
  assert.throws(() => validateConfig(invalid), /never coordinates/);

  const missingReceipt = config();
  missingReceipt.flows.androidToWindowsText[1].target = 'android';
  assert.throws(() => validateConfig(missingReceipt), /assert receipt on windows/);
});

test('preflight pins healthy compose services, endpoint responses, package and APK metadata', async () => {
  const commands = [];
  const command = async (file, args) => {
    commands.push([file, args]);
    if (file === 'docker') return { stdout: JSON.stringify([{ Service: 'router', State: 'running', Health: 'healthy' }, { Service: 'file', State: 'running', Health: 'healthy' }]) };
    if (file === 'aapt') return { stdout: "package: name='network.xpoint.deep.e2e' versionCode='7' versionName='1.2.3'" };
    if (args.includes('get-state')) return { stdout: 'device\n' };
    if (args.includes('pm')) return { stdout: 'package:/data/app/network.xpoint.deep.e2e/base.apk\n' };
    return { stdout: 'versionCode=7 versionName=1.2.3\n' };
  };
  const fs = {
    access: async () => {}, mkdir: async () => {}, writeFile: async () => {},
    stat: async path => ({ size: path.endsWith('.apk') ? 12 : 34 }),
    readFile: async path => {
      if (path.endsWith('.apk')) return Buffer.from('deep fixture');
      const arm64 = Buffer.alloc(128); arm64.write('MZ'); arm64.writeUInt32LE(64, 0x3c); arm64.write('PE\0\0', 64); arm64.writeUInt16LE(0xaa64, 68);
      return arm64;
    }
  };
  const fetch = async () => new Response('{"ok":true}', { status: 200 });
  const result = await preflight(config(), { command, fs, fetch });
  assert.equal(result.android.installed.versionCode, 7);
  assert.equal(result.compose.endpoints.length, 2);
  assert.equal(result.windows.isolatedAppData.includes('physical-e2e-'), true);
  assert.equal(commands.some(([file]) => file === 'aapt'), true);
});

test('preflight fails closed when compose health is not healthy', async () => {
  const broken = config();
  const command = async file => file === 'docker'
    ? { stdout: JSON.stringify([{ Service: 'router', State: 'running', Health: 'healthy' }, { Service: 'file', State: 'running', Health: 'starting' }]) }
    : { stdout: '' };
  const fs = { access: async () => {}, mkdir: async () => {}, writeFile: async () => {}, stat: async () => ({ size: 1 }), readFile: async () => Buffer.from('x') };
  await assert.rejects(preflight(broken, { command, fs, fetch: async () => new Response('ok') }), /not healthy/);
});
