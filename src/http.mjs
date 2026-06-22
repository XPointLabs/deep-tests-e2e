import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const urls = {
  router: process.env.XNODE_URL ?? 'http://127.0.0.1:18081',
  registry: process.env.DEEP_REGISTRY_URL ?? 'http://127.0.0.1:18080',
  storage: process.env.DEEP_STORAGE_URL ?? 'http://127.0.0.1:18100',
  file: process.env.DEEP_FILE_URL ?? 'http://127.0.0.1:18101',
  push: process.env.DEEP_PUSH_URL ?? 'http://127.0.0.1:18102',
  staking: process.env.DEEP_STAKING_URL ?? 'http://127.0.0.1:18082',
  devnetRpc: process.env.DEEP_DEVNET_RPC_URL ?? 'http://127.0.0.1:18545'
};

async function assertOk(response, context) {
  if (response.ok) {
    return;
  }

  const bodyText = await response.text();
  assert.equal(response.ok, true, `${response.status} ${context}: ${bodyText}`);
}

export async function getJson(baseUrl, path) {
  const response = await fetch(new URL(path, baseUrl));
  await assertOk(response, `GET ${path}`);
  return response.json();
}

export async function postJson(baseUrl, path, payload) {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  await assertOk(response, `POST ${path}`);
  return response.json();
}

export async function putJson(baseUrl, path, payload) {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  await assertOk(response, `PUT ${path}`);
  return response.json();
}

export async function postBytes(baseUrl, path, bytes, contentType = 'application/octet-stream') {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'POST',
    headers: { 'content-type': contentType },
    body: bytes
  });
  await assertOk(response, `POST ${path}`);
  return response.json();
}

export async function getBytes(baseUrl, path) {
  const response = await fetch(new URL(path, baseUrl));
  await assertOk(response, `GET ${path}`);
  return Buffer.from(await response.arrayBuffer());
}

export async function jsonRpc(baseUrl, method, params = []) {
  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
  });
  await assertOk(response, `RPC ${method}`);
  const body = await response.json();
  assert.equal(body.error, undefined, `RPC ${method} returned ${JSON.stringify(body.error)}`);
  return body.result;
}

export function writeArtifact(name, value) {
  const directory = process.env.DEEP_ARTIFACT_DIR;
  if (!directory) {
    return;
  }
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, name), JSON.stringify(value, null, 2));
}

