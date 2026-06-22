import assert from 'node:assert/strict';

function requiredEnv(name) {
  const value = process.env[name];
  assert.ok(value && value.length > 0, `Missing required environment variable: ${name}`);
  return value;
}

async function readJson(url, expectedStatus = 200, init) {
  const response = await fetch(url, init);
  assert.equal(response.status, expectedStatus, `Unexpected status for ${url}: ${response.status}`);
  return response.json();
}

function assertHasNumber(obj, key, context) {
  assert.equal(typeof obj[key], 'number', `${context} is missing numeric field '${key}'`);
}

function assertHealthy(body, context) {
  const isHealthy = body?.ok === true || body?.ready === true || String(body?.status || '').toLowerCase() === 'healthy';
  assert.equal(isHealthy, true, `${context} health must be healthy`);
}

async function checkRouter(baseUrl) {
  const health = await readJson(`${baseUrl}/health/ready`);
  assertHealthy(health, 'Router');
}

async function checkRegistry(baseUrl) {
  const health = await readJson(`${baseUrl}/health/live`);
  assertHealthy(health, 'Registry');

  const runtime = await readJson(`${baseUrl}/api/nodes/runtime`);
  assertHasNumber(runtime, 'totalNodes', 'Registry runtime');
  assertHasNumber(runtime, 'corruptedStateRecoveries', 'Registry runtime');
}

async function checkStaking(baseUrl) {
  const health = await readJson(`${baseUrl}/health/live`);
  assertHealthy(health, 'Staking');

  const stats = await readJson(`${baseUrl}/api/events/stats`);
  assertHasNumber(stats, 'attempted', 'Staking stats');
  assertHasNumber(stats, 'inserted', 'Staking stats');
  assertHasNumber(stats, 'duplicates', 'Staking stats');
  assertHasNumber(stats, 'staleNodeProjectionIgnored', 'Staking stats');
  assertHasNumber(stats, 'staleStatusIgnored', 'Staking stats');
  assertHasNumber(stats, 'corruptedStateRecoveries', 'Staking stats');
  assertHasNumber(stats, 'totalEvents', 'Staking stats');
}

async function checkCompatService(baseUrl, expectedMode) {
  const health = await readJson(`${baseUrl}/health/ready`);
  assertHealthy(health, `Compat ${expectedMode}`);

  const statsBody = await readJson(`${baseUrl}/stats`);
  assert.equal(statsBody.mode, expectedMode, `Compat stats mode mismatch for ${expectedMode}`);
  assert.ok(statsBody.stats && typeof statsBody.stats === 'object', 'Compat stats object is required');
  assert.ok(statsBody.inventory && typeof statsBody.inventory === 'object', 'Compat inventory object is required');

  assertHasNumber(statsBody.stats, 'requestsTotal', `Compat ${expectedMode} stats`);
  assertHasNumber(statsBody.stats, 'healthChecks', `Compat ${expectedMode} stats`);
}

async function checkDevnetRpc(baseUrl) {
  const payload = {
    jsonrpc: '2.0',
    id: 1,
    method: 'eth_chainId',
    params: []
  };

  const body = await readJson(baseUrl, 200, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });

  assert.ok(body && typeof body.result === 'string' && body.result.length > 0, 'Devnet eth_chainId result is missing');
}

async function main() {
  const routerUrl = requiredEnv('XNODE_URL');
  const registryUrl = requiredEnv('DEEP_REGISTRY_URL');
  const stakingUrl = requiredEnv('DEEP_STAKING_URL');
  const storageUrl = requiredEnv('DEEP_STORAGE_URL');
  const fileUrl = requiredEnv('DEEP_FILE_URL');
  const pushUrl = requiredEnv('DEEP_PUSH_URL');
  const devnetRpcUrl = requiredEnv('DEEP_DEVNET_RPC_URL');

  await checkRouter(routerUrl);
  await checkRegistry(registryUrl);
  await checkStaking(stakingUrl);
  await checkCompatService(storageUrl, 'storage');
  await checkCompatService(fileUrl, 'file');
  await checkCompatService(pushUrl, 'push');
  await checkDevnetRpc(devnetRpcUrl);

  console.log('runtime checks passed');
}

await main();
