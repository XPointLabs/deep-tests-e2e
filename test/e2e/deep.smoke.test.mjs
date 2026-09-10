import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import test from 'node:test';
import {
  attachmentVectors,
  messageVectors,
  registrationPayloads,
  rewardInvariants
} from '../../src/fixtures.mjs';
import {
  getBytes,
  getJson,
  jsonRpc,
  postBytes,
  postJson,
  urls,
  writeArtifact
} from '../../src/http.mjs';

function currentSigTs() {
  return Math.floor(Date.now() / 1000);
}

function createPushSubscribeSignatureMessage(pubkey, sigTs, wantData, namespaces) {
  return Buffer.from(`MONITOR${String(pubkey).toLowerCase()}${Number(sigTs)}${wantData ? '1' : '0'}${namespaces.join(',')}`);
}

function createPushUnsubscribeSignatureMessage(pubkey, sigTs) {
  return Buffer.from(`UNSUBSCRIBE${String(pubkey).toLowerCase()}${Number(sigTs)}`);
}

function storageNamespaceSignatureValue(namespace) {
  const parsed = Number(namespace);
  return Number.isFinite(parsed) && parsed === 0 ? '' : String(namespace ?? '');
}

function createPushSigningIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const pubkey = `03${Buffer.from(publicKeyDer.subarray(-32)).toString('hex')}`;

  return {
    pubkey,
    signPushSubscribe(sigTs, wantData, namespaces) {
      return cryptoSign(null, createPushSubscribeSignatureMessage(pubkey, sigTs, wantData, namespaces), privateKey).toString('base64');
    },
    signPushUnsubscribe(sigTs) {
      return cryptoSign(null, createPushUnsubscribeSignatureMessage(pubkey, sigTs), privateKey).toString('base64');
    },
    signStorageRetrieve(namespace, timestamp) {
      const message = Buffer.from(`retrieve${storageNamespaceSignatureValue(namespace)}${timestamp}`);
      return cryptoSign(null, message, privateKey).toString('base64');
    }
  };
}

function createCurrentPushSubscriptionPayload(identity, overrides = {}) {
  const payload = { ...registrationPayloads.pushSubscription, ...overrides };
  const sigTs = currentSigTs();
  const namespaces = Array.isArray(payload.namespaces) ? payload.namespaces.map(value => Number(value)) : [];
  const wantData = payload.data === undefined ? true : Boolean(payload.data);

  return {
    ...payload,
    pubkey: identity.pubkey,
    session_ed25519: undefined,
    subkey_tag: undefined,
    data: wantData,
    namespaces,
    sig_ts: sigTs,
    signature: identity.signPushSubscribe(sigTs, wantData, namespaces)
  };
}

function createPushUnsubscribePayload(identity, subscription) {
  const sigTs = currentSigTs();
  return {
    pubkey: subscription.pubkey,
    sig_ts: sigTs,
    signature: identity.signPushUnsubscribe(sigTs),
    service: subscription.service,
    service_info: subscription.service_info
  };
}

function isNoAuthRetrieveNamespace(namespace) {
  return namespace === -10 || (namespace < 0 && (-namespace % 20) === 1);
}

function createStorageRetrievePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace === undefined ? undefined : Number(payload.namespace);
  if ((namespace === undefined || !isNoAuthRetrieveNamespace(namespace)) && payload.signature === undefined) {
    const timestamp = Number(payload.timestamp ?? Date.now());
    payload.timestamp = timestamp;
    payload.signature = identity.signStorageRetrieve(namespace, timestamp);
  }
  return payload;
}

function createSmokeNodeRegistrationPayload() {
  return {
    ...registrationPayloads.nodeRegistration,
    nodeId: `${registrationPayloads.nodeRegistration.nodeId}-smoke`,
    transport: {
      ...registrationPayloads.nodeRegistration.transport,
      uuid: '00000000-0000-4000-8000-000000000003'
    }
  };
}

test('Deep smoke e2e', async () => {
  const expectedChainId = process.env.DEEP_EXPECTED_CHAIN_ID ?? '0x7a69';
  const health = {
    router: await getJson(urls.router, '/health/ready'),
    registry: await getJson(urls.registry, '/health/live'),
    storage: await getJson(urls.storage, '/health/ready'),
    file: await getJson(urls.file, '/health/ready'),
    push: await getJson(urls.push, '/health/ready'),
    staking: await getJson(urls.staking, '/health/live'),
    chainId: await jsonRpc(urls.devnetRpc, 'eth_chainId')
  };
  assert.equal(health.chainId, expectedChainId);
  writeArtifact('health.json', health);

  const alice = registrationPayloads.accounts.alice;
  const bob = registrationPayloads.accounts.bob;
  assert.equal(alice.sessionId.startsWith('05'), true);
  assert.equal(bob.sessionId.startsWith('05'), true);
  const smokeIdentity = createPushSigningIdentity();

  const offline = messageVectors.vectors.find(vector => vector.id === 'offline-message/simple-v1');
  const nowMs = Date.now();
  const storedOffline = await postJson(urls.storage, '/storage/store', {
    pubkey: smokeIdentity.pubkey,
    namespace: offline.namespace,
    timestamp: nowMs,
    ttl: offline.ttlMs,
    data: Buffer.from(offline.bodyBase64Url, 'base64url').toString('base64')
  });
  assert.match(storedOffline.hash, /^[A-Za-z0-9_-]+$/);

  const retrievedOffline = await postJson(urls.storage, '/storage/retrieve', {
    ...createStorageRetrievePayload(smokeIdentity, {
      pubkey: smokeIdentity.pubkey,
      namespace: offline.namespace
    })
  });
  const retrievedOfflineMessage = retrievedOffline.messages.find(
    message => message.hash === storedOffline.hash
  );
  assert.ok(retrievedOfflineMessage);
  assert.equal(
    Buffer.from(retrievedOfflineMessage.data, 'base64').toString('utf8'),
    offline.bodyUtf8
  );
  writeArtifact('offline-message.json', { storedOffline, retrievedOffline });

  const attachment = attachmentVectors.vectors[0];
  const attachmentBytes = Buffer.from(attachment.contentBase64Url, 'base64url');
  const upload = await postBytes(urls.file, '/file', attachmentBytes, attachment.contentType);
  const info = await getJson(urls.file, `/file/${upload.id}/info`);
  const downloaded = await getBytes(urls.file, `/file/${upload.id}`);
  assert.equal(info.size, attachment.size);
  assert.deepEqual(downloaded, attachmentBytes);
  writeArtifact('attachment.json', { upload, info });

  const group = messageVectors.vectors.find(vector => vector.id === 'group-message/simple-v1');
  const groupPubkey = smokeIdentity.pubkey;
  const storedGroup = await postJson(urls.storage, '/storage/store', {
    pubkey: groupPubkey,
    namespace: group.namespace,
    timestamp: nowMs,
    ttl: group.ttlMs,
    data: Buffer.from(group.bodyBase64Url, 'base64url').toString('base64')
  });
  const retrievedGroup = await postJson(urls.storage, '/storage/retrieve', {
    ...createStorageRetrievePayload(smokeIdentity, {
      pubkey: groupPubkey,
      namespace: group.namespace
    })
  });
  const retrievedGroupMessage = retrievedGroup.messages.find(
    message => message.hash === storedGroup.hash
  );
  assert.ok(retrievedGroupMessage);
  assert.deepEqual(
    JSON.parse(Buffer.from(retrievedGroupMessage.data, 'base64').toString('utf8')),
    group.bodyJson
  );
  writeArtifact('group-message.json', { storedGroup, retrievedGroup });

  const pushSigningIdentity = smokeIdentity;
  const pushSubscription = createCurrentPushSubscriptionPayload(pushSigningIdentity);
  const push = await postJson(urls.push, '/subscribe', pushSubscription);
  assert.equal(push.success, true);
  assert.equal(push.added, true);
  writeArtifact('push-registration.json', push);

  const pushDeliveredMessage = await postJson(urls.storage, '/storage/store', {
    pubkey: pushSubscription.pubkey,
    namespace: 0,
    timestamp: Date.now(),
    ttl: 60_000,
    data: Buffer.from('smoke push delivery').toString('base64')
  });
  const pushDeliveries = await getJson(urls.push, `/subscriptions/${encodeURIComponent(pushSubscription.pubkey)}`);
  assert.equal(pushDeliveries.subscriptions.length, 1);
  assert.equal(pushDeliveries.deliveries.length, 1);
  assert.equal(pushDeliveries.deliveries[0].hash, pushDeliveredMessage.hash);
  assert.equal(pushDeliveries.deliveries[0].token, pushSubscription.service_info.token);
  writeArtifact('push-delivery.json', { pushDeliveredMessage, pushDeliveries });

  const pushUnsubscribe = await postJson(
    urls.push,
    '/unsubscribe',
    createPushUnsubscribePayload(pushSigningIdentity, pushSubscription)
  );
  assert.equal(pushUnsubscribe.success, true);
  assert.equal(pushUnsubscribe.removed, true);
  writeArtifact('push-unsubscribe.json', pushUnsubscribe);

  const smokeNodeRegistration = createSmokeNodeRegistrationPayload();
  const registration = await postJson(urls.registry, '/api/nodes/register', smokeNodeRegistration);
  assert.equal(registration.nodeId, smokeNodeRegistration.nodeId);

  const transport = registration.transport;
  assert.equal(transport.protocol, 'vless');
  assert.equal(transport.uuid, smokeNodeRegistration.transport.uuid);
  writeArtifact('node-registration.json', { registration });

  for (const event of rewardInvariants.events) {
    await postJson(urls.staking, '/api/events', event);
  }
  const node = await getJson(urls.staking, `/api/staking/nodes/${rewardInvariants.node.nodeId}`);
  assert.equal(node.status, rewardInvariants.node.expectedStatus);
  assert.equal(node.operatorFeeBps, rewardInvariants.node.operatorFeeBps);

  const rewards = await getJson(urls.staking, `/api/staking/rewards/${rewardInvariants.wallet}`);
  assert.equal(rewards.tokenSymbol, rewardInvariants.token.symbol);
  assert.equal(
    rewards.claimableRewardsAtomic,
    rewardInvariants.expectedRewards.claimableRewardsAtomic
  );
  writeArtifact('reward-query.json', { node, rewards });

  const routerStatus = await getJson(urls.router, '/status');
  assert.equal(routerStatus.router.state, 'privacy-routing-unavailable');
  assert.equal(routerStatus.router.privacyRouting, false);
  const disabledRpcResponse = await fetch(new URL('/api/session/rpc', urls.router), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      id: 'smoke-status',
      method: 'status',
      payload: {}
    })
  });
  assert.equal(disabledRpcResponse.status, 404);
  writeArtifact('router-status.json', {
    routerStatus,
    disabledRpcStatus: disabledRpcResponse.status
  });
});

