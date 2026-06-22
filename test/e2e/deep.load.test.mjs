import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { registrationPayloads } from '../../src/fixtures.mjs';
import {
  getBytes,
  getJson,
  postBytes,
  postJson,
  urls,
  writeArtifact
} from '../../src/http.mjs';

const backendMode = process.env.DEEP_BACKEND_MODE ?? 'compat';
const storageSubaccountAccess = Object.freeze({
  READ: 0x01,
  WRITE: 0x02,
  DELETE: 0x04,
  ANY_PREFIX: 0x08
});
const loadPlan = Object.freeze({
  storageStoreCount: 12,
  storageBatchSize: 4,
  storageRetryAttempts: 2,
  duplicateUploadAttempts: 3,
  duplicateExtendAttempts: 2,
  avatarUpdateAttempts: 2,
  uniqueFileUploads: 4,
  fileUploadBatchSize: 2,
  fileExtendCount: 2,
  deliveryPollAttempts: 20,
  deliveryPollDelayMs: 100
});

function storageNamespaceSignatureValue(namespace) {
  if (namespace === undefined || namespace === null || namespace === '') {
    return '';
  }

  if (typeof namespace === 'string' && namespace.toLowerCase() === 'all') {
    return 'all';
  }

  const parsed = Number(namespace);
  return Number.isFinite(parsed) && parsed === 0 ? '' : String(parsed);
}

function createPushSubscribeSignatureMessage(pubkey, timestamp, wantData, namespaces) {
  return Buffer.from(`MONITOR${String(pubkey).toLowerCase()}${Number(timestamp)}${wantData ? '1' : '0'}${namespaces.join(',')}`);
}

function createPushUnsubscribeSignatureMessage(pubkey, timestamp) {
  return Buffer.from(`UNSUBSCRIBE${String(pubkey).toLowerCase()}${Number(timestamp)}`);
}

function createStorageSigner(privateKey, directPubkey) {
  return {
    signStore(namespace, signatureTimestamp) {
      return cryptoSign(null, Buffer.from(`store${storageNamespaceSignatureValue(namespace)}${signatureTimestamp}`), privateKey).toString('base64');
    },
    signRetrieve(namespace, timestamp) {
      return cryptoSign(null, Buffer.from(`retrieve${storageNamespaceSignatureValue(namespace)}${timestamp}`), privateKey).toString('base64');
    },
    signPushSubscribe(pubkey, timestamp, wantData, namespaces) {
      return cryptoSign(null, createPushSubscribeSignatureMessage(pubkey ?? directPubkey, timestamp, wantData, namespaces), privateKey).toString('base64');
    },
    signPushUnsubscribe(pubkey, timestamp) {
      return cryptoSign(null, createPushUnsubscribeSignatureMessage(pubkey ?? directPubkey, timestamp), privateKey).toString('base64');
    }
  };
}

function createTestStorageSigningIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const pubkeyEd25519 = Buffer.from(publicKeyDer.subarray(-32)).toString('hex');
  const directPubkey = `03${pubkeyEd25519}`;
  const signer = createStorageSigner(privateKey, directPubkey);

  return {
    directPubkey,
    ...signer,
    createSubaccount(options = {}) {
      const { publicKey: subaccountPublicKey } = generateKeyPairSync('ed25519');
      const subaccountPublicKeyDer = subaccountPublicKey.export({ type: 'spki', format: 'der' });
      const subaccountPublicKeyBytes = Buffer.from(subaccountPublicKeyDer.subarray(-32));
      const flags = (options.read === false ? 0 : storageSubaccountAccess.READ) |
        (options.write === false ? 0 : storageSubaccountAccess.WRITE) |
        (options.delete === true ? storageSubaccountAccess.DELETE : 0) |
        (options.anyPrefix === true ? storageSubaccountAccess.ANY_PREFIX : 0);

      return Buffer.concat([
        Buffer.from([Number.parseInt(directPubkey.slice(0, 2), 16), flags, 0x00, 0x00]),
        subaccountPublicKeyBytes
      ]).toString('base64');
    }
  };
}

function createSignedStorageStorePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  const signatureTimestamp = Number(payload.sig_timestamp ?? payload.sigTimestamp ?? payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp: signatureTimestamp,
    ttl: 60_000,
    namespace,
    data: Buffer.from('backend load smoke message', 'utf8').toString('base64'),
    signature: identity.signStore(namespace, signatureTimestamp),
    ...payload
  };
}

function createSignedStorageRetrievePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace === undefined ? 0 : Number(payload.namespace);
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    namespace,
    timestamp,
    signature: identity.signRetrieve(namespace, timestamp),
    ...payload
  };
}

function currentSigTs() {
  return Math.floor(Date.now() / 1000);
}

function createCurrentPushSubscriptionPayload(identity, overrides = {}) {
  const payload = { ...registrationPayloads.pushSubscription, ...overrides };
  const sigTs = currentSigTs();
  const namespaces = Array.isArray(payload.namespaces) ? payload.namespaces.map(value => Number(value)) : [];
  const wantData = payload.data === undefined ? true : Boolean(payload.data);
  const serviceInfo = payload.service_info ?? registrationPayloads.pushSubscription.service_info;

  return {
    ...payload,
    pubkey: identity.directPubkey,
    session_ed25519: undefined,
    subkey_tag: undefined,
    data: wantData,
    namespaces,
    sig_ts: sigTs,
    signature: identity.signPushSubscribe(identity.directPubkey, sigTs, wantData, namespaces),
    service_info: serviceInfo
  };
}

function createPushUnsubscribePayload(identity, subscription) {
  const sigTs = currentSigTs();
  return {
    pubkey: subscription.pubkey,
    sig_ts: sigTs,
    signature: identity.signPushUnsubscribe(subscription.pubkey, sigTs),
    service: subscription.service,
    service_info: subscription.service_info
  };
}

async function measure(samples, execute) {
  const startedAt = performance.now();
  const result = await execute();
  samples.push(performance.now() - startedAt);
  return result;
}

function roundMs(value) {
  return Math.round(value * 100) / 100;
}

function summarizeSamples(samples) {
  if (!Array.isArray(samples) || samples.length === 0) {
    return null;
  }

  const sorted = [...samples].sort((left, right) => left - right);
  const total = sorted.reduce((sum, value) => sum + value, 0);
  const percentile = ratio => sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * ratio) - 1)];

  return {
    count: sorted.length,
    minMs: roundMs(sorted[0]),
    maxMs: roundMs(sorted[sorted.length - 1]),
    avgMs: roundMs(total / sorted.length),
    p50Ms: roundMs(percentile(0.5)),
    p95Ms: roundMs(percentile(0.95)),
    totalMs: roundMs(total)
  };
}

async function runInBatches(items, batchSize, worker) {
  const results = [];
  for (let index = 0; index < items.length; index += batchSize) {
    const batch = items.slice(index, index + batchSize);
    const batchResults = await Promise.all(batch.map(worker));
    results.push(...batchResults);
  }
  return results;
}

function sortStrings(values) {
  return [...values].map(value => String(value)).sort((left, right) => left.localeCompare(right));
}

function diffCounters(before, after, keys) {
  return Object.fromEntries(keys.map(key => [key, Number(after[key] ?? 0) - Number(before[key] ?? 0)]));
}

function diffInventory(before, after, keys) {
  return Object.fromEntries(keys.map(key => [key, Number(after[key] ?? 0) - Number(before[key] ?? 0)]));
}

async function waitForPushDeliveries(pubkey, expectedCount) {
  let lastSnapshot = null;

  for (let attempt = 1; attempt <= loadPlan.deliveryPollAttempts; attempt += 1) {
    lastSnapshot = await getJson(urls.push, `/subscriptions/${encodeURIComponent(pubkey)}`);
    if (lastSnapshot.deliveries.length >= expectedCount) {
      return {
        attempts: attempt,
        snapshot: lastSnapshot
      };
    }

    await new Promise(resolve => setTimeout(resolve, loadPlan.deliveryPollDelayMs));
  }

  assert.fail(`push deliveries did not reach ${expectedCount}; last snapshot ${JSON.stringify(lastSnapshot)}`);
}

async function getServiceStats() {
  const [storage, file, push] = await Promise.all([
    getJson(urls.storage, '/stats'),
    getJson(urls.file, '/stats'),
    getJson(urls.push, '/stats')
  ]);

  return { storage, file, push };
}

test(
  'Deep backend-external load smoke',
  { skip: backendMode !== 'external' ? 'load evidence is required only for backend-external' : false },
  async () => {
    const storageIdentity = createTestStorageSigningIdentity();
    const storagePubkey = storageIdentity.directPubkey;
    const pushSubscription = createCurrentPushSubscriptionPayload(storageIdentity, {
      namespaces: [2],
      service_info: {
        ...registrationPayloads.pushSubscription.service_info,
        token: `${registrationPayloads.pushSubscription.service_info.token}-load`
      }
    });

    const statsBefore = await getServiceStats();

    const pushSubscribeSamples = [];
    const firstPush = await measure(pushSubscribeSamples, () => postJson(urls.push, '/subscribe', pushSubscription));
    const secondPush = await measure(pushSubscribeSamples, () => postJson(urls.push, '/subscribe', pushSubscription));
    assert.equal(firstPush.success, true);
    assert.equal(firstPush.added, true);
    assert.equal(secondPush.success, true);
    assert.equal(secondPush.updated, true);

    const storageRequests = Array.from({ length: loadPlan.storageStoreCount }, (_, index) => createSignedStorageStorePayload(storageIdentity, {
      pubkey: storagePubkey,
      namespace: 2,
      timestamp: Date.now() + index,
      ttl: 90_000 + (index * 1_000),
      data: Buffer.from(`backend-load-store-${index}`, 'utf8').toString('base64')
    }));
    const storageStoreSamples = [];
    const storedMessages = await runInBatches(storageRequests, loadPlan.storageBatchSize, request => measure(storageStoreSamples, () => postJson(urls.storage, '/storage/store', request)));
    assert.equal(new Set(storedMessages.map(message => message.hash)).size, loadPlan.storageStoreCount);

    const storageRetrySamples = [];
    const idempotentStoragePayload = createSignedStorageStorePayload(storageIdentity, {
      pubkey: storagePubkey,
      namespace: 7,
      timestamp: Date.now() + loadPlan.storageStoreCount + 1,
      ttl: 90_000,
      data: Buffer.from('backend-load-storage-retry', 'utf8').toString('base64'),
      idempotency_key: 'backend-load-storage-idem-1'
    });
    const firstIdempotentStore = await measure(storageRetrySamples, () => postJson(urls.storage, '/storage/store', idempotentStoragePayload));
    const secondIdempotentStore = await measure(storageRetrySamples, () => postJson(urls.storage, '/storage/store', idempotentStoragePayload));
    assert.equal(firstIdempotentStore.hash, secondIdempotentStore.hash);
    assert.equal(secondIdempotentStore.idempotent, true);

    const storageRetrieveSamples = [];
    const retrievedMessages = await measure(
      storageRetrieveSamples,
      () => postJson(urls.storage, '/storage/retrieve', createSignedStorageRetrievePayload(storageIdentity, {
        pubkey: storagePubkey,
        namespace: 2,
        timestamp: Date.now()
      }))
    );
    assert.equal(retrievedMessages.messages.length, loadPlan.storageStoreCount);
    assert.deepEqual(
      sortStrings(retrievedMessages.messages.map(message => message.hash)),
      sortStrings(storedMessages.map(message => message.hash))
    );

    const idempotentRetrieved = await measure(
      storageRetrieveSamples,
      () => postJson(urls.storage, '/storage/retrieve', createSignedStorageRetrievePayload(storageIdentity, {
        pubkey: storagePubkey,
        namespace: 7,
        timestamp: Date.now()
      }))
    );
    assert.equal(idempotentRetrieved.messages.length, 1);
    assert.equal(idempotentRetrieved.messages[0].hash, firstIdempotentStore.hash);

    const duplicateUploadContent = Buffer.from('backend-load-duplicate-upload', 'utf8');
    const fileUploadSamples = [];
    const duplicateUploads = await Promise.all(
      Array.from({ length: loadPlan.duplicateUploadAttempts }, () => measure(
        fileUploadSamples,
        () => postBytes(urls.file, '/file', duplicateUploadContent, 'text/plain')
      ))
    );
    assert.equal(new Set(duplicateUploads.map(upload => upload.id)).size, 1);
    assert.ok(Math.max(...duplicateUploads.map(upload => upload.expires)) >= Math.min(...duplicateUploads.map(upload => upload.expires)));

    const uniqueFilePayloads = Array.from({ length: loadPlan.uniqueFileUploads }, (_, index) => ({
      index,
      bytes: Buffer.from(`backend-load-unique-upload-${index}-${'x'.repeat(64 + index)}`, 'utf8')
    }));
    const uniqueUploads = await runInBatches(
      uniqueFilePayloads,
      loadPlan.fileUploadBatchSize,
      payload => measure(fileUploadSamples, async () => ({
        index: payload.index,
        response: await postBytes(urls.file, '/file', payload.bytes, 'text/plain'),
        bytes: payload.bytes
      }))
    );
    assert.equal(new Set(uniqueUploads.map(upload => upload.response.id)).size, loadPlan.uniqueFileUploads);

    const fileInfoSamples = [];
    const fileInfos = await runInBatches(
      uniqueUploads,
      loadPlan.fileUploadBatchSize,
      upload => measure(fileInfoSamples, async () => ({
        id: upload.response.id,
        info: await getJson(urls.file, `/file/${upload.response.id}/info`),
        bytes: upload.bytes
      }))
    );
    for (const fileInfo of fileInfos) {
      assert.equal(fileInfo.info.size, fileInfo.bytes.length);
    }

    const fileDownloadSamples = [];
    const fileDownloads = await runInBatches(
      uniqueUploads,
      loadPlan.fileUploadBatchSize,
      upload => measure(fileDownloadSamples, async () => ({
        id: upload.response.id,
        bytes: await getBytes(urls.file, `/file/${upload.response.id}`),
        expected: upload.bytes
      }))
    );
    for (const fileDownload of fileDownloads) {
      assert.deepEqual(fileDownload.bytes, fileDownload.expected);
    }

    const fileExtendSamples = [];
    const extendedUploads = [];
    for (const fileInfo of fileInfos.slice(0, loadPlan.fileExtendCount)) {
      extendedUploads.push(await measure(fileExtendSamples, async () => ({
        id: fileInfo.id,
        info: fileInfo.info,
        response: await postJson(urls.file, `/file/${fileInfo.id}/extend`, {})
      })));
    }
    for (const extendedUpload of extendedUploads) {
      assert.equal(extendedUpload.response.size, extendedUpload.info.size);
      assert.equal(extendedUpload.response.uploaded, extendedUpload.info.uploaded);
      assert.ok(extendedUpload.response.expires >= extendedUpload.info.expires);
    }

    const duplicateExtendResponses = await Promise.all(
      Array.from({ length: loadPlan.duplicateExtendAttempts }, () => measure(fileExtendSamples, async () => ({
        id: duplicateUploads[0].id,
        response: await postJson(urls.file, `/file/${duplicateUploads[0].id}/extend`, {})
      })))
    );
    for (const duplicateExtend of duplicateExtendResponses) {
      assert.equal(duplicateExtend.id, duplicateUploads[0].id);
      assert.equal(duplicateExtend.response.size, duplicateUploadContent.length);
      assert.ok(duplicateExtend.response.expires >= Math.max(...duplicateUploads.map(upload => upload.expires)));
    }

    const duplicateUploadInfoAfterExtend = await measure(
      fileInfoSamples,
      () => getJson(urls.file, `/file/${duplicateUploads[0].id}/info`)
    );
    assert.equal(duplicateUploadInfoAfterExtend.size, duplicateUploadContent.length);
    assert.equal(
      duplicateUploadInfoAfterExtend.expires,
      Math.max(...duplicateExtendResponses.map(extend => extend.response.expires))
    );
    assert.ok(duplicateUploadInfoAfterExtend.expires >= Math.max(...duplicateUploads.map(upload => upload.expires)));

    const avatarOwner = `${storagePubkey}-load-avatar`;
    const avatarSamples = [];
    const avatarPayloads = [
      {
        contentType: 'image/png',
        bytes: Buffer.from(`backend-load-avatar-png-${storagePubkey}`, 'utf8')
      },
      {
        contentType: 'image/jpeg',
        bytes: Buffer.from(`backend-load-avatar-jpeg-${storagePubkey}`, 'utf8')
      }
    ];
    const avatarUploads = [];
    for (const payload of avatarPayloads) {
      avatarUploads.push(await measure(
        avatarSamples,
        () => postBytes(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}`, payload.bytes, payload.contentType)
      ));
    }
    assert.equal(avatarUploads.length, loadPlan.avatarUpdateAttempts);
    assert.notEqual(avatarUploads[0].fileId, avatarUploads[1].fileId);

    const avatarInfo = await measure(
      avatarSamples,
      () => getJson(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}/info`)
    );
    assert.equal(avatarInfo.sessionId, avatarOwner);
    assert.equal(avatarInfo.fileId, avatarUploads.at(-1).fileId);
    assert.equal(avatarInfo.contentType, avatarPayloads.at(-1).contentType);
    assert.equal(avatarInfo.size, avatarPayloads.at(-1).bytes.length);

    const avatarDownload = await measure(
      avatarSamples,
      () => getBytes(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}`)
    );
    assert.deepEqual(avatarDownload, avatarPayloads.at(-1).bytes);

    const pushDeliveryResult = await waitForPushDeliveries(storagePubkey, loadPlan.storageStoreCount);
    const pushDeliveries = pushDeliveryResult.snapshot;
    assert.equal(pushDeliveries.subscriptions.length, 1);
    assert.equal(pushDeliveries.deliveries.length, loadPlan.storageStoreCount);
    assert.deepEqual(
      sortStrings(pushDeliveries.deliveries.map(delivery => delivery.hash)),
      sortStrings(storedMessages.map(message => message.hash))
    );
    assert.deepEqual(
      new Set(pushDeliveries.deliveries.map(delivery => delivery.token)).size,
      1
    );

    const pushUnsubscribeSamples = [];
    const pushUnsubscribe = await measure(
      pushUnsubscribeSamples,
      () => postJson(urls.push, '/unsubscribe', createPushUnsubscribePayload(storageIdentity, pushSubscription))
    );
    assert.equal(pushUnsubscribe.success, true);
    assert.equal(pushUnsubscribe.removed, true);

    const redundantPushUnsubscribe = await measure(
      pushUnsubscribeSamples,
      () => postJson(urls.push, '/unsubscribe', createPushUnsubscribePayload(storageIdentity, pushSubscription))
    );
    assert.equal(redundantPushUnsubscribe.success, true);
    assert.equal(redundantPushUnsubscribe.removed, false);

    const subscriptionsAfterUnsubscribe = await getJson(urls.push, `/subscriptions/${encodeURIComponent(storagePubkey)}`);
    assert.equal(subscriptionsAfterUnsubscribe.subscriptions.length, 0);
    assert.equal(subscriptionsAfterUnsubscribe.deliveries.length, loadPlan.storageStoreCount);

    const statsAfter = await getServiceStats();
    const statsDelta = {
      storage: diffCounters(statsBefore.storage.stats, statsAfter.storage.stats, ['storageStore', 'storageRetrieve']),
      file: diffCounters(statsBefore.file.stats, statsAfter.file.stats, ['fileUpload', 'fileDownload', 'fileInfo', 'fileExtend', 'avatarUpload', 'avatarDownload', 'avatarInfo']),
      push: diffCounters(statsBefore.push.stats, statsAfter.push.stats, ['pushSubscribe', 'pushUnsubscribe', 'subscriptionsList', 'pushNotificationsQueued'])
    };
    const inventoryDelta = {
      storage: diffInventory(statsBefore.storage.inventory, statsAfter.storage.inventory, ['storageMessages']),
      file: diffInventory(statsBefore.file.inventory, statsAfter.file.inventory, ['files', 'avatars']),
      push: diffInventory(statsBefore.push.inventory, statsAfter.push.inventory, [
        'pushDeliveries',
        'pushProviderDelivered',
        'pushProviderFailed',
        'pushProviderNotConfigured'
      ])
    };

    assert.equal(statsDelta.storage.storageStore, loadPlan.storageStoreCount + loadPlan.storageRetryAttempts);
    assert.equal(statsDelta.storage.storageRetrieve, 2);
    assert.equal(statsDelta.file.fileUpload, loadPlan.duplicateUploadAttempts + loadPlan.uniqueFileUploads);
    assert.equal(statsDelta.file.fileDownload, loadPlan.uniqueFileUploads);
    assert.equal(statsDelta.file.fileInfo, loadPlan.uniqueFileUploads + 1);
    assert.equal(statsDelta.file.fileExtend, loadPlan.fileExtendCount + loadPlan.duplicateExtendAttempts);
    assert.equal(statsDelta.file.avatarUpload, loadPlan.avatarUpdateAttempts);
    assert.equal(statsDelta.file.avatarDownload, 1);
    assert.equal(statsDelta.file.avatarInfo, 1);
    assert.equal(statsDelta.push.pushSubscribe, 2);
    assert.equal(statsDelta.push.pushUnsubscribe, 2);
    assert.ok(statsDelta.push.subscriptionsList >= pushDeliveryResult.attempts + 1);
    assert.equal(statsDelta.push.pushNotificationsQueued, loadPlan.storageStoreCount);
    assert.equal(inventoryDelta.storage.storageMessages, loadPlan.storageStoreCount + 1);
    assert.equal(inventoryDelta.file.files, loadPlan.uniqueFileUploads + 1 + loadPlan.avatarUpdateAttempts);
    assert.equal(inventoryDelta.file.avatars, 1);
    assert.equal(inventoryDelta.push.pushDeliveries, loadPlan.storageStoreCount);

    writeArtifact('backend-load-smoke.json', {
      backendMode,
      scenario: loadPlan,
      serviceUrls: {
        storage: urls.storage,
        file: urls.file,
        push: urls.push
      },
      statsBefore,
      statsAfter,
      statsDelta,
      inventoryDelta,
      timings: {
        pushSubscribe: summarizeSamples(pushSubscribeSamples),
        storageStore: summarizeSamples(storageStoreSamples),
        storageRetry: summarizeSamples(storageRetrySamples),
        storageRetrieve: summarizeSamples(storageRetrieveSamples),
        fileUpload: summarizeSamples(fileUploadSamples),
        fileInfo: summarizeSamples(fileInfoSamples),
        fileDownload: summarizeSamples(fileDownloadSamples),
        fileExtend: summarizeSamples(fileExtendSamples),
        avatar: summarizeSamples(avatarSamples),
        pushUnsubscribe: summarizeSamples(pushUnsubscribeSamples)
      },
      observations: {
        storedHashes: storedMessages.map(message => message.hash),
        retrievedHashes: retrievedMessages.messages.map(message => message.hash),
        idempotentStorageHash: firstIdempotentStore.hash,
        duplicateUploadId: duplicateUploads[0].id,
        duplicateUploadExpires: duplicateUploads.map(upload => upload.expires),
        duplicateExtendExpires: duplicateExtendResponses.map(extend => extend.response.expires),
        uniqueUploadIds: uniqueUploads.map(upload => upload.response.id),
        avatarOwner,
        avatarFileIds: avatarUploads.map(upload => upload.fileId),
        avatarContentType: avatarInfo.contentType,
        redundantPushUnsubscribeRemoved: redundantPushUnsubscribe.removed,
        pushDeliveryPollAttempts: pushDeliveryResult.attempts,
        pushDeliveryTokens: [...new Set(pushDeliveries.deliveries.map(delivery => delivery.token))],
        pushDeliveryProviderStatuses: [
          ...new Set(pushDeliveries.deliveries.map(delivery => delivery.provider?.status ?? 'missing'))
        ],
        pushProviderInventory: {
          delivered: statsAfter.push.inventory.pushProviderDelivered,
          failed: statsAfter.push.inventory.pushProviderFailed,
          notConfigured: statsAfter.push.inventory.pushProviderNotConfigured
        }
      }
    });
  }
);
