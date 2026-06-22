import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import test from 'node:test';
import {
  attachmentVectors,
  registrationPayloads
} from '../../src/fixtures.mjs';
import {
  getBytes,
  getJson,
  postBytes,
  postJson,
  putJson,
  urls,
  writeArtifact
} from '../../src/http.mjs';

const compatRelayId = '1111111111111111111111111111111111111111111111111111111111111111';
const storageSubaccountAccess = Object.freeze({
  READ: 0x01,
  WRITE: 0x02,
  DELETE: 0x04,
  ANY_PREFIX: 0x08
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

function concatenateSignatureValues(values) {
  let result = '';
  for (const value of values) {
    if (Array.isArray(value)) {
      result += concatenateSignatureValues(value);
      continue;
    }

    result += String(value ?? '');
  }
  return result;
}

function normalizeSubaccountTokenBytes(values) {
  const items = Array.isArray(values) ? values : [values];
  return items.map(value => {
    if (value && typeof value === 'object' && value.tokenBytes) {
      return Buffer.from(value.tokenBytes);
    }

    const normalized = typeof value === 'object' && value !== null && 'subaccount' in value
      ? value.subaccount
      : String(value);
    return Buffer.from(normalized, 'base64');
  });
}

function createStorageRevokeSubaccountSignatureMessage(timestamp, subaccounts) {
  return Buffer.concat([Buffer.from(`revoke_subaccount${timestamp}`), ...normalizeSubaccountTokenBytes(subaccounts)]);
}

function createStorageUnrevokeSubaccountSignatureMessage(timestamp, subaccounts) {
  return Buffer.concat([Buffer.from(`unrevoke_subaccount${timestamp}`), ...normalizeSubaccountTokenBytes(subaccounts)]);
}

function createStorageRevokedSubaccountsSignatureMessage(timestamp) {
  return Buffer.from(`revoked_subaccounts${timestamp}`);
}

function createPushSubscribeSignatureMessage(pubkey, timestamp, wantData, namespaces) {
  return Buffer.from(`MONITOR${String(pubkey).toLowerCase()}${Number(timestamp)}${wantData ? '1' : '0'}${namespaces.join(',')}`);
}

function createPushUnsubscribeSignatureMessage(pubkey, timestamp) {
  return Buffer.from(`UNSUBSCRIBE${String(pubkey).toLowerCase()}${Number(timestamp)}`);
}

function createStorageSigner(privateKey) {
  return {
    signStore(namespace, signatureTimestamp) {
      return cryptoSign(null, Buffer.from(`store${storageNamespaceSignatureValue(namespace)}${signatureTimestamp}`), privateKey).toString('base64');
    },
    signRetrieve(namespace, timestamp) {
      return cryptoSign(null, Buffer.from(`retrieve${storageNamespaceSignatureValue(namespace)}${timestamp}`), privateKey).toString('base64');
    },
    signGetExpiries(timestamp, messages) {
      return cryptoSign(null, Buffer.from(concatenateSignatureValues(['get_expiries', timestamp, messages])), privateKey).toString('base64');
    },
    signExpireAll(namespace, expiry) {
      return cryptoSign(null, Buffer.from(concatenateSignatureValues(['expire_all', storageNamespaceSignatureValue(namespace), expiry])), privateKey).toString('base64');
    },
    signExpire(mode, expiry, messages) {
      return cryptoSign(null, Buffer.from(concatenateSignatureValues(['expire', mode, expiry, messages])), privateKey).toString('base64');
    },
    signDelete(messages) {
      return cryptoSign(null, Buffer.from(concatenateSignatureValues(['delete', messages])), privateKey).toString('base64');
    },
    signDeleteAll(namespace, timestamp) {
      return cryptoSign(null, Buffer.from(concatenateSignatureValues(['delete_all', storageNamespaceSignatureValue(namespace), timestamp])), privateKey).toString('base64');
    },
    signRevokeSubaccount(timestamp, subaccounts) {
      return cryptoSign(null, createStorageRevokeSubaccountSignatureMessage(timestamp, subaccounts), privateKey).toString('base64');
    },
    signUnrevokeSubaccount(timestamp, subaccounts) {
      return cryptoSign(null, createStorageUnrevokeSubaccountSignatureMessage(timestamp, subaccounts), privateKey).toString('base64');
    },
    signRevokedSubaccounts(timestamp) {
      return cryptoSign(null, createStorageRevokedSubaccountsSignatureMessage(timestamp), privateKey).toString('base64');
    },
    signPushSubscribe(pubkey, timestamp, wantData, namespaces) {
      return cryptoSign(null, createPushSubscribeSignatureMessage(pubkey, timestamp, wantData, namespaces), privateKey).toString('base64');
    },
    signPushUnsubscribe(pubkey, timestamp) {
      return cryptoSign(null, createPushUnsubscribeSignatureMessage(pubkey, timestamp), privateKey).toString('base64');
    }
  };
}

function createTestStorageSigningIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const pubkeyEd25519 = Buffer.from(publicKeyDer.subarray(-32)).toString('hex');
  const directPubkey = `03${pubkeyEd25519}`;
  const signer = createStorageSigner(privateKey);

  return {
    directPubkey,
    ...signer,
    createSubaccount(options = {}) {
      const { publicKey: subaccountPublicKey, privateKey: subaccountPrivateKey } = generateKeyPairSync('ed25519');
      const subaccountPublicKeyDer = subaccountPublicKey.export({ type: 'spki', format: 'der' });
      const subaccountPublicKeyBytes = Buffer.from(subaccountPublicKeyDer.subarray(-32));
      const flags = (options.read === false ? 0 : storageSubaccountAccess.READ) |
        (options.write === false ? 0 : storageSubaccountAccess.WRITE) |
        (options.delete === true ? storageSubaccountAccess.DELETE : 0) |
        (options.anyPrefix === true ? storageSubaccountAccess.ANY_PREFIX : 0);
      const tokenBytes = Buffer.concat([
        Buffer.from([Number.parseInt(directPubkey.slice(0, 2), 16), flags, 0x00, 0x00]),
        subaccountPublicKeyBytes
      ]);

      return {
        subaccount: tokenBytes.toString('base64'),
        subaccountSig: cryptoSign(null, tokenBytes, privateKey).toString('base64'),
        tokenBytes,
        ...createStorageSigner(subaccountPrivateKey)
      };
    }
  };
}

const storageSigningIdentity = createTestStorageSigningIdentity();

function currentSigTs() {
  return Math.floor(Date.now() / 1000);
}

function createCurrentPushSubscriptionPayload(overrides = {}) {
  const payload = { ...registrationPayloads.pushSubscription, ...overrides };
  const serviceInfo = payload.service_info ?? registrationPayloads.pushSubscription.service_info;
  const sigTs = currentSigTs();
  const namespaces = Array.isArray(payload.namespaces) ? payload.namespaces.map(value => Number(value)) : [];
  const wantData = payload.data === undefined ? true : Boolean(payload.data);

  return {
    ...payload,
    pubkey: storageSigningIdentity.directPubkey,
    session_ed25519: undefined,
    subkey_tag: undefined,
    data: wantData,
    namespaces,
    sig_ts: sigTs,
    signature: storageSigningIdentity.signPushSubscribe(storageSigningIdentity.directPubkey, sigTs, wantData, namespaces),
    service_info: serviceInfo
  };
}

function createStorageDeleteAllPayload(pubkey, namespace) {
  return {
    pubkey,
    timestamp: Date.now(),
    signature: registrationPayloads.pushSubscription.signature,
    ...(namespace === undefined ? {} : { namespace })
  };
}

function createStorageStorePayload(overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  if (namespace % 10 !== 0 && payload.signature === undefined) {
    payload.signature = registrationPayloads.pushSubscription.signature;
  }
  return payload;
}

function isNoAuthRetrieveNamespace(namespace) {
  return namespace === -10 || (namespace < 0 && (-namespace % 20) === 1);
}

function createStorageRetrievePayload(overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace === undefined ? undefined : Number(payload.namespace);
  if ((namespace === undefined || !isNoAuthRetrieveNamespace(namespace)) && payload.signature === undefined) {
    payload.signature = registrationPayloads.pushSubscription.signature;
  }
  if (payload.signature !== undefined && payload.timestamp === undefined) {
    payload.timestamp = Date.now();
  }
  return payload;
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
    data: Buffer.from('signed full-suite storage message', 'utf8').toString('base64'),
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

function createSignedStorageGetExpiriesPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const timestamp = Number(payload.timestamp ?? Date.now());
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];

  return {
    pubkey: identity.directPubkey,
    timestamp,
    messages,
    signature: identity.signGetExpiries(timestamp, messages),
    ...payload
  };
}

function createSignedStorageExpireAllPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const expiry = Number(payload.expiry ?? (Date.now() + 60_000));

  return {
    pubkey: identity.directPubkey,
    expiry,
    signature: identity.signExpireAll(namespace, expiry),
    ...payload
  };
}

function createSignedStorageExpirePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];
  const expiry = Array.isArray(payload.expiry)
    ? payload.expiry.map(value => Number(value))
    : Number(payload.expiry ?? (Date.now() + 60_000));
  const mode = payload.shorten === true ? 'shorten' : payload.extend === true ? 'extend' : '';

  return {
    pubkey: identity.directPubkey,
    messages,
    expiry,
    signature: identity.signExpire(mode, expiry, messages),
    ...payload
  };
}

function createSignedStorageDeletePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];

  return {
    pubkey: identity.directPubkey,
    messages,
    signature: identity.signDelete(messages),
    ...payload
  };
}

function createSignedStorageDeleteAllPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp,
    signature: identity.signDeleteAll(namespace, timestamp),
    ...payload
  };
}

function withStorageSubaccount(payload, subaccount) {
  return {
    ...payload,
    subaccount: subaccount.subaccount,
    subaccount_sig: subaccount.subaccountSig
  };
}

function normalizeSubaccountTokenValues(values) {
  const items = Array.isArray(values) ? values : [values];
  return items.map(value => typeof value === 'object' && value !== null && 'subaccount' in value ? value.subaccount : String(value));
}

function createSignedStorageRevokeSubaccountPayload(identity, overrides = {}) {
  const { revoke: providedRevoke, ...rest } = overrides;
  const timestamp = Number(rest.timestamp ?? Date.now());
  const revokeValues = normalizeSubaccountTokenValues(providedRevoke ?? []);
  const revoke = Array.isArray(providedRevoke) ? revokeValues : revokeValues[0];

  return {
    pubkey: identity.directPubkey,
    timestamp,
    revoke,
    signature: identity.signRevokeSubaccount(timestamp, revokeValues),
    ...rest
  };
}

function createSignedStorageUnrevokeSubaccountPayload(identity, overrides = {}) {
  const { unrevoke: providedUnrevoke, ...rest } = overrides;
  const timestamp = Number(rest.timestamp ?? Date.now());
  const unrevokeValues = normalizeSubaccountTokenValues(providedUnrevoke ?? []);
  const unrevoke = Array.isArray(providedUnrevoke) ? unrevokeValues : unrevokeValues[0];

  return {
    pubkey: identity.directPubkey,
    timestamp,
    unrevoke,
    signature: identity.signUnrevokeSubaccount(timestamp, unrevokeValues),
    ...rest
  };
}

function createSignedStorageRevokedSubaccountsPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp,
    signature: identity.signRevokedSubaccounts(timestamp),
    ...payload
  };
}

test('Deep full e2e compatibility extensions', async () => {
  const pubkey = storageSigningIdentity.directPubkey;
  const nowMs = Date.now();
  const first = await postJson(urls.storage, '/storage/store', createSignedStorageStorePayload(storageSigningIdentity, {
    pubkey,
    namespace: 2,
    timestamp: nowMs,
    ttl: 86400000,
    data: Buffer.from('first full-suite message').toString('base64')
  }));
  const second = await postJson(urls.storage, '/storage/store', createSignedStorageStorePayload(storageSigningIdentity, {
    pubkey,
    namespace: 2,
    timestamp: nowMs + 1000,
    ttl: 86400000,
    data: Buffer.from('second full-suite message').toString('base64')
  }));
  const afterFirst = await postJson(urls.storage, '/storage/retrieve', createSignedStorageRetrievePayload(storageSigningIdentity, {
    pubkey,
    namespace: 2,
    last_hash: first.hash
  }));
  const expiries = await postJson(urls.storage, '/storage/get_expiries', createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
    pubkey,
    messages: [first.hash, second.hash, 'missing-hash'],
    timestamp: Date.now()
  }));
  const expired = await postJson(urls.storage, '/storage/expire_all', createSignedStorageExpireAllPayload(storageSigningIdentity, {
    pubkey,
    expiry: nowMs + 86400000
  }));
  const expiriesAfterExpireAll = await postJson(urls.storage, '/storage/get_expiries', createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
    pubkey,
    messages: [first.hash, second.hash],
    timestamp: Date.now()
  }));
  const targetedExpiry = nowMs + 86400000 + 5000;
  const expiredSelected = await postJson(urls.storage, '/storage/expire', createSignedStorageExpirePayload(storageSigningIdentity, {
    pubkey,
    messages: [first.hash],
    expiry: targetedExpiry,
    extend: true
  }));
  const expiriesAfterExpire = await postJson(urls.storage, '/storage/get_expiries', createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
    pubkey,
    messages: [first.hash, second.hash],
    timestamp: Date.now()
  }));
  const multiExpireTargets = [
    { hash: second.hash, expiry: targetedExpiry + 7_000 },
    { hash: first.hash, expiry: targetedExpiry + 3_000 }
  ];
  const expectedMultiExpire = [...multiExpireTargets].sort((left, right) => left.hash.localeCompare(right.hash));
  const expiredSelectedMulti = await postJson(urls.storage, '/storage/expire', createSignedStorageExpirePayload(storageSigningIdentity, {
    pubkey,
    messages: multiExpireTargets.map(item => item.hash),
    expiry: multiExpireTargets.map(item => item.expiry)
  }));
  const expiriesAfterMultiExpire = await postJson(urls.storage, '/storage/get_expiries', createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
    pubkey,
    messages: [first.hash, second.hash],
    timestamp: Date.now()
  }));
  assert.equal(afterFirst.messages.length, 1);
  assert.equal(afterFirst.messages[0].hash, second.hash);
  assert.deepEqual(expiries.expiries, {
    [first.hash]: nowMs + 86400000,
    [second.hash]: nowMs + 1000 + 86400000
  });
  assert.deepEqual(expired.swarm[compatRelayId].updated, [second.hash]);
  assert.deepEqual(expiriesAfterExpireAll.expiries, {
    [first.hash]: nowMs + 86400000,
    [second.hash]: nowMs + 86400000
  });
  assert.deepEqual(expiredSelected.swarm[compatRelayId].updated, [first.hash]);
  assert.deepEqual(expiriesAfterExpire.expiries, {
    [first.hash]: targetedExpiry,
    [second.hash]: nowMs + 86400000
  });
  assert.deepEqual(expiredSelectedMulti.swarm[compatRelayId].updated, expectedMultiExpire.map(item => item.hash));
  assert.deepEqual(expiredSelectedMulti.swarm[compatRelayId].expiry, expectedMultiExpire.map(item => item.expiry));
  assert.deepEqual(expiriesAfterMultiExpire.expiries, Object.fromEntries(expectedMultiExpire.map(item => [item.hash, item.expiry])));

  const selectivelyDeleted = await postJson(urls.storage, '/storage/delete', createSignedStorageDeletePayload(storageSigningIdentity, {
    pubkey,
    messages: ['garbage-hash', first.hash]
  }));
  assert.deepEqual(selectivelyDeleted.swarm[compatRelayId].deleted, [first.hash]);

  const afterSelectiveDelete = await postJson(urls.storage, '/storage/retrieve', createSignedStorageRetrievePayload(storageSigningIdentity, {
    pubkey,
    namespace: 2
  }));
  assert.equal(afterSelectiveDelete.messages.length, 1);
  assert.equal(afterSelectiveDelete.messages[0].hash, second.hash);

  const deleted = await postJson(
    urls.storage,
    '/storage/delete_all',
    createSignedStorageDeleteAllPayload(storageSigningIdentity, { pubkey, namespace: 2 })
  );
  assert.deepEqual(deleted.swarm[compatRelayId].deleted, [second.hash]);

  const afterDeleteAll = await postJson(urls.storage, '/storage/retrieve', createSignedStorageRetrievePayload(storageSigningIdentity, {
    pubkey,
    namespace: 2
  }));
  assert.equal(afterDeleteAll.messages.length, 0);

  const revokePrivate = await postJson(urls.storage, '/storage/store', createSignedStorageStorePayload(storageSigningIdentity, {
    pubkey,
    namespace: 42,
    timestamp: Date.now(),
    ttl: 86400000,
    data: Buffer.from('subaccount revoke private').toString('base64')
  }));
  const revokeUnrevocable = await postJson(urls.storage, '/storage/store', createSignedStorageStorePayload(storageSigningIdentity, {
    pubkey,
    namespace: -11,
    timestamp: Date.now() + 1000,
    ttl: 86400000,
    data: Buffer.from('subaccount revoke unrevocable').toString('base64')
  }));
  const storageSubaccount = storageSigningIdentity.createSubaccount();
  const subaccountBeforeRevokeTimestamp = Date.now();
  const subaccountBeforeRevoke = await postJson(urls.storage, '/storage/retrieve', withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
    pubkey,
    namespace: 42,
    timestamp: subaccountBeforeRevokeTimestamp,
    signature: storageSubaccount.signRetrieve(42, subaccountBeforeRevokeTimestamp)
  }), storageSubaccount));
  const subaccountRevocationListBefore = await postJson(
    urls.storage,
    '/storage/revoked_subaccounts',
    createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, { pubkey, timestamp: Date.now() })
  );
  const revokedSubaccount = await postJson(
    urls.storage,
    '/storage/revoke_subaccount',
    createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, { pubkey, timestamp: Date.now(), revoke: storageSubaccount })
  );
  const blockedRetrieveTimestamp = Date.now();
  const blockedRetrieveResponse = await fetch(new URL('/storage/retrieve', urls.storage), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
      pubkey,
      namespace: 42,
      timestamp: blockedRetrieveTimestamp,
      signature: storageSubaccount.signRetrieve(42, blockedRetrieveTimestamp)
    }), storageSubaccount))
  });
  const blockedAfterRevoke = await blockedRetrieveResponse.json();
  const subaccountRevocationListAfter = await postJson(
    urls.storage,
    '/storage/revoked_subaccounts',
    createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, { pubkey, timestamp: Date.now() })
  );
  const unrevocableAfterRevokeTimestamp = Date.now();
  const subaccountUnrevocableRetrieve = await postJson(urls.storage, '/storage/retrieve', withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
    pubkey,
    namespace: -11,
    timestamp: unrevocableAfterRevokeTimestamp,
    signature: storageSubaccount.signRetrieve(-11, unrevocableAfterRevokeTimestamp)
  }), storageSubaccount));
  const restoredSubaccount = await postJson(
    urls.storage,
    '/storage/unrevoke_subaccount',
    createSignedStorageUnrevokeSubaccountPayload(storageSigningIdentity, { pubkey, timestamp: Date.now(), unrevoke: storageSubaccount })
  );
  const restoredRetrieveTimestamp = Date.now();
  const subaccountAfterUnrevoke = await postJson(urls.storage, '/storage/retrieve', withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
    pubkey,
    namespace: 42,
    timestamp: restoredRetrieveTimestamp,
    signature: storageSubaccount.signRetrieve(42, restoredRetrieveTimestamp)
  }), storageSubaccount));

  assert.equal(subaccountBeforeRevoke.messages.length, 1);
  assert.equal(subaccountBeforeRevoke.messages[0].hash, revokePrivate.hash);
  assert.deepEqual(subaccountRevocationListBefore.revoked_subaccounts, []);
  assert.equal(revokedSubaccount.swarm[compatRelayId].count, 1);
  assert.equal(blockedRetrieveResponse.status, 401);
  assert.equal(blockedAfterRevoke.message, 'retrieve signature verification failed');
  assert.deepEqual(subaccountRevocationListAfter.revoked_subaccounts, [storageSubaccount.subaccount]);
  assert.equal(subaccountUnrevocableRetrieve.messages.length, 1);
  assert.equal(subaccountUnrevocableRetrieve.messages[0].hash, revokeUnrevocable.hash);
  assert.equal(restoredSubaccount.swarm[compatRelayId].count, 1);
  assert.equal(subaccountAfterUnrevoke.messages.length, 1);
  assert.equal(subaccountAfterUnrevoke.messages[0].hash, revokePrivate.hash);

  const sequencePubkey = `${pubkey}-sequence`;
  const sequenceTimestamp = Date.now();
  const sequence = await postJson(urls.storage, '/storage/sequence', {
    requests: [
      {
        method: 'store',
        params: {
          pubkey: sequencePubkey,
          timestamp: sequenceTimestamp,
          ttl: 60_000,
          data: Buffer.from('sequence full-suite message a').toString('base64')
        }
      },
      {
        method: 'retrieve',
        params: {
          pubkey: sequencePubkey,
          timestamp: Date.now(),
          signature: registrationPayloads.pushSubscription.signature
        }
      },
      {
        method: 'store',
        params: {
          pubkey: sequencePubkey,
          timestamp: sequenceTimestamp + 1_000,
          ttl: 60_000,
          data: Buffer.from('sequence full-suite message b').toString('base64')
        }
      },
      {
        method: 'delete_all',
        params: {
          pubkey: sequencePubkey,
          timestamp: Date.now(),
          signature: registrationPayloads.pushSubscription.signature
        }
      },
      {
        method: 'retrieve',
        params: {
          pubkey: sequencePubkey,
          timestamp: Date.now(),
          signature: registrationPayloads.pushSubscription.signature
        }
      }
    ]
  });
  assert.deepEqual(sequence.results.map(result => result.code), [200, 200, 200, 200, 200]);
  assert.equal(sequence.results[1].body.messages.length, 1);
  assert.equal(sequence.results[1].body.messages[0].hash, sequence.results[0].body.hash);
  assert.deepEqual(
    sequence.results[3].body.swarm[compatRelayId].deleted,
    [sequence.results[0].body.hash, sequence.results[2].body.hash].sort()
  );
  assert.deepEqual(sequence.results[4].body.messages, []);

  const content = Buffer.from(attachmentVectors.vectors[0].contentBase64Url, 'base64url');
  const uploadOne = await postBytes(urls.file, '/file', content, 'text/plain');
  const uploadOneInfo = await getJson(urls.file, `/file/${uploadOne.id}/info`);
  const uploadTwo = await postBytes(urls.file, '/file', content, 'text/plain');
  const uploadTwoInfo = await getJson(urls.file, `/file/${uploadTwo.id}/info`);
  assert.equal(uploadOne.id, uploadTwo.id);
  assert.equal(typeof uploadOne.expires, 'number');
  assert.ok(uploadTwo.expires >= uploadOne.expires);
  assert.equal(uploadTwoInfo.uploaded, uploadOneInfo.uploaded);
  assert.ok(uploadTwoInfo.expires >= uploadOneInfo.expires);
  const extendedUpload = await postJson(urls.file, `/file/${uploadOne.id}/extend`, {});
  assert.equal(extendedUpload.size, uploadOneInfo.size);
  assert.equal(extendedUpload.uploaded, uploadOneInfo.uploaded);
  assert.ok(extendedUpload.expires >= uploadOneInfo.expires);

  const avatarOwner = `${pubkey}-avatar`;
  const avatarOneBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
  const avatarOne = await postBytes(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}`, avatarOneBytes, 'image/png');
  const avatarOneInfo = await getJson(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}/info`);
  const avatarOneDownloaded = await getBytes(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}`);
  assert.equal(avatarOne.sessionId, avatarOwner);
  assert.equal(avatarOne.fileId, avatarOneInfo.fileId);
  assert.equal(avatarOneInfo.contentType, 'image/png');
  assert.equal(avatarOneInfo.size, avatarOneBytes.length);
  assert.deepEqual(avatarOneDownloaded, avatarOneBytes);

  const avatarTwoBytes = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x02]);
  const avatarTwo = await postBytes(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}`, avatarTwoBytes, 'image/jpeg');
  const avatarTwoInfo = await getJson(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}/info`);
  const avatarTwoDownloaded = await getBytes(urls.file, `/avatar/${encodeURIComponent(avatarOwner)}`);
  assert.equal(avatarTwo.sessionId, avatarOwner);
  assert.notEqual(avatarTwo.fileId, avatarOne.fileId);
  assert.equal(avatarTwoInfo.fileId, avatarTwo.fileId);
  assert.equal(avatarTwoInfo.contentType, 'image/jpeg');
  assert.equal(avatarTwoInfo.size, avatarTwoBytes.length);
  assert.ok(avatarTwoInfo.updated >= avatarOneInfo.updated);
  assert.deepEqual(avatarTwoDownloaded, avatarTwoBytes);

  const pushSubscription = createCurrentPushSubscriptionPayload({
    service_info: {
      ...registrationPayloads.pushSubscription.service_info,
      token: `${registrationPayloads.pushSubscription.service_info.token}-full`
    }
  });
  const firstPush = await postJson(urls.push, '/subscribe', pushSubscription);
  const secondPush = await postJson(urls.push, '/subscribe', pushSubscription);
  assert.equal(firstPush.success, true);
  assert.equal(secondPush.updated, true);

  const registered = await postJson(
    urls.registry,
    '/api/nodes/register',
    registrationPayloads.nodeRegistration
  );
  const nextTransport = {
    ...registrationPayloads.nodeRegistration.transport,
    host: 'router-updated',
    port: 8443,
    uuid: '00000000-0000-4000-8000-000000000002'
  };
  const updated = await putJson(urls.registry, `/api/nodes/${registered.nodeId}/transport`, nextTransport);
  const profile = await getJson(urls.registry, `/api/nodes/${registered.nodeId}/transport-profile`);
  assert.equal(updated.endpoint, 'router-updated:8443');
  assert.equal(profile.bundle.uuid, nextTransport.uuid);

  writeArtifact('full-suite.json', {
    afterFirst,
    expiries,
    expired,
    expiriesAfterExpireAll,
    expiredSelected,
    expiriesAfterExpire,
    expiredSelectedMulti,
    expiriesAfterMultiExpire,
    selectivelyDeleted,
    afterSelectiveDelete,
    deleted,
    afterDeleteAll,
    revokePrivate,
    revokeUnrevocable,
    subaccountBeforeRevoke,
    subaccountRevocationListBefore,
    revokedSubaccount,
    blockedAfterRevoke,
    subaccountRevocationListAfter,
    subaccountUnrevocableRetrieve,
    restoredSubaccount,
    subaccountAfterUnrevoke,
    sequence,
    uploadOne,
    uploadTwo,
    uploadOneInfo,
    uploadTwoInfo,
    extendedUpload,
    avatarOne,
    avatarOneInfo,
    avatarTwo,
    avatarTwoInfo,
    firstPush,
    secondPush,
    updated,
    profile
  });
});
