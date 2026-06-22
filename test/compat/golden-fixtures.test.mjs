import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  attachmentVectors,
  manifest,
  messageVectors,
  registrationPayloads,
  rewardInvariants
} from '../../src/fixtures.mjs';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

test('source manifest pins upstream references', () => {
  const repositories = new Set(manifest.sources.map(source => source.repository));
  for (const expected of [
    'session-foundation/session-playwright',
    'session-foundation/session-appium',
    'session-foundation/session-docker-ci',
    'session-foundation/session-deps',
    'session-foundation/session-router',
    'session-foundation/session-storage-server',
    'session-foundation/session-file-server',
    'session-foundation/session-token-contracts',
    'session-foundation/libsession-util'
  ]) {
    assert.equal(repositories.has(expected), true, `${expected} missing from manifest`);
  }
});

test('message golden vectors are deterministic', () => {
  for (const vector of messageVectors.vectors) {
    const body = Buffer.from(vector.bodyBase64Url, 'base64url');
    assert.equal(sha256(body), vector.sha256, vector.id);
    assert.equal(vector.timestampMs > 0, true);
    assert.equal(vector.ttlMs > 0, true);

    if (vector.bodyUtf8) {
      assert.equal(body.toString('utf8'), vector.bodyUtf8);
    }

    if (vector.bodyJson) {
      assert.deepEqual(JSON.parse(body.toString('utf8')), vector.bodyJson);
    }
  }
});

test('attachment vectors match Session file-server upload contract', () => {
  for (const vector of attachmentVectors.vectors) {
    const content = Buffer.from(vector.contentBase64Url, 'base64url');
    assert.equal(content.length, vector.size);
    assert.equal(sha256(content), vector.sha256);
    assert.match(vector.contentType, /^[a-z]+\/[a-z0-9.+-]+$/i);
  }
});

test('reward invariants preserve claimable accounting', () => {
  const expected = rewardInvariants.expectedRewards;
  assert.equal(
    expected.lifetimeRewardsAtomic - expected.claimedRewardsAtomic,
    expected.claimableRewardsAtomic
  );
  assert.equal(rewardInvariants.node.stakeAtomic >= rewardInvariants.stakingRequirementAtomic, true);
  assert.equal(rewardInvariants.node.expectedStatus, 'active');
});

test('registration payloads include VLESS and push metadata boundaries', () => {
  const registration = registrationPayloads.nodeRegistration;
  assert.equal(registration.transport.protocol, 'vless');
  assert.match(registration.transport.uuid, /^[0-9a-f-]{36}$/i);
  assert.equal(registration.transport.port > 0 && registration.transport.port <= 65535, true);
  assert.match(registration.blsPublicKey.x, /^0x[0-9a-f]+$/i);
  assert.match(registration.blsPublicKey.y, /^0x[0-9a-f]+$/i);

  const push = registrationPayloads.pushSubscription;
  assert.deepEqual(push.namespaces, [...push.namespaces].sort((a, b) => a - b));
  assert.equal(push.pubkey.startsWith('05'), true);
  assert.equal(push.enc_key.length, 64);
});

