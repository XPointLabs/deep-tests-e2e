import assert from 'node:assert/strict';
import {
  attachmentVectors,
  manifest,
  messageVectors,
  registrationPayloads,
  rewardInvariants
} from '../src/fixtures.mjs';

assert.equal(manifest.schemaVersion, 1);
assert.ok(manifest.sources.length >= 10);
assert.ok(manifest.sources.every(source => /^[0-9a-f]{7,40}$/i.test(source.commit)));

assert.equal(messageVectors.kind, 'message-vectors');
assert.ok(messageVectors.vectors.length >= 2);

assert.equal(attachmentVectors.kind, 'attachment-vectors');
assert.ok(attachmentVectors.vectors.length >= 1);

assert.equal(rewardInvariants.kind, 'reward-invariants');
assert.equal(rewardInvariants.token.symbol, 'XPNT');

assert.equal(registrationPayloads.kind, 'registration-payload-fixtures');
assert.ok(registrationPayloads.accounts.alice.sessionId.startsWith('05'));
assert.equal(registrationPayloads.nodeRegistration.transport.protocol, 'vless');

console.log('fixture validation passed');

