import assert from 'node:assert/strict';
import physicalConfig from '../fixtures/physical-e2e.example.json' with { type: 'json' };
import rewardInvariants from '../fixtures/golden/reward-invariants.json' with { type: 'json' };
import configSchema from '../schemas/physical-e2e-config.v4.schema.json' with { type: 'json' };
import evidenceSchema from '../schemas/physical-e2e-evidence.v4.schema.json' with { type: 'json' };
import { CONFIG_VERSION, EVIDENCE_SCHEMA_VERSION, REQUIRED_FLOWS, validateConfig } from '../src/physical-e2e.mjs';

assert.doesNotThrow(() => validateConfig(physicalConfig));
assert.equal(configSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
assert.equal(configSchema.properties.version.const, CONFIG_VERSION);
assert.equal(configSchema.additionalProperties, false);
assert.deepEqual(configSchema.properties.flows.required, [...REQUIRED_FLOWS]);
assert.equal(evidenceSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
assert.equal(evidenceSchema.properties.schemaVersion.const, EVIDENCE_SCHEMA_VERSION);
assert.equal(evidenceSchema.properties.flows.minItems, REQUIRED_FLOWS.length);
assert.equal(evidenceSchema.properties.flows.maxItems, REQUIRED_FLOWS.length);

const releaseFixtureText = JSON.stringify({ physicalConfig, configSchema, evidenceSchema });
for (const legacy of ['Settings.SessionId', 'NewConversation.SessionId', '^05[', '/storage/', '/file']) {
  assert.equal(releaseFixtureText.includes(legacy), false, `release fixture contains retired semantics: ${legacy}`);
}

assert.equal(rewardInvariants.kind, 'reward-invariants');
assert.equal(rewardInvariants.token.symbol, 'XPNT');
assert.equal(
  rewardInvariants.expectedRewards.lifetimeRewardsAtomic - rewardInvariants.expectedRewards.claimedRewardsAtomic,
  rewardInvariants.expectedRewards.claimableRewardsAtomic
);

console.log('fixture validation passed');

