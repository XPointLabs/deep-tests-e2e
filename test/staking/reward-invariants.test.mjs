import assert from 'node:assert/strict';
import test from 'node:test';
import rewardInvariants from '../../fixtures/golden/reward-invariants.json' with { type: 'json' };

test('staking-only reward invariants preserve claimable accounting', () => {
  const expected = rewardInvariants.expectedRewards;
  assert.equal(expected.lifetimeRewardsAtomic - expected.claimedRewardsAtomic, expected.claimableRewardsAtomic);
  assert.equal(rewardInvariants.node.stakeAtomic >= rewardInvariants.stakingRequirementAtomic, true);
  assert.equal(rewardInvariants.node.expectedStatus, 'active');
  assert.equal(rewardInvariants.token.symbol, 'XPNT');
});
