import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { verifyReleaseEvidence } from '../src/physical-e2e.mjs';

const configPath = resolve(process.argv[2] ?? process.env.DEEP_PHYSICAL_CONFIG_PATH ?? '');
const evidencePath = resolve(process.argv[3] ?? process.env.DEEP_PHYSICAL_EVIDENCE_PATH ?? '');
assert.ok(process.argv[2] || process.env.DEEP_PHYSICAL_CONFIG_PATH, 'Set DEEP_PHYSICAL_CONFIG_PATH or pass the physical config path');
assert.ok(process.argv[3] || process.env.DEEP_PHYSICAL_EVIDENCE_PATH, 'Set DEEP_PHYSICAL_EVIDENCE_PATH or pass the physical evidence path');

const config = JSON.parse(await readFile(configPath, 'utf8'));
const evidenceInfo = await stat(evidencePath);
assert.ok(evidenceInfo.isFile(), 'physical evidence path must be a file');
assert.ok(evidenceInfo.size <= config.limits.maxEvidenceBytes, 'physical evidence file exceeds configured maximum bytes');
const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
verifyReleaseEvidence(config, evidence);
console.log('release-eligible physical evidence verified');
