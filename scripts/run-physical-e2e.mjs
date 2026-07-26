import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPhysicalE2E, validateConfig } from '../src/physical-e2e.mjs';

const configPath = process.argv[2] && resolve(process.argv[2]);
if (!configPath) throw new Error('Usage: node scripts/run-physical-e2e.mjs <physical-e2e.json>');

const config = JSON.parse(await readFile(configPath, 'utf8'));
validateConfig(config);
const artifactsDir = resolve(process.env.DEEP_ARTIFACT_DIR ?? 'artifacts/physical-e2e');
const evidence = await runPhysicalE2E(config, { artifactsDir });
console.log(`physical Deep E2E ${evidence.status}; evidence: ${resolve(artifactsDir, 'physical-deep-e2e.json')}`);
