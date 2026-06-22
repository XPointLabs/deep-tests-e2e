import { readFileSync } from 'node:fs';

function load(name) {
  const url = new URL(`../fixtures/golden/${name}`, import.meta.url);
  return JSON.parse(readFileSync(url, 'utf8').replace(/^\uFEFF/, ''));
}

export const manifest = load('manifest.json');
export const messageVectors = load('message-vectors.json');
export const attachmentVectors = load('attachment-vectors.json');
export const rewardInvariants = load('reward-invariants.json');
export const registrationPayloads = load('registration-payloads.json');

