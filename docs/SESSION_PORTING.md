# Session Porting Spec - E2E Fixtures And Flows

Last updated: 2026-06-10.

## Scope

This document defines how Session-derived service and client behavior becomes Deep e2e evidence. It applies to fixtures, compatibility tests, smoke/full flows, and load/restart evidence consumed by DevOps.

## Contract Sources

Use local upstream references when available:

- `../source/session-storage-server`
- `../source/session-file-server`
- `../source/session-push-notification-server`
- `../source/session-android`
- `../source/session-ios`
- `../source/session-desktop`

When an upstream checkout is unavailable, treat existing checked-in fixtures as the temporary baseline and document the gap.

## Porting Workflow

1. Extract the externally visible contract: route, method, payload, auth/signature, status, response shape, persistence side effects.
2. Add or update a fixture in `src/fixtures.mjs` or a dedicated test fixture file.
3. Add compatibility tests under `test/compat` for isolated contract behavior.
4. Add e2e coverage under `test/e2e` only when multiple services must interact.
5. Expose runtime stats assertions when DevOps gates need evidence.
6. Document deviations here.

## Current Coverage Areas

- Storage: signed store/retrieve lifecycle, expiry, deletion, subaccounts, sequence/batch, revocation.
- File/avatar: upload/download/info/extend, idempotence, avatar state.
- Calls: runtime health/stats coverage when a call signaling endpoint is configured.
- Push: subscribe/resubscribe/unsubscribe, signature fields, provider delivery inventory, storage-triggered notify.
- Registry/router: node registration, VLESS metadata, bootstrap/status/RPC.
- Staking/contracts: reward/stake projection and devnet health.
- Backend external load: storage/file/push deltas and timing summaries.

## Fixture Rules

- Fixtures must be deterministic and readable.
- Keep generated identities local to tests unless the fixture intentionally models a stable vector.
- Preserve upstream status/error semantics even if implementation internals differ.
- Keep large or sensitive binary payloads out of the repo unless explicitly required and sanitized.

## Accepted Deviations

- The e2e suite validates compatibility services and dedicated Deep services, not upstream production deployments.
- Provider canaries may use staging provider proxies as long as the evidence proves configured provider dispatch.
- Test concurrency is intentionally `1` for shared-state service flows.

## Evidence Required For A Ported Contract

- route and payload fixture,
- positive assertion,
- at least one invalid/auth/error assertion for signed contracts,
- runtime stats delta if service inventory changes,
- restart/load evidence for production cutover paths,
- link to DevOps gate if release-critical.

## Stop-The-Line Conditions

- A Session contract is represented only by a smoke happy path.
- A signed endpoint lacks invalid-signature or timestamp-window coverage.
- Provider delivery can pass when provider endpoints are not configured.
- Runtime stats are not sufficient to prove the intended service was exercised.
