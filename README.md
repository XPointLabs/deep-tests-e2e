# Deep E2E Tests

Golden compatibility fixtures and end-to-end smoke tests for Deep.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing fixtures or test flows.
- Use [`docs/SESSION_PORTING.md`](docs/SESSION_PORTING.md) when adding Session-derived compatibility coverage.
- Keep these tests as externally visible contract evidence, not implementation-specific unit tests.

## Local

Run the complete local environment from the workspace root:

```powershell
pwsh ./deep-devops/scripts/test-env.ps1
```

To run the same suite against external storage/file/push endpoints while keeping the local router/registry/staking/contracts stack, export `DEEP_STORAGE_URL`, `DEEP_FILE_URL`, and `DEEP_PUSH_URL`, then invoke:

```powershell
pwsh ./deep-devops/scripts/test-env.ps1 -BackendMode external
```

If the test-client must use container-visible backend URLs that differ from the host diagnostics path, also export optional `DEEP_STORAGE_STATS_URL`, `DEEP_FILE_STATS_URL`, and `DEEP_PUSH_STATS_URL` so runtime snapshot gating can still probe `/stats` from the host.

For dedicated backend load evidence, run `npm run e2e:load` against a live `backend-external` profile or use `pwsh ./deep-devops/scripts/test-env.ps1 -Suite full -BackendMode external`; the external full suite now requires `backend-load-smoke.json` with non-zero storage/file/push deltas. For the local dedicated backend services, `-ManagedExternalProfile backend-external` is now the reproducible path and is the same orchestration used by CI.

Run only fixture compatibility checks:

```powershell
cd ./deep-tests-e2e
npm run fixtures:validate
npm run compat
```

## Physical Android + Windows evidence

For a local physical-client rehearsal (not UAT), see
[`docs/PHYSICAL_DEEP_E2E.md`](docs/PHYSICAL_DEEP_E2E.md). The runner starts
fail-closed against the pinned Android Wi-Fi device/package and a healthy,
named local Compose project; it writes a machine-readable evidence artifact
only after all cross-platform checks complete.

## Fixture Coverage

- message vectors from Session desktop/Appium automation flows and storage server network-test semantics
- attachment vectors from Session file server `/file` API semantics
- reward invariants from Session token contract unit tests and Deep staking projection behavior
- registration payload fixtures for VLESS metadata and push subscription payloads

Smoke e2e covers new account fixture creation, offline message storage/retrieval, attachment upload/download, group messaging, push registration/unregister via real MONITOR/UNSUBSCRIBE signatures from a generated ed25519 identity, live storage->push delivery for an active subscription, node registration with VLESS metadata, reward query, router status/RPC, and contracts devnet health. The smoke registry path uses its own node registration identity so transport-profile mutations in the full suite do not leak across tests.

Full e2e additionally exercises a real signed timestamped private-namespace storage lifecycle via a generated ed25519 identity: storage `/store`, `/retrieve` (`last_hash` and post-delete reads), `/get_expiries`, `/expire_all`, `/expire` (shared and per-message expiry arrays), `/delete`, `/delete_all`, `/revoke_subaccount`, `/revoked_subaccounts`, and `/unrevoke_subaccount`, including the unrevocable retrieve exception for namespaces `-(100n+11)`, plus storage `/sequence`, file upload idempotence, file `/extend` expiry refresh, avatar upload/update/fetch through `/avatar/{sessionId}`, push resubscribe semantics using a real signed push identity, and registry transport-profile update flow with the delivery hop enabled in the same compat stack.

The dedicated load-smoke e2e covers backend-external storage/file/push pressure on the production cutover path: signed storage burst store/retrieve plus explicit idempotent retry proof, concurrent same-content file upload retry/idempotence, concurrent same-id file `/extend` monotonicity, avatar update/fetch stats deltas, push subscribe/resubscribe plus redundant unsubscribe idempotence, and storage-triggered push delivery with `/stats` delta assertions, provider-status inventory capture, and timing summaries written to `backend-load-smoke.json`.

The compatibility contract suite (`npm run compat`) now also exercises storage subaccount authorization against the compat runtime, including read/write/delete/`any_prefix` access checks and write-only `/storage/expire` extend-only behavior.

The same compat suite now also exercises storage subaccount revocation lifecycle behavior: `/storage/revoke_subaccount`, `/storage/unrevoke_subaccount`, `/storage/revoked_subaccounts`, 50-token retention, and the unrevocable retrieve exception for namespaces `-(100n+11)`.

`ci:smoke` and `ci:full` now begin with runtime checks that validate health and operational stats endpoints (`/api/nodes/runtime`, `/api/events/stats`, and `/stats` for storage/file/push backends) before compatibility and e2e tests run. The e2e scripts also force `--test-concurrency=1` because the backend integration scenarios intentionally share stateful services.

Storage/file/calls/push dependencies in the devops stack are now provided by standalone product or compatibility service implementations (not mock-only test stubs), keeping the same API contract and test fixtures. The shared harness can also point those same fixtures at external storage/file/push/calls endpoints for cutover rehearsal without changing the tests themselves.

That external-mode cutover path is now also validated against dedicated `storage/file/calls/push` services in `deep-devops`; the service slices are served from standalone runtimes, and the same smoke/full suites still run against them without changing fixtures. `deep-devops/.github/workflows/integration.yml` now includes backend-external smoke, while `deep-devops/.github/workflows/nightly-full-e2e.yml` includes backend-external full with load evidence. Managed external full also emits `backend-restart-smoke.json`, including storage/file/avatar/push subscription, pending call-signal, and persisted push-delivery checks across a real compose restart.
