# Agent Specification - Deep E2E Tests

Last updated: 2026-06-10.

## Mission

`deep-tests-e2e` owns externally visible compatibility fixtures and end-to-end validation for Deep. It proves that independent repos compose into a working messenger stack and that Session-derived service contracts remain stable.

## Source Of Truth

- DevOps orchestration: `../deep-devops/AGENTS.md`.
- Session porting rules: `docs/SESSION_PORTING.md`.
- Current fixtures and helper modules under `src/` and `test/`.
- Workspace entry point: `../prompts/00_Agent_Entry_Point.md`.

## Ownership Boundaries

Owned here:

- `src/fixtures.mjs`, `src/http.mjs`.
- `scripts/validate-fixtures.mjs`, `scripts/runtime-checks.mjs`.
- `test/compat/*` contract fixture tests.
- `test/e2e/*` smoke, full, and load tests.

Not owned here:

- Service implementation details.
- Compose orchestration and release gates.
- Protocol codec internals.

## Test Philosophy

Tests here should describe contracts at service boundaries. They should be stable across implementation rewrites and suitable as migration evidence from Session to Deep.

Prefer:

- black-box HTTP assertions,
- deterministic fixtures,
- explicit runtime health/stats checks,
- artifact output that DevOps gates can consume.

Avoid:

- reaching into service internals,
- test ordering that hides shared-state coupling,
- weakening assertions to accommodate temporary implementation drift.

## New Deep Solution Rules

When adding a Deep-specific flow, include:

- required services and environment variables,
- fixture setup,
- success path,
- one failure or idempotency path where relevant,
- runtime stats or artifact evidence if the flow is release-critical.

## Session Compatibility Rules

When adding Session-derived behavior:

- cite the upstream service/client source in comments or docs,
- add fixture validation if the payload shape is stable,
- preserve upstream status/error shape where externally visible,
- document accepted deviations in `docs/SESSION_PORTING.md`.

## Required Verification

Fixture-only:

```powershell
npm run fixtures:validate
npm run compat
```

Against a running stack:

```powershell
npm run ci:smoke
npm run ci:full
npm run e2e:load
```

Most agents should run these through `deep-devops/scripts/test-env.ps1` so compose state and artifacts are captured.

## Acceptance Gates

A test change is complete only when:

- fixtures are deterministic,
- tests can run with `--test-concurrency=1`,
- new env vars are documented,
- artifacts remain machine-readable JSON where consumed by DevOps,
- failure messages identify the service/contract that broke.

## Stop-The-Line Conditions

- A fixture no longer matches the documented Session-visible contract.
- A test passes without contacting the intended service.
- Shared mutable state leaks between smoke/full/load tests.
- A release-critical assertion is replaced with a warning.
- Secrets are written into test artifacts.

## Agent Workflow

1. Read this file and `docs/SESSION_PORTING.md`.
2. Identify whether the change is fixture, compat, smoke, full, or load.
3. Update fixtures before implementation-specific expectations.
4. Run focused npm scripts or the DevOps harness.
5. Update README/docs when coverage or required env vars change.
