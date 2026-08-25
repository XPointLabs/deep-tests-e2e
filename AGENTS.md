# Deep E2E Tests agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only black-box E2E deltas.

## Owns

- Deterministic service-boundary fixtures and their schema validation.
- Black-box HTTP/runtime smoke, full and load tests across independently built services.
- Machine-readable failure/evidence output consumed by DevOps gates.

Compose orchestration belongs in `deep-devops`. MAUI Android/Windows physical automation belongs
in `deep-client-maui/eng`; this repo may consume its sanitized result but does not simulate it.

## Repository rules

- Test public Deep-native contracts, not implementation internals or historical Session behavior.
- Every test must prove it contacted the intended real service; a local fake cannot satisfy an E2E
  or release assertion.
- Fixtures are deterministic, order-independent and safe with `--test-concurrency=1`.
- Cover a failure, replay or idempotency path for release-critical flows.
- Never weaken an assertion into a warning to accommodate temporary drift.
- Evidence is bounded, machine-readable and free of secrets, message/file contents and private IDs.
- Document required services and environment variables when coverage changes.

## Verify

```powershell
npm run fixtures:validate
npm run compat
npm run ci:smoke
```

Run `npm run ci:full` and `npm run e2e:load` for affected full/load behavior. Prefer the DevOps
`test-env.ps1` harness when Docker lifecycle and evidence capture are part of the claim.
