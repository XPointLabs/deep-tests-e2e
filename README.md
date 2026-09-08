# Deep E2E Tests

Black-box release contracts and bounded physical evidence for the clean-break
Deep generation.

Read [`AGENTS.md`](AGENTS.md) before changing fixtures or test flows. Tests in
this repository assert externally visible contracts and must never accept a
local fake as release evidence.

## Local contract checks

```powershell
cd C:\Work\DeepSession\XPointLabs\deep-tests-e2e
npm run fixtures:validate
npm run compat
```

These commands validate the v4 Android↔Windows config/evidence schemas,
canonical 90-character lowercase `deep1…` identity grammar, strict ordered
flow coverage, provenance boundaries, bounded evidence and secret/content
redaction. Injected unit-test adapters are permanently marked
`releaseEligible: false`.

The useful staking accounting fixture is intentionally separate:

```powershell
npm run staking:compat
```

## Physical Android↔Windows evidence

See [`docs/PHYSICAL_DEEP_E2E.md`](docs/PHYSICAL_DEEP_E2E.md). The physical
runner covers offline create and phrase restore before any client network
callback, reciprocal arbitrary Deep ID resolution with `Pending → Verified`,
1:1 text both ways, closed-group invite/accept/message/remove with removed
device exclusion, cold restart and bounded long-offline automatic retry.

```powershell
$env:DEEP_ARTIFACT_DIR = 'C:\deep-evidence\physical'
npm run e2e:physical -- C:\private-local-config\physical-deep-e2e.json
```

A physical result can be `passed` only with the built-in process/Docker/ADB/
WebDriver adapters, real independently built apps, exact service health
provenance and successful cleanup. Physical execution remains a separate UAT
gate because it requires those external artifacts and services.

`ci:full` cannot pass on contract tests alone. It additionally requires
`DEEP_PHYSICAL_CONFIG_PATH` and `DEEP_PHYSICAL_EVIDENCE_PATH`, then verifies a
release-eligible `passed` artifact against that exact v4 config and its service
build/URL pins. `ci:smoke` remains the bounded local contract lane.

## Quarantined pre-cutover fixtures

The old message, attachment, registration and service smoke/full/load files
remain in the repository only as pre-cutover reference material. They exercise
historical Session IDs and storage/file/push semantics and are excluded from
`fixtures:validate`, `compat` and `ci:smoke`; `ci:full` adds only verified
physical clean-break evidence.

If an explicit archaeology run is required, the non-release scripts are named
`legacy:compat`, `legacy:runtime:checks`, `legacy:e2e:smoke`,
`legacy:e2e:full` and `legacy:e2e:load`. Their success is never clean-break
release evidence.
