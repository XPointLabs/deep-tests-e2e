# Physical Deep Android↔Windows release harness

`npm run e2e:physical -- <config.json>` is the fail-closed physical runner for
the clean-break Deep generation. Its config and evidence contracts are
[`physical-e2e-config.v4.schema.json`](../schemas/physical-e2e-config.v4.schema.json)
and [`physical-e2e-evidence.v4.schema.json`](../schemas/physical-e2e-evidence.v4.schema.json).
The checked-in [`physical-e2e.example.json`](../fixtures/physical-e2e.example.json)
contains no credentials or recovery material. Its repeated-digit build digests
are explicit placeholders that preflight rejects; a local copy must replace
every one from the reviewed build matrix.

The harness never treats an injected adapter or fake service as release
evidence. Unit tests using injected dependencies can produce only
`test-only-passed` with `releaseEligible: false`; only the default process,
Docker, ADB and WebDriver adapters can produce `passed`.

## Preflight and bounded execution

Before either client starts, the runner requires:

- one healthy container for every service in the named local Compose project;
- one unique loopback health endpoint per service, returning HTTP 200 and exact
  matching JSON `service` plus configured `buildSha256` provenance fields;
- the pinned authorized Android device, package and explicit launcher;
- byte-matching APK version/signing provenance from `aapt`, `apksigner` and the
  installed package;
- an ARM64 Windows PE and an exact spawned PID/name/path/top-level-window
  binding;
- a canonical, non-reparse, uniquely created Windows E2E AppData directory.

Config v4 bounds the whole run, its independent cleanup window, every UI
timeout, flow/action counts, offline probe duration, long-offline rehearsal
duration and final evidence bytes.
Only semantic `id` and `accessibility id` selectors are accepted. Unknown
fields/actions, XPath, coordinates, non-loopback endpoints, secret-looking
keys and legacy identity selectors fail before UI launch.

After online provenance is captured, all configured services are stopped and
every endpoint must become unreachable. Only then are Android and Windows
launched for offline onboarding. A reachable HTTP response, including 503,
fails the offline proof.

## Required ordered flows

The exact v4 flow set is:

1. `offlineAccountCreate`: create the isolated Windows account while all
   services are unreachable; `PhysicalE2E.NetworkCallbackCount` must remain
   exactly `0` before and after creation. Capture a canonical permanent Deep ID
   and hold the 24-word recovery phrase only in runner memory.
2. `offlineAccountRestore`: delete only the sentinel-protected generated
   Windows profile, relaunch offline, restore from the in-memory phrase, prove
   the same Deep ID and callback count `0`, then restart and re-health every
   service.
3. `reciprocalContact`: capture the existing Android Deep ID; import each
   unrelated canonical Deep ID on the opposite client and prove both exact
   `Pending → Verified` transitions.
4. `windowsToAndroidText`: send one uniquely correlated 1:1 message and observe
   it once on Android.
5. `androidToWindowsText`: repeat in the opposite direction.
6. `smallClosedGroup`: Windows creates a named closed group and invites the
   Android Deep ID; Android accepts; both become `Active`; a group message is
   delivered; Windows removes Android; both observe `Removed`; a post-removal
   marker must remain absent on Android for the configured stability window.
7. `coldRestartVerify`: cold-restart both apps with distinct Windows PIDs and
   prove both Deep IDs, reciprocal verified contacts, direct history and the
   removed-member state survived.
8. `longOfflineRetry`: stop and prove all services unreachable, queue a new 1:1
   message, restart both clients, hold the bounded offline window, restore and
   re-prove every service, then observe automatic delivery and exact
   `Delivered` state without a manual retry action.

Both clients must expose one canonical 90-character lowercase permanent Deep
ID through `Settings.DeepId` and `NewConversation.DeepId`. Historical `05…`
identifiers and `SessionId` selectors are rejected. State automation elements
must expose the canonical values `Pending`, `Verified`, `Active`, `Removed`,
`Queued` and `Delivered`, independent of localized display text.

## Evidence and cleanup

Evidence contains build/service/process provenance, SHA-256 correlation values,
ordered action purposes, offline/restoration durations and cleanup outcomes.
It never contains recovery words, plaintext Deep IDs, aliases, message bodies
or raw selectors/paths. Evidence is validated and size-bounded before writing.

The full release gate verifies the artifact again against its exact private
config, including ordered service names, URL digests and expected build hashes:

```powershell
$env:DEEP_PHYSICAL_CONFIG_PATH = 'C:\private-local-config\physical-deep-e2e.json'
$env:DEEP_PHYSICAL_EVIDENCE_PATH = 'C:\deep-evidence\physical\physical-deep-e2e.json'
npm run ci:full
```

Cleanup independently closes both drivers, force-stops Android, terminates only
the exact spawned Windows PID, restores any services left stopped, validates
the isolation sentinel and removes only the generated AppData directory. Any
cleanup failure makes the run fail.

## Physical prerequisites

The physical lane remains unexecuted until all of these exist together:

- independently built Android ARM64 and Windows ARM64 clean-break apps;
- the exact v4 automation selectors and canonical state text in those apps,
  including `PhysicalE2E.NetworkCallbackCount`;
- an Android profile unrelated to the freshly created Windows profile;
- reviewed real router, directory, mailbox/invite and group-control services
  exposing exact health provenance in one local Compose project;
- ADB, `aapt`, `apksigner`, Appium UiAutomator2 and a Windows
  Appium/WinAppDriver-compatible endpoint that echo all provenance
  capabilities.

Copy the example outside the repository and replace only local build paths and
the reviewed service names/ports:

```powershell
cd C:\Work\DeepSession\XPointLabs\deep-tests-e2e
$env:DEEP_ARTIFACT_DIR = 'C:\deep-evidence\physical'
npm run e2e:physical -- C:\private-local-config\physical-deep-e2e.json
```
