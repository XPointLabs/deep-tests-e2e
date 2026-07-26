# Physical Deep E2E Runner

`npm run e2e:physical -- <config.json>` is a local, fail-closed evidence
runner for the physical Android client and Windows ARM64 client. It does not
read UAT configuration or secrets.

Copy [`fixtures/physical-e2e.example.json`](../fixtures/physical-e2e.example.json)
outside the repository and replace the local build paths and semantic control
IDs. Version 2 configs reject secret-looking keys, coordinates, XPath, missing
negative assertions, and incomplete endpoint pins.

## Preflight gates

The clients are not opened until all of these checks pass:

- every configured Compose service resolves to exactly one `running`,
  `healthy` container;
- every service has exactly one HTTP 200 endpoint pin with a required
  successful body marker;
- ADB reports the exact serial `192.168.1.45:36969` as `device`;
- package `network.xpoint.deep.e2e` is installed;
- local `aapt` package/version metadata and `apksigner` certificate SHA-256
  match the installed `dumpsys package` version and signing certificate;
- the Windows executable is an ARM64 PE;
- source attachment and all local inputs exist;
- the unique AppData and `Downloads` directories are canonical directories,
  not reparse points.

The Android WebDriver session is pinned to the serial, package, version code,
version name, and signing digest. Each Windows session is attached to the
top-level window of the exact spawned PID; process name and executable path
are independently checked. A cold restart must produce a distinct PID.

## Required semantic flows

Only `accessibility id` and `id` selectors are allowed.

1. Enter the unique invalid-ID marker, submit it, assert an explicit rejection,
   and assert that it is absent from contact state.
2. Capture and format-check the actual identity from each client. Add each one
   reciprocally, set unique per-run contact markers, submit, and wait for both
   contact states.
3. Enter and submit the Windows-to-Android marker, then wait for that exact
   marker on Android.
4. Enter and submit the Android-to-Windows marker, then wait for that exact
   marker on Windows.
5. Push a uniquely named source fixture to Android, send it, wait for the
   correlated filename on Windows, download it, and hash the decrypted file.
6. Delete that decrypted output, cold-stop both clients, relaunch with a
   distinct Windows PID, reopen the conversation, download the attachment
   again, and hash the newly created decrypted file.

`assertDownloadedAttachment` has no configurable path. It can only inspect the
exact per-run `AppData\Downloads\<attachmentName>` destination. The verifier
rejects source paths, paths outside the unique root, nested destinations,
symlinks, reparse redirects, and non-regular files.

## Route-correlated chaos

Chaos is disabled by default. If enabled, a semantic `captureRouteMarker`
action must read a non-empty route-node ID that exactly equals
`expectedRouteNode`. Each action must reference that captured value, target
the same route node, use the `restartComposeService` allowlisted action, and
name an explicitly allowlisted Compose service.

Artifacts contain only SHA-256 hashes of route IDs and explicitly record
`deterministicFailoverClaim: false`. Observing a route and perturbing its
service does not prove deterministic failover.

## Cleanup and evidence

Cleanup always attempts every resource independently:

- close both WebDriver sessions;
- force-stop the Android package;
- terminate the exact active Windows PID;
- remove the uniquely named Android attachment;
- remove the unique Windows AppData tree, including decrypted material.

The run can become `passed` only after every cleanup step succeeds. Evidence is
written after cleanup; failure to write evidence cannot bypass cleanup. Local
paths are represented by basename plus a path hash.

## Local command

```powershell
cd C:\Work\DeepSession\XPointLabs\deep-tests-e2e
$env:DEEP_ARTIFACT_DIR = 'C:\deep-evidence\physical'
npm run e2e:physical -- C:\private-local-config\physical-deep-e2e.json
```

Operator setup must provide healthy local Compose services, `adb`, `aapt`,
`apksigner`, and authenticated local Android/Windows Appium drivers. Replace
the example control IDs with the final MAUI `AutomationId` values before a
physical run.
