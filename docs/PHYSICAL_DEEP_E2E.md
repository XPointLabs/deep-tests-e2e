# Physical Deep E2E Runner

`npm run e2e:physical -- <config.json>` is a deliberately local, fail-closed
orchestrator for a physical Android client and the Windows ARM64 client. It is
not a UAT runner and it does not read UAT secrets.

Start from [`fixtures/physical-e2e.example.json`](../fixtures/physical-e2e.example.json),
copy it outside the repository, and replace only local build paths and semantic
control identifiers. The config is rejected if it contains secret-looking keys.

The runner requires all of the following before it opens a client UI:

- a named Docker Compose project whose configured services are `running` and
  `healthy`, plus a pinned health URL and expected response for each endpoint;
- the exact Wi-Fi ADB serial `192.168.1.45:36969`, an authorized `device`
  state, and installed package `network.xpoint.deep.e2e`;
- local APK existence, SHA-256, and `aapt dump badging` package verification,
  followed by installed version-code/version-name capture;
- an existing ARM64 PE Windows executable and a newly-created, run-unique AppData root.
  The Windows process is launched with `APPDATA`, `LOCALAPPDATA`, `TEMP`, and
  `TMP` beneath that root.

The resulting `physical-deep-e2e.json` contains preflight metadata, unique
message/identity markers, step evidence, and decrypted attachment SHA-256. It
does not serialize the config, environment, driver capabilities, or secrets.

## Semantic UI contract

Every UI operation is a W3C WebDriver action on either the `android` or
`windows` target. Only `accessibility id` and `id` selectors are accepted;
XPath, image matching, and screen coordinates are rejected. This allows Appium
UiAutomator2 resource/accessibility IDs on Android and UI Automation
`AutomationId`/accessibility IDs on Windows.

The six required flows are configured as action lists:

1. invalid identity rejection;
2. reciprocal identity addition;
3. Windows-to-Android correlated text;
4. Android-to-Windows correlated text;
5. Android-to-Windows attachment plus a SHA-256 check of the decrypted Windows
   download; and
6. a cold restart of both processes followed by the same SHA-256 check.

The runner validates that text is injected at the sender and read back on the
other platform. It also validates that both per-run identities are used. Add
click/submit/wait controls specific to the current UI after the MAUI
`AutomationId` work lands.

## Controlled route chaos

Chaos is off by default. When enabled, `chaos.routeMarker` must be a semantic
`captureRouteMarker` action that reads visible route text and checks its
expected non-empty marker before any chaos action runs. The evidence records
the observed marker. The runner intentionally records no “deterministic
failover” result: a route observation only authorizes a route-correlated
experiment, it does not prove a deterministic failover property.

## Local command

```powershell
cd C:\Work\DeepSession\XPointLabs\deep-tests-e2e
$env:DEEP_ARTIFACT_DIR = 'C:\deep-evidence\physical'
npm run e2e:physical -- C:\private-local-config\physical-deep-e2e.json
```

Use an already authenticated local Appium/Windows UI Automation endpoint. The
runner does not start Docker, install an APK, connect ADB, or alter Android
state before preflight; those are intentional operator-owned setup actions.
