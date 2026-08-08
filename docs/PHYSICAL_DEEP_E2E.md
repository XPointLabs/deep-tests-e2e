# Physical Deep E2E Runner

`npm run e2e:physical -- <config.json>` is a local, fail-closed evidence runner
for the physical Android client and Windows ARM64 client. It does not read UAT
configuration or secrets.

Copy [`fixtures/physical-e2e.example.json`](../fixtures/physical-e2e.example.json)
outside the repository and replace only the local build paths, the actual
`Downloads\Deep` path, device picker selectors/label, and route binding.
Version 3 uses checked-in platform-specific selector roles. It rejects
secret-looking keys, coordinates, XPath, missing bootstrap/resend evidence,
and incomplete endpoint pins.

## Preflight gates

The clients are not opened until all of these checks pass:

- every configured Compose service resolves to exactly one `running`,
  `healthy` container;
- every service has one unique HTTP 200 endpoint whose JSON `service` field
  proves exact provenance;
- ADB reports `192.168.1.45:43337` as `device`;
- package `network.xpoint.deep.e2e` is installed and resolves to the exact
  launcher `network.xpoint.deep.DeepLauncher`;
- local `aapt` package/version metadata and `apksigner` certificate SHA-256
  match the installed `dumpsys package` values;
- the Windows executable is an ARM64 PE;
- the source attachment is a canonical regular file, not a symlink/reparse
  path, and its followed filesystem identity is captured;
- the isolated AppData directory and actual production `Downloads\Deep`
  directory are canonical directories, not reparse points;
- the exact correlated destination filename does not already exist.

The Android WebDriver session is pinned to serial, package, launcher, version,
and signing digest. Windows sessions attach to the top-level window of the
exact spawned PID after independent process name/path checks. Every restart
must produce a PID distinct from the previously active process. Android is
launched explicitly with `am start -W -n`, never an implicit launcher fallback.

## Required semantic flows

Only `accessibility id` and `id` selector maps are allowed. Actions reference a
platform role, not a copied raw selector. Purpose uniqueness and strict order
are validated before UI startup.

1. Bootstrap the isolated Windows profile through `Welcome.DisplayName` and
   `Welcome.Create`; wait for Conversations and capture its identity in
   Settings. Android must already be on the physically confirmed
   `Page.Conversations` profile; capture its existing identity without erasing
   the device profile.
2. Submit the unique invalid-ID marker, assert an explicit rejection, return to
   Conversations, and prove throughout a stability window that it is absent.
3. Add both captured identities reciprocally with unique aliases and prove both
   correlated conversation rows.
4. Send the Windows-to-Android marker and prove the unique matching Android
   message body.
5. Send the Android-to-Windows marker and prove the unique matching Windows
   message body.
6. Pick and send the uniquely named Android fixture; select the exact matching
   Windows attachment, save it, and hash the decrypted file.
7. Delete that output, cold-restart both clients, reopen the correlated Windows
   conversation, save again, and hash the newly created file.
8. Capture the routed node, stop only its bound Compose service, send a unique
   message to a proven Failed (`!`) state, restart both clients, restore health,
   click manual retry once, and prove delivery on Android.
9. Repeat with a second unique message but never click retry; prove automatic
   post-restart delivery on Android. The lane fails closed if the product does
   not implement automatic retry.

`assertDownloadedAttachment` has no configurable file path. It inspects only
`Downloads\Deep\<attachmentName>`. Verification rejects paths outside that
root, nested destinations, symlinks, reparse redirects, non-regular files, the
source referent, and hard links to its filesystem identity. Deletion between
phases must be observed specifically as `ENOENT`.

## Platform selector and navigation contract

Android roles use exact resource IDs such as
`network.xpoint.deep.e2e:id/Page.Conversations`; Windows roles use exact MAUI
AutomationIds. Repeated rows, bodies, statuses, retries, and attachment labels
are queried as collections. Marker-bearing operations require exactly one
matching element; the runner never accepts the first result.

- Android: `Conversations.NewConversationTop` ->
  `StartConversation.NewMessage` -> `NewConversation.*`; Settings opens through
  `Conversations.ProfileSettings`; direct chat uses `Chat.Draft`/`Chat.Send`.
- Windows: `Conversations.NewConversation` ->
  `StartConversation.NewMessage` -> `NewConversation.*`; Settings opens through
  `DesktopWorkspace.ProfileSettings`; direct chat uses
  `DesktopWorkspace.DirectDraft`/`DesktopWorkspace.DirectSend`.
- The Android system picker is OS/device-owned. Its exact resource IDs and
  localized Downloads label are local prerequisites, not MAUI IDs.

## Route-correlated resend gate

Chaos is mandatory because both resend flows are mandatory. The captured route
must equal `expectedRouteNode`, and `routeBindings` must map it to exactly one
configured Compose service. Service restoration and endpoint re-health are
mandatory, including cleanup after a mid-flow failure.

The current MAUI tree does not yet expose raw `TransportRouteNode.RouterId`.
The fixture intentionally references `PhysicalE2E.RouteNodeMarker` and fails
closed until a physical-E2E debug build exposes one visible, unique text element
with that AutomationId. Its text must be the raw RouterId; role/country display
text is not accepted, and production builds must omit the marker.

The current repeated `Conversations.ConversationRow` and
`DesktopWorkspace.ConversationRow` controls also expose the fixed accessible
description `Диалог`, not their bound title. To keep navigation correlated when
the Android profile already contains contacts, each clickable row must expose
its bound `ConversationListItem.Title` as its accessible Name/Description. A
first-row fallback is intentionally forbidden.

Artifacts store route hashes and explicitly set
`deterministicFailoverClaim: false`. Observing a route and perturbing its
service does not prove deterministic failover.

## Cleanup and evidence

Cleanup always attempts every resource independently:

- close both WebDriver sessions;
- force-stop Android and terminate the exact active Windows PID;
- remove the uniquely named Android attachment;
- restore the routed Compose service if failure left it stopped;
- delete only the exact correlated file from production `Downloads\Deep`;
- remove the isolated Windows AppData tree.

The run becomes `passed` only after every cleanup step succeeds. Evidence is
written after cleanup. Local paths are represented by basename and path hash.

## Local prerequisites and command

Operator setup must provide Node.js 24+, healthy local Compose services, an
unlocked/authorized Wi-Fi ADB device, `adb`, `aapt`, `apksigner`, Appium
UiAutomator2, and an interactive ARM64 Windows session with a Windows
Appium/WinAppDriver-compatible endpoint. Drivers must preserve and echo the
runner's `deep:*` provenance capabilities; there is no unverified fallback. If
both drivers cannot share port 4723, configure separate URLs. The source
fixture must be an absolute canonical regular file.

```powershell
cd C:\Work\DeepSession\XPointLabs\deep-tests-e2e
$env:DEEP_ARTIFACT_DIR = 'C:\deep-evidence\physical'
npm run e2e:physical -- C:\private-local-config\physical-deep-e2e.json
```
