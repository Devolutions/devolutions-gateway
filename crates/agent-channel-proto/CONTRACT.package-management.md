# Package management contract

This contract defines the package-management interface between the Agent and DVLS, with UniGetUI and the package broker participating in operation execution.
The provisional decisions below are proposals and are not normative until confirmed.
`channel.proto` defines the Agent-to-Authority package-management messages.
The UniGetUI IPC and broker request details below describe cross-component behavior, not additional protobuf messages.

<a id="definitions"></a>
## Definitions

- **Authority**: DVLS, which sends package-management requests and stores reported inventory.
- **Agent**: Devolutions Agent, which discovers UniGetUI instances, routes requests and reports results.
- **Broker**: the Agent package broker, which validates authorization tokens and executes operations.
- **Instance**: one running UniGetUI process and its IPC endpoint.
- **Target user SID**: the Windows user SID whose session supplies the UniGetUI instance for an operation.
- **Scope**: proven user or machine installation ownership, or unknown when ownership cannot be established.

<a id="channel"></a>
## Channel

The Agent and Authority exchange package-management requests and reports on the Agent Identity stream.
The package-management payloads use their own namespace inside `agent-channel-proto` and do not require a separate NuGet package.
Each report correlates with the request that caused it.
Inventory, install, update and uninstall all use UniGetUI IPC, and package writes do not go directly to WinGet.
UniGetUI runs unelevated in the target user's session.
The Authority-facing target is an opaque Agent-issued user UUID, not a platform SID.
The following table describes the Agent-to-Authority messages.
The extension framing and any UniGetUI-to-Broker request details not specified below remain provisional.

| Message | Direction | Fields |
| --- | --- | --- |
| `DiscoverUniGetUiInstances` | Authority to Agent | none |
| `UniGetUiInstances` | Agent to Authority | `instances`, `registry_epoch` |
| `UniGetUiInstancesUnavailable` | Agent to Authority | `reason` |
| `UniGetUiInstance` | Agent to Authority | `user_uuid`, `display_name`, `session_id`, `signature_verified` |
| `SyncInventory` | Authority to Agent | `target_user_uuid`, `registry_epoch` |
| `InventoryReport` | Agent to Authority | `report_id`, `last`, `target_user_uuid`, `registry_epoch`, `page_index`, `page_count`, `scan_completed_at`, `update_scan_completed_at`, `packages`, `managers`, `sources` |
| `InventoryUnavailable` | Agent to Authority | `target_user_uuid`, `registry_epoch`, `reason` |
| `InstalledPackage` | Agent to Authority | `manager`, `source`, `source_name`, `id`, `name`, `version`, `available_version`, `scope`, `reported_scope` |
| `PackageOperationRequest` | Authority to Agent | `operation_id`, `type`, `manager`, `source`, `package_id`, `version`, `scope`, `target_user_uuid`, `registry_epoch`, `reported_scope` |
| `UniGetUIOperationRequest` | Agent to UniGetUI | `operation`, `grant` |
| `BrokerOperationRequest` | UniGetUI to Broker | `operation`, `grant` |
| `PackageOperationResult` | Agent to Authority | `operation_id`, `success`, `error`, `status`, `execution_started` |

User UUIDs and registry epochs are non-nil UUIDs encoded as lowercase hyphenated strings.
The new fields use the following protobuf numbers; the former SID field numbers and names are reserved.

| Message | User UUID field | Registry epoch field |
| --- | --- | --- |
| `UniGetUiInstances` | — | `registry_epoch` (2) |
| `UniGetUiInstance` | `user_uuid` (5) | — |
| `SyncInventory` | `target_user_uuid` (2) | `registry_epoch` (3) |
| `InventoryReport` | `target_user_uuid` (9) | `registry_epoch` (10) |
| `InventoryUnavailable` | `target_user_uuid` (3) | `registry_epoch` (4) |
| `PackageOperationRequest` | `target_user_uuid` (9) | `registry_epoch` (10) |

`UniGetUiInstance.user_sid` (1), `SyncInventory.target_user_sid` (1), `InventoryReport.target_user_sid` (6), `InventoryUnavailable.target_user_sid` (1) and `PackageOperationRequest.target_user_sid` (7) are reserved.
Agent and Authority versions that do not both enforce the UUID and epoch fields are unsupported.

Remote inventory and remote writes have separate Agent configuration switches, both enabled by default.
They are `DeviceManagement.RemoteInventoryEnabled` and `DeviceManagement.RemoteWritesEnabled` in the Agent configuration.
When inventory is disabled, the Agent reports `SAFE_ENDPOINT_UNAVAILABLE` without querying UniGetUI.
When writes are disabled, the Agent rejects a new operation without contacting UniGetUI or issuing a grant.
Previously journaled operation IDs retain their recorded status.
Neither switch disables discovery.

<a id="instances"></a>
## Instance discovery and targeting

The Agent reports discovered, unelevated UniGetUI instances in logged-on user sessions with their user UUID, session ID, display name and signature-verification result.
The Agent answers each `DiscoverUniGetUiInstances` request with one report, `UniGetUiInstances` or `UniGetUiInstancesUnavailable`, never with a partial list.
It sends `UniGetUiInstances` only when it can report the complete registered set.
That list replaces the previous instance set; an empty list means no instance.
Otherwise, including when the whole channel envelope would exceed its size limit, the Agent sends `UniGetUiInstancesUnavailable`.
It is `DeviceManagementReport.unigetui_instances_unavailable` field 7, with `reason` field 1: `UNSPECIFIED` (0), `BUSY` (1), `COLLECTION_FAILED` (2) or `TOO_LARGE` (3).
The Authority maps `UNSPECIFIED` and unrecognized reasons to generic unavailability, and an unavailable report preserves the previous instance set.
The response envelope's `correlation_id` is the request UUID.
The Authority records the active epoch and its revision when it dispatches a discovery request.
It applies either report only to its current pending discovery request for that Agent Identity when the active epoch and revision still match the recorded values, and ignores stale, unsolicited and duplicate reports.
It uses those recorded values for a per-Agent compare-and-swap when changing the active registry epoch, incrementing the revision on each change.
After a channel reconnect, the receiving Authority node disables targeting until it accepts a fresh complete discovery report from that connection.
Pending requests on different Authority nodes are not globally fenced.
An older stream can issue a new discovery, reinstate an earlier epoch, remove newer observations and enable targeting of its own instances.
Reports can be lost when a stream closes, so the Authority times out discovery requests without a report.
The Agent and Authority must both understand the unavailable report; mixed versions are unsupported.
The Agent obtains the SID and session ID from the authenticated connection and verifies the endpoint-owning process as described in `CONTRACT.package-management.md §registration`.
It verifies the executable signature before reporting an instance or accepting it as a target.
The Authority stores and selects the target user UUID and may display a safe user name and session ID.
Every package operation includes a target user UUID, including a machine-scope operation.
The Agent maps a known UUID to a user SID and resolves a live instance for that user when it executes the request.
It rejects a missing, malformed, nil or unknown user UUID, or a request for a different registry epoch, before Broker execution.
While its operation journal retains the operation ID, the Agent sends the write at most once to one resolved instance and does not retry it against that or another endpoint.
Inventory covers the package managers and scopes exposed by UniGetUI.
Remote writes are limited to operations supported by the existing package broker and fail closed when unsupported.
Remote writes never fall back to local package execution.

The Agent persists its SID-to-UUID mapping across restarts in state whose DACL allows only SYSTEM to read or write it.
Each newly mapped user receives a random UUIDv4, and the Agent never reassigns a known UUID to a different user.
The mapping store has its own random UUIDv4 registry epoch, created with the store.
Discovery reports that epoch, and inventory and operation requests carry the epoch in which their target was discovered.
Only a complete, current discovery report can establish or change the Authority's active epoch for an Agent Identity.
When the active epoch changes, the Authority atomically removes that Agent's observations, sync state and instance rows from the previous epoch and replaces the instance set, while retaining operation and journal evidence.
An unavailable discovery report does not change the active epoch.
Within an unchanged epoch, an absent user remains historical and discovery absence does not prove its observations were removed.
Restoring an older mapping store with the same epoch can lose mappings without a detectable epoch change; the Agent still rejects unknown UUIDs rather than remapping them.

<a id="registration"></a>
## UniGetUI registration

### Endpoint

UniGetUI connects to `\\.\pipe\Devolutions.Now.PackageBroker.Registration.v1`, served by the Broker inside the `DevolutionsAgent` service.
It is separate from the Broker execution pipe, which serves one HTTP request per connection from a small shared pool, so held connections would starve it.
Grant execution stays on the Broker execution pipe.
The Agent creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`; if that fails, registration is unavailable and discovery reports `COLLECTION_FAILED`.
The pipe rejects remote clients, and its DACL denies NETWORK access while granting SYSTEM and Administrators full control and `BUILTIN\Users` only `FILE_GENERIC_READ` and `FILE_WRITE_DATA`, never `FILE_APPEND_DATA`, which for pipes is `FILE_CREATE_PIPE_INSTANCE`.
UniGetUI opens the pipe with `GENERIC_READ | FILE_WRITE_DATA` and `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`.

### Authentication

Before sending any frame, UniGetUI authenticates the server.
After connecting, it obtains the server process ID with `GetNamedPipeServerProcessId` and the server session ID with `GetNamedPipeServerSessionId`.
It then queries the `DevolutionsAgent` service with `QueryServiceStatusEx` and accepts the server only when the service is running, its process ID equals the server process ID, and the server session ID is 0.
The service name is fixed in UniGetUI and never taken from the server.
UniGetUI does not open the server process, because a standard user cannot obtain the process access needed to pin a SYSTEM service process.
On any failure, UniGetUI closes the connection without sending data and retries under the reconnect rules.
UniGetUI applies the same check to every Broker execution pipe connection before writing to it.
On the execution pipe, a failed check is a transport failure that is never retried on another route; after the request was sent, the outcome is `UNKNOWN`.
The issuing Broker keeps grants in memory, and a grant becomes invalid when that Broker instance stops.
The grant client applies the same server check to the event connection and requires its server PID to match the execution connection; an event authentication failure after submission is `UNKNOWN`.
Same-user code can duplicate UniGetUI's pipe handles, so these checks do not guarantee process-exclusive output confidentiality.
The Agent obtains the connected process ID with `GetNamedPipeClientProcessId`, opens the process immediately and retains that handle for the connection.
It reads only the bounded `Hello` before authenticating the client, and sends no response until authentication succeeds.
The Agent impersonates the named-pipe client, reads its token SID and session ID, checks that the impersonation level permits identification, and reverts impersonation.
It compares that SID and session ID with the retained process token before using them.
It accepts the client only when the retained process image is a signature-verified `UniGetUI.exe`, the token is not elevated, and the session is a logged-on user session.
The executable and its ancestor directories must pass the Broker's trusted-writer checks, so UniGetUI must be installed for all users in an administrator-protected directory.
The Agent logs the reason when those checks reject a registration.
Signature verification uses the retained image file and rejects a different signed file substituted at its path.
Values that UniGetUI reports about itself are never used for identity or targeting.
The client process ID identifies only the process that connected; same-user code may be able to duplicate the connected handle and read or write later frames, including `Request` arguments that carry a grant.
Such a process may redeem a grant only for its bound SID and effectful payload.
An operation response on this connection alone does not establish the operation's outcome.
Registration does not prove which process sends a later frame.

### Framing

Each frame is a 4-byte unsigned little-endian length `N`, followed by `N` bytes of a UTF-8 JSON object.
`N` is 1 to 1,048,576; a frame outside that range, invalid JSON, a missing `kind` or an unknown `kind` closes the connection.
Unknown members are ignored.
All identifiers are lowercase hyphenated UUIDs.

| `kind` | Direction | Members |
| --- | --- | --- |
| `Hello` | UniGetUI to Agent | `protocolVersion` (integer), `clientVersion` (string, at most 128 characters) |
| `Welcome` | Agent to UniGetUI | `protocolVersion` (integer) |
| `Request` | Agent to UniGetUI | `id`, `command` (string), `arguments` (object) |
| `Response` | UniGetUI to Agent | `id`, `ok` (boolean), `result` (any JSON value when `ok`), `error` (object when not `ok`) |
| `Ping` | either | none |
| `Pong` | either | none |

UniGetUI sends `Hello` with `protocolVersion` 1 within 10 seconds of connecting.
The Agent closes the connection if it has not received the complete `Hello` within 10 seconds of connection.
The Agent answers with `Welcome` after accepting the client identity, or closes the connection, including for any other `protocolVersion`.
The instance is registered from `Welcome` until the connection closes.
No `Request` is sent before `Welcome`.

### Commands

UniGetUI answers each `Request` with exactly one `Response` carrying the same `id`.
Responses may arrive in any order, and the Agent has at most 8 outstanding requests per connection.
`error` has a `code` string and a `message` string of at most 2,048 characters with no credentials, local paths or captured output.
`code` is `UnsupportedCommand`, `InvalidArguments`, `Busy` or `Failed`.

| `command` | `arguments` | `result` |
| --- | --- | --- |
| `ListInstalledPackages` | none | the JSON array served by UniGetUI IPC `GET /uniget/v1/packages/installed` |
| `ListPackageUpdates` | none | the JSON array served by `GET /uniget/v1/packages/updates` |
| `ListManagers` | none | the JSON array served by `GET /uniget/v1/managers` |
| `ListSources` | none | the JSON array served by `GET /uniget/v1/sources` |
| `GetInventorySnapshot` | none | `{ "completedAt": string, "updateCompletedAt": string or null, "managers": array, "sources": array, "installedPackages": array, "updates": array }` |
| `GetPackageVersions` | `manager`, `sourceName`, `packageId` | `{ "versions": [string] }` |
| `ExecutePackageOperation` | `operationId`, `brokerRequestId`, `operation`, `manager`, `sourceName`, `packageId`, `version`, `scope`, `reportedScope`, `grant` | `{ "status": "Succeeded" \| "Failed" \| "Unknown", "error": string }` |

The `GetInventorySnapshot` arrays use the item shapes of the corresponding list commands, subject to the source-safety rules in `CONTRACT.package-management.md §inventory`.
An installed-package item may omit `systemRestartPending` when no value was captured in memory.
`GetInventorySnapshot` returns timestamps as RFC 3339 UTC strings.
`updateCompletedAt` may be omitted or null when no complete update scan is available; in that case, `updates` is empty.
When UniGetUI cannot produce the installed snapshot required by `CONTRACT.package-management.md §inventory`, it answers `Failed` or `UnsupportedCommand` without a snapshot.
`operation` is `Install`, `Update` or `Uninstall`; `version` is empty when not requested.
`scope` is the administrator's requested execution scope, `User` or `Machine`.
`sourceName` is empty for uninstall and may be empty for update, as specified in `CONTRACT.package-management.md §operations`.
For update and uninstall, `reportedScope` is the selected inventory row's `reported_scope`, including an empty string when no scope was reported.
For install, `reportedScope` is omitted.
UniGetUI submits `ExecutePackageOperation` to the Broker with the grant under `CONTRACT.package-management.md §operations` and answers when the outcome is known.
`Unknown` means UniGetUI cannot establish the outcome; `error` is empty unless `status` is `Failed`.
A rejected or unanswered `ExecutePackageOperation`, or one whose connection closes first, is reported to the Authority as `UNKNOWN` unless trusted Broker evidence establishes the outcome.
While its operation journal retains the operation ID, the Agent never resends it on this or another connection.

### Source identity

Every package and update entry carries `source`, a display label, and `sourceName`, the canonical Broker `Source.Name`.
`sourceName` is empty when the canonical name is unknown, ambiguous within the manager, or unsafe to report.
There is no separate opaque source reference.
`GetPackageVersions` and an install require a nonempty `sourceName`.
When a request names a source, UniGetUI resolves it by ordinal comparison against the manager's source names and rejects the request with `InvalidArguments` when no source or more than one matches.
Update and uninstall do not require proof of the installed package's original source.
UniGetUI never substitutes another source or the display label.

### Liveness and duplicates

Either side sends `Ping` after 30 seconds without sending a frame and answers every `Ping` with `Pong`.
Either side closes the connection after 90 seconds without receiving a frame.
UniGetUI keeps one registration connection per process.
After a close or failed attempt, it reconnects with exponential backoff from 1 to 60 seconds with random jitter, and authenticates the server and sends `Hello` again.
When a process opens a new connection, the Agent closes its older one.
Several processes may register for the same user SID and session.
`UniGetUiInstances` lists one entry per registered user SID and session, and is complete by construction because the registered set is the Agent's own state.
The Agent accepts at most 4 connections per user SID and 64 in total, and closes excess connections after identifying the client.

<a id="inventory"></a>
## Inventory

Each package entry contains its manager, source, package ID, name, installed version, available version, ownership scope and reported scope.
`source` is a display label; `source_name` is the canonical Broker `Source.Name` or empty when that identity cannot be safely reported.
UniGetUI supplies the canonical name as `sourceName`; the Agent does not derive it from the display label.
Source names, URLs and labels containing credentials or local paths are not sent to the Authority.
An inventory response copies UniGetUI's last completed installed-package scan, which may be stale.
An inventory request does not start a package-manager scan, launch a package manager, change its state or log raw source details.
UniGetUI does not use unclassified local tasks unless their isolation is established.
It may copy already-finished local scan values without invoking, joining or inspecting those tasks during the request.
When no endpoint can satisfy those requirements, it reports inventory unavailable without running the unsafe path.
The installed scan covers every manager reported as both enabled and installed for that scan; disabled and uninstalled managers do not require a scan.
When no completed installed scan exists, its completion time is unavailable, any required manager is unready, its scan failed, or UniGetUI cannot establish that distinct reported scopes survived the scan, it reports inventory unavailable without sending a partial or empty replacement snapshot.
The installed list is a consistent copy of that completed scan.
Safe source information may be omitted when unavailable; an omitted source does not prove that the source is absent.
Update information is advisory and may come from an independently completed update scan.
When no complete update scan is available, `available_version` is empty for every package.
The Authority does not treat an available version as proof or authorization.
Every inventory request includes the target user UUID, as do install, update and uninstall requests.
The ownership `scope` is `USER`, `MACHINE` or `UNKNOWN`.
The Agent reports `UNKNOWN` for every installation.
`reported_scope` preserves UniGetUI's raw `reportedScope` value separately from ownership.
When `reportedScope` is null or absent, `reported_scope` is empty.
UniGetUI aliases `Global` to `Machine` and `Local` to `User`, but those labels do not establish ownership across managers.
The Authority does not use `reported_scope` to deduplicate machine-wide installations or authorize machine-wide changes.
The scope-label definitions are in [UniGetUI package scope aliases].
For each Agent Identity and target user UUID, the Authority transactionally allocates a durable generation and records the identity, request UUID, target user UUID, registry epoch, epoch revision and generation as pending before enqueueing a sync request.
Every retry after a timeout uses a new request UUID and generation.
The Agent sets the response envelope's `correlation_id` to the request UUID, including after a stream reconnect.
Each page and unavailable response echoes the requested target user UUID and registry epoch.
Reports can be lost when a stream closes, so the Authority times out requests without a terminal outcome.
The Authority accepts a report only when its authenticated Agent Identity and correlation UUID match a pending request, its target user UUID and epoch match that request, and the active epoch and revision still match.
It ignores stale, unsolicited, mismatched and already completed reports without changing inventory or newer requests.

Each collection has a nonempty `report_id` identifying the snapshot independently of the request UUID.
All pages of that collection carry the same `report_id` and `page_count`.
Only page 0 carries the `managers` and `sources` lists; later pages leave both lists empty.
`scan_completed_at` is `InventoryReport` field 11, a `google.protobuf.Timestamp` that is present and valid on every page.
It is the completion time of the copied installed scan, not the time the Agent reads or sends the snapshot.
`update_scan_completed_at` is `InventoryReport` field 12, an optional `google.protobuf.Timestamp` containing the completion time of the update scan.
It is present and valid on every page when the response uses a complete update scan, and absent on every page otherwise.
The Agent carries both completion times from UniGetUI unchanged, and their presence and values are identical on every page of the collection.
The Authority derives each scan's age from its timestamp, not from the time of upload or the last successful sync.
If a timestamp is in the Authority's future, the Authority reports that scan's age as unknown.
`page_index` and `page_count` are `InventoryReport` fields 7 and 8, respectively.
`page_count` is at least one, including for an empty inventory, and `page_index` is zero-based and less than `page_count`.
`last` is true exactly when `page_index` is the final index.
The Authority stages at most one collection for a request, bounds its staged page count and size, accepts identical duplicate pages and rejects conflicting duplicates or inconsistent scan timestamps.
It atomically replaces observations for that Agent Identity and target user and updates that target's last-successful sync only after all indexes for that collection are present and the pending request, generation, active epoch and epoch revision still match.
When staging is lost after restart or failover, the Authority abandons the incomplete attempt, ignores later pages from it and preserves the last completed inventory.

The Agent sends `InventoryUnavailable` as `DeviceManagementReport.inventory_unavailable` field 6, with `target_user_uuid` field 3, `registry_epoch` field 4 and `reason` field 2.
`reason` is `UNSPECIFIED` (0), `SAFE_ENDPOINT_UNAVAILABLE` (1), `BUSY` (2) or `COLLECTION_FAILED` (3).
The Authority maps `UNSPECIFIED` and unrecognized reasons to generic unavailability, never success or authorization.
It stores or displays only an allowlisted reason or a generic label, not raw diagnostics.
An unavailable result discards only that request's staged pages and preserves the last completed inventory and last-successful sync.
The Agent and Authority must both understand unavailable reports and complete-page validation; mixed versions are unsupported.

Any refresh after a package operation uses a new `SyncInventory` request with its own correlation and generation.
Such a refresh neither determines the operation's outcome nor retries the write.
Connection activity or a last-seen timestamp is not an inventory-sync outcome.
The Authority stores observations separately for each reporting target user for every scope, including `MACHINE`.
It preserves multiple versions reported for a target and does not replace another target's observations.
The device view keeps every observation in a separate row; a count of those rows is a count of observations, not confirmed distinct installations.
Equal source names do not establish a shared feed or prove an installed package's origin.
An unmapped scope does not establish either ownership class.
Omission from a snapshot does not prove that a package was uninstalled.

<a id="operations"></a>
## Package operations

The operation type is exactly one of `install`, `update` or `uninstall`.
Remote writes allow install, update and uninstall for Broker-supported managers when they run unelevated with the target user's token.
An operation runs elevated only when its manager is WinGet and the administrator requests `Machine` execution scope.
The Agent rejects `Machine` execution scope for other managers.
When a Broker builder supports an installed-scope selector, it passes the selected row's reported scope to the manager.
WinGet instead uses the administrator's requested execution scope.
An install may replace an existing installation when the manager cannot prevent it.
The Authority-to-Agent request contains an operation ID, operation type, manager, source, package ID, requested version when applicable, scope, target user UUID, registry epoch and selected row's reported scope when applicable, but no bypass token.
An install requires a nonempty canonical Broker source name, not the inventory display label.
An update may name its current execution feed or leave the source empty to use the manager's normal default feed.
Uninstall uses no feed and carries an empty source.
For WinGet update and uninstall, the administrator selects the package by manager and package ID and chooses its execution scope independently of the row's reported scope.
For other managers, update and uninstall identify the installed package by manager, package ID and the selected inventory row's raw `reported_scope` without proving its original source.
`PackageOperationRequest.reported_scope` is optional string field 11 and is present for update and uninstall, even when empty, and absent for install.
The Authority copies that field from the selected observation without changing it.
The Agent rejects an update or uninstall when that field is absent, and forwards it to UniGetUI unchanged as `reportedScope`.
UniGetUI rejects a write targeting an existing installation when it cannot identify the authorized row.
An installation with `UNKNOWN` ownership may be updated or uninstalled unelevated.
The administrator may request an elevated WinGet update or uninstall without a claim about the row's ownership.
When the manager cannot select the authorized row by scope, UniGetUI checks its current installed list immediately before submission.
It rejects the operation unless exactly one listed installation matches the manager and package ID and that installation is the authorized row.
The installed list may omit an installation that the manager can act on, so the manager may affect another installation accessible to the target user's unelevated token.
The Agent mints an opaque, short-lived, single-use grant, also called a bypass token, held in the Broker's memory.
The grant binds the target user SID, operation type, manager, source, package ID, version, scope, requested elevation and Broker request ID.
UniGetUI sends `POST /v1/package-operations/execute-grant` over the Broker's named pipe while running unelevated as the target user.
The request uses `Content-Type: application/json`, `Accept: application/json` and exactly one `X-Devolutions-Package-Grant` header.
Before sending the grant, UniGetUI authenticates the pipe server as the live Broker service.
It uses the server authentication in `CONTRACT.package-management.md §registration`.
The Broker accepts `application/json` content types with parameters, including `charset=utf-8`; the JSON body is UTF-8.
The `Accept` value is exactly `application/json`, ignoring case and surrounding whitespace.
The grant is 1 to 2,048 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._~:-]*`.
Header names are case-insensitive; duplicate grant or `Accept` headers are rejected.
The client validates the grant before sending it and does not send it with any other Broker request.
The Broker independently validates the decoded request and the pipe caller's SID against the grant before execution, and atomically consumes a matching grant while creating its outcome record.
The Broker rejects an invalid, expired, reused or mismatched grant rather than applying local policy.
The Broker rejects missing, duplicate, invalid or unsupported grant requests before consuming a grant or starting work.
Once consumed, a grant is never restored, even if submission or response delivery fails.
The legacy `POST /v1/package-operations/execute` route rejects any request carrying the grant header.
If the grant route is unavailable, including an older Broker's 404 response, UniGetUI does not retry through the legacy route or execute locally.
The Agent, UniGetUI and Broker reject execution-affecting fields not authorized by the grant.
The Authority request does not authorize custom parameters or hooks, so remote requests carrying them are rejected.
UniGetUI's broker request builder maps source, custom parameters and pre-operation, post-operation and kill-before-operation commands into the request.
These execution-affecting fields are visible in the [UniGetUI broker request builder][UniGetUI broker request fields].

The Broker request's `Operation` must match the Authority operation type.
The Broker compares `Manager` to the authorized manager using ASCII case-insensitive comparison of the Broker enum spelling.
An alias without an agreed mapping is rejected.
`Source.Name`, `Package.Id` and a nonempty requested version are compared exactly as decoded Unicode strings, without trimming or case folding.
For an update with an empty source, `Source.Name` is empty and `Source.Url` is absent; the grant binds the choice of the manager's default feed.
For uninstall, `Source.Name` is empty and `Source.Url` is absent.
An empty requested version requires an absent Broker `Package.Version`; a nonempty requested version must not be dropped or replaced.
The Broker compares `Options.Scope` to the scope bound by the grant.
For WinGet and all installs, that scope is the administrator's requested execution scope.
For PowerShell and PowerShell 7 updates, and PowerShell 7 uninstalls, `reported_scope` selects the Broker scope: `user` or `machine` ignoring ASCII case maps to `User` or `Machine`, an empty value maps to an absent scope, and any other nonempty value is rejected.
When that scope is absent, UniGetUI applies the unique-row rule before submission.
For other updates and uninstalls, the Broker scope is `User` and UniGetUI applies the unique-row rule.
The Broker rejects any `Source.Url` the grant does not authorize.
Matching a source name or URL in the request alone does not establish the feed the manager uses.
For install and update, the grant binds the requested source name or the choice of the target user's default feed.
Elevated operations are limited to WinGet in machine scope.
Elevated WinGet installs and updates rely on WinGet's administrator-protected source configuration; the Agent and Broker do not verify the effective feed or whether the installed WinGet version enforces that protection.
A user-scope operation that requires elevation is rejected.
It rejects `Package.Architecture`, `Package.Channel`, a custom install location, custom parameters, pre-operation or post-operation commands, and kill-before-operation entries.
It also rejects `Interactive`, `SkipHashCheck`, `PreRelease` and `UninstallPrevious` when true.
When the manager's Broker builder supports `NoUpgrade`, the Agent binds it as true and the Broker requires it for an install.
Any future execution-affecting request field must be explicitly authorized or rejected.

The Broker requires `RequestKind` to be `PackageRequest` and `RequestVersion` to be `1.0`.
The request is a JSON `PackageRequest`; unknown or duplicate fields at any object level are rejected.
The Agent generates a Broker request ID as a lowercase, hyphenated UUID and binds it to the grant.
UniGetUI preserves that ID, and the Broker rejects a different `RequestId`.
`CreatedAt` is excluded from the grant; the Broker parses it as an RFC 3339 timestamp and measures grant expiry independently of it.
The Broker's request-ID deduplication includes `CreatedAt` in its request fingerprint.
The Broker requires `Client.Transport` to be `HttpNamedPipe` and `Client.RequestedElevation` to match the grant.
It resolves `Client.EffectiveUser` to the authenticated pipe caller's SID and verifies `Client.ClientExecutablePath` against the retained process image.
Those two string values are excluded from the grant; their verified SID and image must match the authenticated process, and the SID must match the grant.
`Client.ClientVersion` is excluded from the grant and is not evidence of authorization.
The actual execution token must have exactly the elevation bound to the grant.
The Broker rejects an elevated request unless the Authority requested WinGet `Machine` execution scope.
`IncludeCommandPreview` must be false, and `CaptureOutput` must be true.
UniGetUI uses captured stdout and stderr only for local result parsing; it does not send them to the Agent or Authority or write them to logs.
For grant operations, the Broker authenticates the connecting process before sending any event frames and rejects an unverified connector without disclosing output.
This check does not prevent another process with a duplicate connected handle from reading the frames.
The grant client authenticates the event pipe as described in `CONTRACT.package-management.md §registration`.
The legacy event pipe and its user-SID access rules remain unchanged.
For grant operations, the Broker emits `Finish` only after both output readers have completed without losing data.
On a read failure, reader panic, invalid UTF-8, output overflow or other loss, it closes the event stream without `Finish`.
The grant client accepts output only after a valid `Hello` and `Finish` with no overflow or malformed frames and only when it can establish that no output was lost or injected.
The v1 event stream cannot establish completeness: another reader can consume whole frames without leaving a gap visible to the client.
An exit code or output alone does not establish a package outcome.
When the operation's verdict depends on either, the Agent reports `UNKNOWN`.

The Broker atomically records consumption of each grant in memory before starting its authorized operation.
The record is bound to the issued grant and Broker request ID and records positive evidence of process start and termination, including the exit code when available.
The Agent reads the record in process; a registration response alone cannot establish start, failure or success.
A missing, evicted or restart-lost record, a mismatch, or an outcome that cannot otherwise be verified is `UNKNOWN`.
A Broker rejection establishes only that the rejected request started no work; it does not prove that another request did not or cannot consume the same grant.
After a grant has been made available to UniGetUI, the Agent reports an unverified outcome as `UNKNOWN`, not a definite failure.
The in-memory Broker record need not survive a restart.

The .NET broker passes `--source` for install and for updates with an explicit source, which overrides NuGet configuration including Package Source Mapping.
The source override is documented in [dotnet tool install].
An operation result identifies the operation ID.
When the outcome is known, it reports success or failure with an error value on failure.
When the Agent cannot recover an operation's outcome, it reports `UNKNOWN`.
`PackageOperationResult.execution_started` is optional field 5.
The Agent sets it to true only when the Broker's in-process record proves that the operation's process started; otherwise it is absent.
The Authority treats false like absence; neither proves that the operation did not start or permits a retry.
The Agent sends an `UNKNOWN` result in `DeviceManagementReport.package_operation_unknown` with field number 5.
It sends a known result with status `UNSPECIFIED` in `DeviceManagementReport.package_operation_result` with field number 2.
The Authority does not record success or failure for a result whose field and status disagree.
The Authority ignores `success` when the status is `UNKNOWN`.
Agent and Authority versions must both understand `UNKNOWN` when they exchange operation results, including queued results after reconnect or rollback.
Mixed versions that do not satisfy this requirement are unsupported.
The Agent durably records an operation before making a grant for it available and does not submit another operation for the same operation ID.
Repeated deliveries with the same operation ID and payload return the recorded result or wait for the active operation to finish.
A repeated operation ID with a different payload is rejected.
When an existing journal's deduplication state cannot be recovered, the Agent does not treat an operation ID as new and reports `UNKNOWN`.
When the operation journal is missing, the Agent creates a new one; operations recorded only in the missing journal may execute again.
The Authority may submit a new operation ID after an `UNKNOWN` outcome only by explicitly accepting that the earlier operation may have completed.
The Broker's request-ID replay tracking does not replace this Authority operation-ID tracking.
The Broker-owned record is looked up by the issued grant and Broker request ID, not by an operation ID supplied in a registration response.
A rejection is a failure only before a grant for that operation has been made available and when the journal confirms that no earlier submission could have started.
A lost or malformed response after submission is not evidence of failure.
An unrecoverable record in an existing journal is `UNKNOWN`, and any UniGetUI recovery query uses the same resolved instance.
Local broker policy is bypassed only for a valid DVLS-authorized operation; local policy continues to govern user self-service operations.
The exact requested-version semantics for each operation are provisional as described in `CONTRACT.package-management.md §provisional-decisions`.

<a id="broker-grant-response"></a>
## Broker grant response

A successful grant execution returns HTTP 200, `Content-Type: application/json` and a JSON object with the following fields.
All fields are required and non-null unless marked optional.
Unknown or duplicate members are rejected at every object level.

| Field | Value |
| --- | --- |
| `ResponseKind` | The string `GrantExecutionResponse`. |
| `ResponseVersion` | The string `1.0`. |
| `Server` | An object with `ServerVersion`, a string of 1 to 128 characters, and `Transport`, either `HttpNamedPipe` or `HttpLoopbackSimulator`. |
| `RequestId` | The submitted Broker request ID. |
| `ReceivedAt`, `CompletedAt` | RFC 3339 UTC timestamps. |
| `Request` | An object with optional nullable `Manager` (Broker manager enum), `Source` (string), `PackageId` (package-identifier string) and `Operation` (`Install`, `Update` or `Uninstall`). |
| `Authorization` | An object containing only `Kind`, whose value is `RemoteGrant`. |
| `Operation` | An object containing `OperationId`, `Status`, `SubmittedAt` and optional nullable `EventChannel`. |
| `Operation.OperationId` | The Broker-issued operation ID. |
| `Operation.Status` | One of `Starting`, `Running`, `Canceling`, `Completed`, `Failed` or `Canceled`. |
| `Operation.SubmittedAt` | An RFC 3339 UTC timestamp. |
| `Operation.EventChannel` | When present, an object with `Kind: LocalPipe` and a `Path` string of 1 to 1,024 characters. |

`Policy`, `Decision`, `RuleId` and `Diagnostics` are forbidden, including as null values.
Responses contain no grant value, captured stdout or stderr, command preview or execution command line.
The client checks the route, HTTP status, response kind, version, authorization, echoed request ID and operation before using the response.
It does not rely on response headers, which the named-pipe transport may not expose.
If required output is unavailable, truncated, overflowed, stolen or unparseable, the result is `UNKNOWN` unless another trusted source establishes the outcome.

<a id="broker-grant-errors"></a>
## Broker grant errors

Except for an older Broker's 404, a rejected request returns an `ErrorResponse` JSON object with required `ResponseKind`, `ResponseVersion`, `Server`, `Code` and `Message` fields.
`ResponseKind` is `ErrorResponse`, `ResponseVersion` is `1.0`, and `Server` has the same shape as in `CONTRACT.package-management.md §broker-grant-response`.
`Message` is a nonempty string of at most 2,048 characters.
An optional non-null `Details` array contains objects with optional nullable `Code` and `Path` strings of at most 128 and 512 characters, respectively, and a required nonempty `Message` of at most 2,048 characters.
Unknown members, `Validation` and `Management` are rejected.
Messages and details contain no grant value, captured output, command preview or execution command line.

| Rejection | HTTP | `Code` |
| --- | --- | --- |
| Missing grant | 401 | `Unauthenticated` |
| Duplicate, malformed, empty or oversized grant header | 400 | `BadRequest` |
| Invalid, expired, consumed or mismatched grant, or unauthorized request fields | 403 | `Forbidden` |
| Any grant header on legacy `/execute` | 400 | `BadRequest` |
| Missing, duplicate or unsupported `Accept`, or unsupported request version | 400 | `BadRequest` |
| Failed pipe-client authentication | 401 | `Unauthorized` |
| Ambiguous source name or other non-policy security validation failure | 422 | `ValidationFailed` |
| Malformed request JSON or unknown request field | 400 | `BadRequest` |
| Request body over the Broker limit | 413 | `PayloadTooLarge` |
| Unsupported request content type | 415 | `UnsupportedMediaType` |
| Conflicting request or operation identity | 409 | `Conflict` |
| Grant route not implemented by a rebuilt Broker | 501 | `UnsupportedEndpoint` |
| Grant route absent on an older Broker | 404 | No structured body is required. |

Each rejection starts no work for that request.
It consumes no grant, except that a consumed grant may have been used by an earlier request.
Another concurrent request may independently consume the same grant.
No rejection establishes that the overall granted operation did not or cannot start.
When several defects apply, the Broker may return any corresponding error from the table.
An HTTP parser may close the connection or return a transport-level error for an oversized wire header.
The client does not copy an untrusted response body or grant into exceptions, traces or logs.
Other errors, disconnects, timeouts and malformed or lost responses do not prove that work did not start.
The client reports an unresolvable outcome as `UNKNOWN` and does not retry either execute route.
The shared SDK exposes `ExecuteGrant(request, grant, cancellationToken)` returning `GrantExecutionResponse`, and `OpenGrantEventChannel(response, cancellationToken)` returning an operation event channel.
Existing status and cancellation requests use the Broker-issued operation ID without a grant header.

<a id="provisional-errors"></a>
## Provisional error-code proposal

No error-code spelling or operation-status vocabulary other than `UNKNOWN` is agreed yet.
The following codes are proposals only and must not be treated as a final wire contract:

| Code | Proposed meaning |
| --- | --- |
| `INVALID_BYPASS_TOKEN` | The token is invalid, expired or already used. |
| `TARGET_USER_MISMATCH` | The named-pipe caller SID differs from the token's target user SID. |
| `NO_INSTANCE_FOR_TARGET` | No live UniGetUI instance belongs to the requested target user SID. |
| `UNIGETUI_NOT_RUNNING` | No live UniGetUI instance is available. |
| `UNSUPPORTED_MANAGER` | The package manager cannot be routed through the Broker. |
| `BROKER_ROUTE_UNAVAILABLE` | The operation cannot use the Broker route. |
| `UNAUTHORIZED_OPERATION_FIELDS` | The request contains execution-affecting fields that are not covered by its token. |

<a id="provisional-decisions"></a>
## Provisional decisions (confirm with Benoit)

The following defaults are proposals and are not normative until confirmed.
Extension framing lands after beta; beta package-management messages remain in their own namespace.
The target extension framing has the Agent advertise each extension name and supported version range in `Hello`.
The Authority opens a channel with a channel ID, extension name and version, and the Agent accepts or refuses the open.
The Agent refuses an unknown extension or one disabled by local configuration.
Data messages carry a channel ID and opaque payload, and either party may close a channel with a reason.
Package management is the first separately versioned extension.
An operation result does not itself update package records.
The requested-version field is optional where an operation does not use a version; its exact meaning for each operation is unresolved.
The endpoint errors use the proposed codes in `CONTRACT.package-management.md §provisional-errors`, and neither permits retrying the write against another endpoint.
A transport disconnection does not prove that an operation failed.
While its operation journal retains the operation ID, the Agent does not replay it automatically after disconnection or restart.

<a id="external-changes"></a>
## Required changes outside this repository

UniGetUI must expose each safely reportable canonical Broker source name as `sourceName` independently of its display label, or leave `sourceName` empty when it cannot establish that identity.
UniGetUI must pass the Agent-minted operation token through IPC to the package broker's named pipe without elevating its process.
UniGetUI must reject remote operations when broker routing is disabled, the manager is unsupported, the source cannot use broker routing, or the token does not authorize all execution-affecting fields; it must not fall back to local process execution.
This fail-closed requirement covers the existing local-fallback paths in [PackageOperations.cs][UniGetUI operation fallback].
The current fixed mapping is in [`BrokerRequestBuilder.TryMapManagerName`][UniGetUI manager mapping] at commit `da6be7b86100302a79a208e7ab4d5c6fcd695fd5`.
A Broker route for the UniGetUI `Installer` manager requires feed-item resolution, installer hash, identity and signature verification, and installed-version receipt handling; adding a manager enum value alone is insufficient.
These operations are implemented in the pinned [WinInstaller runner], [WinInstaller manager] and [Installer receipt] sources.
DVLS stores the target user UUID and package scope without storing the target user SID.
DVLS/RDM shows the Agent-reported user and session in an instance picker and sends the selected target user UUID and registry epoch with every operation.

[UniGetUI manager mapping]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.AgentBroker/BrokerRequestBuilder.cs#L201-L221
[UniGetUI operation fallback]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Operations/PackageOperations.cs#L387-L514
[UniGetUI broker request fields]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.AgentBroker/BrokerRequestBuilder.cs#L53-L84
[UniGetUI package scope aliases]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Enums/Enums.cs#L11-L18
[dotnet tool install]: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-tool-install#options
[WinInstaller runner]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/Internal/WinInstallerRunner.cs#L30-L106
[WinInstaller manager]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/WinInstaller.cs
[Installer receipt]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/Internal/InstallReceipts.cs
