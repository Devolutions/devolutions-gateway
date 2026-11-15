# Package management contract

This draft defines the package-management interface between the Agent and DVLS, with UniGetUI and the package broker participating in operation execution.
The provisional decisions below are proposals and are not normative until Benoit confirms them.
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
The beta wire format may change before final release, and the Authority's beta database schema includes the target user SID and package scope.
The Agent-to-Authority messages in the following table are defined in `channel.proto`.
The extension framing and any UniGetUI-to-Broker request details not specified below remain provisional.

| Message | Direction | Fields |
| --- | --- | --- |
| `DiscoverUniGetUiInstances` | Authority to Agent | none |
| `UniGetUiInstances` | Agent to Authority | `instances` |
| `UniGetUiInstancesUnavailable` | Agent to Authority | `reason` |
| `UniGetUiInstance` | Agent to Authority | `user_sid`, `display_name`, `session_id`, `signature_verified` |
| `SyncInventory` | Authority to Agent | `target_user_sid` |
| `InventoryReport` | Agent to Authority | `report_id`, `last`, `target_user_sid`, `page_index`, `page_count`, `packages`, `managers`, `sources` |
| `InventoryUnavailable` | Agent to Authority | `target_user_sid`, `reason` |
| `InstalledPackage` | Agent to Authority | `manager`, `source`, `source_name`, `id`, `name`, `version`, `available_version`, `scope`, `reported_scope` |
| `PackageOperationRequest` | Authority to Agent | `operation_id`, `type`, `manager`, `source`, `package_id`, `version`, `scope`, `target_user_sid` |
| `UniGetUIOperationRequest` | Agent to UniGetUI | `operation`, `bypass_token` |
| `BrokerOperationRequest` | UniGetUI to Broker | `operation`, `bypass_token` |
| `PackageOperationResult` | Agent to Authority | `operation_id`, `success`, `error`, `status` |

<a id="instances"></a>
## Instance discovery and targeting

The Agent reports discovered, unelevated UniGetUI instances in logged-on user sessions with their target user SID, session ID, display name and signature-verification result.
The Agent answers each `DiscoverUniGetUiInstances` request with one report, `UniGetUiInstances` or `UniGetUiInstancesUnavailable`, never with a partial list.
It sends `UniGetUiInstances` only when the scan read every registration and resolved each registered endpoint as a reported instance or as absent, not owned by `UniGetUI.exe`, or elevated.
That list replaces the previous instance set; an empty list means no instance.
Otherwise, including when the whole channel envelope would exceed its size limit, the Agent sends `UniGetUiInstancesUnavailable`.
An unresolved registration can make discovery unavailable for every user on the device.
It is `DeviceManagementReport.unigetui_instances_unavailable` field 7, with `reason` field 1: `UNSPECIFIED` (0), `BUSY` (1), `COLLECTION_FAILED` (2) or `TOO_LARGE` (3).
The Authority maps `UNSPECIFIED` and unrecognized reasons to generic unavailability, and an unavailable report preserves the previous instance set.
The response envelope's `correlation_id` is the request UUID.
The Authority applies either report only to its current pending discovery request for that Agent Identity and ignores stale, unsolicited and duplicate reports; where it keeps that request is provisional.
Reports can be lost when a stream closes, so the Authority times out discovery requests without a report.
The Agent and Authority must both understand the unavailable report; mixed versions are unsupported.
The Agent obtains the SID and session ID from the Windows token of the endpoint-owning process, not from a value reported by UniGetUI.
The Agent verifies the executable signature before reporting an instance or accepting it as a target.
The Agent allows at most identification-level impersonation when connecting to a UniGetUI named pipe.
The Authority stores and selects the target user SID, and displays it as `DOMAIN\user (session N)`.
Every package operation includes a target user SID, including a machine-scope operation.
The Agent resolves the target SID to a live instance when it executes the request.
The Agent sends the write at most once to one resolved instance and does not retry it against that or another endpoint.
When a write targets an existing installation, UniGetUI rejects it if that installation cannot be identified in the authorized scope.
Inventory covers the package managers and scopes exposed by UniGetUI.
Remote writes are limited to operations supported by the existing package broker and fail closed when unsupported.
Remote writes never fall back to local package execution.

<a id="registration"></a>
## UniGetUI registration (beta proposal)

This section is a proposal for the beta.
The device-management intent still names Agent-side endpoint discovery as the beta mechanism and registration as a future direction.
This section becomes normative when that intent is updated; it then replaces the registration-file scan and endpoint-owner rules in `CONTRACT.package-management.md §instances`, while the discovery report rules there remain.

### Endpoint

UniGetUI connects to `\\.\pipe\Devolutions.Now.PackageBroker.Registration.v1`, served by the Broker inside the `DevolutionsAgent` service.
It is separate from the Broker execution pipe, which serves one HTTP request per connection from a small shared pool, so held connections would starve it.
Grant execution stays on the Broker execution pipe.
The Agent creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`; if that fails, registration is unavailable and discovery reports `COLLECTION_FAILED`.
The pipe DACL grants SYSTEM and Administrators full control and `BUILTIN\Users` only `FILE_GENERIC_READ` and `FILE_WRITE_DATA`, never `FILE_APPEND_DATA`, which for pipes is `FILE_CREATE_PIPE_INSTANCE`.
UniGetUI opens the pipe with `GENERIC_READ | FILE_WRITE_DATA` and `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`.

### Authentication

Before sending any frame, UniGetUI authenticates the server.
After connecting, it obtains the server process ID with `GetNamedPipeServerProcessId` and the server session ID with `GetNamedPipeServerSessionId`.
It then queries the `DevolutionsAgent` service with `QueryServiceStatusEx` and accepts the server only when the service is running, its process ID equals the server process ID, and the server session ID is 0.
The service name is fixed in UniGetUI and never taken from the server.
UniGetUI does not open the server process, because a standard user cannot obtain the process access needed to pin a SYSTEM service process.
This check assumes that the Service Control Manager holds the service process handle until it reports the service stopped, so a running service's process ID cannot belong to another process.
On any failure, UniGetUI closes the connection without sending data and retries under the reconnect rules.
UniGetUI applies the same check to every Broker execution pipe connection before writing to it.
On the execution pipe, a failed check is a transport failure that is never retried on another route; after the request was sent, the outcome is `UNKNOWN`.
Same-user code can duplicate UniGetUI's pipe handles, so process-level output confidentiality remains an unresolved security requirement.
The Agent identifies the client with `GetNamedPipeClientProcessId` and keeps a handle to that process for the life of the connection.
From that process's token it takes the user SID and session ID.
It accepts the client only when the executable is a signature-verified `UniGetUI.exe`, the token is not elevated, and the session is a logged-on user session.
Values that UniGetUI reports about itself are never used for identity or targeting.

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
| `GetPackageVersions` | `manager`, `sourceName`, `packageId` | `{ "versions": [string] }` |
| `ExecutePackageOperation` | `operationId`, `brokerRequestId`, `operation`, `manager`, `sourceName`, `packageId`, `version`, `scope`, `grant` | `{ "status": "Succeeded" \| "Failed" \| "Unknown", "error": string }` |

`operation` is `Install`, `Update` or `Uninstall`; `version` and `scope` are empty when not requested.
UniGetUI submits `ExecutePackageOperation` to the Broker with the grant under `CONTRACT.package-management.md §operations` and answers when the outcome is known.
`Unknown` means UniGetUI cannot establish the outcome; `error` is empty unless `status` is `Failed`.
A rejected or unanswered `ExecutePackageOperation`, or one whose connection closes first, is reported to the Authority as `UNKNOWN` unless UniGetUI confirmed that no submission started.
The Agent never resends an operation, on this or another connection.

### Source identity

Every package and update entry carries `source`, a display label, and `sourceName`, the canonical Broker `Source.Name`.
`sourceName` is empty when the canonical name is unknown, ambiguous within the manager, or unsafe to report.
There is no separate opaque source reference.
`GetPackageVersions` and `ExecutePackageOperation` require a nonempty `sourceName`.
UniGetUI resolves it by ordinal comparison against the manager's source names and rejects the request with `InvalidArguments` when no source or more than one matches.
For update and uninstall, it also rejects the request when the installed package's canonical source differs.
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
The Agent does not use a UniGetUI inventory endpoint that can change package-manager state or log raw source details.
When no safe endpoint is available, it reports inventory unavailable without sending an empty replacement snapshot.
Every inventory request includes the target user SID, as do install, update and uninstall requests.
The ownership `scope` is `USER`, `MACHINE` or `UNKNOWN`.
The Agent sets it to `USER` or `MACHINE` only when a manager-specific mapping establishes that ownership; otherwise it is `UNKNOWN`.
`reported_scope` preserves UniGetUI's raw `reportedScope` value separately from ownership.
UniGetUI aliases `Global` to `Machine` and `Local` to `User`, but those labels do not establish ownership across managers.
The Authority does not use `reported_scope` to deduplicate machine-wide installations or authorize machine-wide changes.
The scope-label definitions are in [UniGetUI package scope aliases].
For each Agent Identity and target SID, the Authority transactionally allocates a durable generation and records the identity, request UUID, canonical SID and generation as pending before enqueueing a sync request.
Every retry after a timeout uses a new request UUID and generation.
The Agent sets the response envelope's `correlation_id` to the request UUID, including after a stream reconnect.
Reports can be lost when a stream closes, so the Authority times out requests without a terminal outcome.
The Authority accepts a report only when its authenticated Agent Identity and correlation UUID match a pending request and its target SID matches that request's canonical SID.
It ignores stale, unsolicited, mismatched and already completed reports without changing inventory or newer requests.

Each collection has a nonempty `report_id` identifying the snapshot independently of the request UUID.
All pages of that collection carry the same `report_id` and `page_count`.
`page_index` and `page_count` are `InventoryReport` fields 7 and 8, respectively.
`page_count` is at least one, including for an empty inventory, and `page_index` is zero-based and less than `page_count`.
`last` is true exactly when `page_index` is the final index.
The Authority stages at most one collection for a request, bounds its staged page count and size, accepts identical duplicate pages and rejects conflicting duplicates.
It replaces inventory and updates its last-successful sync only after all indexes for that collection are present.
When staging is lost after restart or failover, the Authority abandons the incomplete attempt, ignores later pages from it and preserves the last completed inventory.

The Agent sends `InventoryUnavailable` as `DeviceManagementReport.inventory_unavailable` field 6, with `target_user_sid` field 1 and `reason` field 2.
`reason` is `UNSPECIFIED` (0), `SAFE_ENDPOINT_UNAVAILABLE` (1), `BUSY` (2) or `COLLECTION_FAILED` (3).
The Authority maps `UNSPECIFIED` and unrecognized reasons to generic unavailability, never success or authorization.
It stores or displays only an allowlisted reason or a generic label, not raw diagnostics.
An unavailable result discards only that request's staged pages and preserves the last completed inventory and last-successful sync.
The Agent and Authority must both understand unavailable reports and complete-page validation; mixed versions are unsupported.

Any refresh after a package operation uses a new `SyncInventory` request with its own correlation and generation.
Such a refresh neither determines the operation's outcome nor retries the write.
Connection activity or a last-seen timestamp is not an inventory-sync outcome.
The Authority stores an entry once per device when a manager-specific mapping confirms machine-wide ownership, and once per device and target user SID when it confirms user ownership.
An unmapped scope does not establish either ownership class.
The exact inventory record key is provisional, but it must preserve manager, source, package ID and scope so machine and user installations are not collapsed.
UniGetUI's current package model and `IpcPackageInfo` contain no scope property, while `IpcPackageActionRequest` accepts `Scope`.
The installed IPC list deduplicates with `GetPackageIdentity`, so adding a response property alone may not preserve both machine and user installations.
These gaps are visible in the [UniGetUI package model], [UniGetUI IPC package types] and [installed-package identity implementation] at pinned source commit `da6be7b86100302a79a208e7ab4d5c6fcd695fd5`.

<a id="operations"></a>
## Package operations

The operation type is exactly one of `install`, `update` or `uninstall`.
The Authority-to-Agent request contains an operation ID, operation type, manager, source, package ID, requested version when applicable, scope and target user SID, but no bypass token.
The operation's source is the nonempty canonical Broker source name, not the inventory display label.
When the canonical source name is unavailable, the operation is rejected without execution.
The Agent mints an opaque, short-lived, single-use grant, also called a bypass token, held in the Broker's memory.
The grant binds the target user SID, operation type, manager, source, package ID, version, scope, requested elevation and Broker request ID.
UniGetUI sends `POST /v1/package-operations/execute-grant` over the Broker's named pipe while running unelevated as the target user.
The request uses `Content-Type: application/json`, `Accept: application/json` and exactly one `X-Devolutions-Package-Grant` header.
Before sending the grant, UniGetUI authenticates the pipe server as the live Broker service.
The authentication mechanism remains unresolved; grant execution stays unavailable until it is established.
The Broker accepts `application/json` content types with parameters, including `charset=utf-8`; the JSON body is UTF-8.
The `Accept` value is exactly `application/json`, ignoring case and surrounding whitespace.
The grant is 1 to 2,048 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._~:-]*`.
Header names are case-insensitive; duplicate grant or `Accept` headers are rejected.
The client validates the grant before sending it and does not send it with any other Broker request.
The Broker independently validates the decoded request and the pipe caller's SID against the grant before execution, and consumes a matching grant atomically.
The Broker rejects an invalid, expired, reused or mismatched grant rather than applying local policy.
The Broker rejects missing, duplicate, invalid or unsupported grant requests before consuming a grant or starting work.
Once consumed, a grant is never restored, even if submission or response delivery fails.
The legacy `POST /v1/package-operations/execute` route rejects any request carrying the grant header.
If the grant route is unavailable, including an older Broker's 404 response, UniGetUI does not retry through the legacy route or execute locally.
The Agent, UniGetUI and Broker reject execution-affecting fields not authorized by the grant.
The Authority request does not authorize custom parameters, hooks or other execution options, so remote requests carrying them are rejected.
UniGetUI's broker request builder maps source, custom parameters and pre-operation, post-operation and kill-before-operation commands into the request.
These execution-affecting fields are visible in the [UniGetUI broker request builder][UniGetUI broker request fields].

The Broker request's `Operation` must match the Authority operation type.
The Broker compares `Manager` to the authorized manager using ASCII case-insensitive comparison of the Broker enum spelling.
An alias without an agreed mapping is rejected.
`Source.Name`, `Package.Id` and a nonempty requested version are compared exactly as decoded Unicode strings, without trimming or case folding.
An empty requested version requires an absent Broker `Package.Version`; a nonempty requested version must not be dropped or replaced.
An empty requested scope requires an absent Broker `Options.Scope`.
A `User` or `Machine` scope is compared case-insensitively to `Options.Scope`; other scope labels are rejected until their mappings are agreed.
The Broker rejects any `Source.Url` the Authority has not authorized.
The representation and manager-specific validation of authorized source URLs remain unresolved.
Matching a source name or URL in the request alone does not establish the feed the manager uses.
The Broker rejects an operation before submission when it cannot ensure that the manager's configured source-mapping restrictions remain effective throughout execution.
It rejects `Package.Architecture`, `Package.Channel`, a custom install location, custom parameters, pre-operation or post-operation commands, and kill-before-operation entries.
It also rejects `Interactive`, `SkipHashCheck`, `PreRelease`, `UninstallPrevious` and `NoUpgrade` when true.
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
The actual execution token must be elevated exactly when `Options.Scope` is `Machine` or the grant authorizes `RequestedElevation` as `Elevated`.
The Broker rejects an elevated request unless the Authority's scope authorizes machine effects.
`IncludeCommandPreview` must be false, and `CaptureOutput` must be true.
UniGetUI uses captured stdout and stderr only for local result parsing; it does not send them to the Agent or Authority or write them to logs.
For grant operations, the Broker sends event frames only to the verified process that submitted the operation.
It authenticates the connecting process before sending any event frames, and rejects other processes without disclosing output.
The grant client verifies that the event pipe belongs to the same live Broker instance that accepted the operation.
The legacy event pipe and its user-SID access rules remain unchanged.
For grant operations, the Broker emits `Finish` only after both output readers have completed without losing data.
On a read failure, reader panic, invalid UTF-8, output overflow or other loss, it closes the event stream without `Finish`.
The grant client accepts output only after a valid `Hello` and `Finish` with no overflow or malformed frames.
When the operation's verdict requires output that is unavailable or incomplete, UniGetUI reports `UNKNOWN`.

The npm broker always emits `--global`, while the .NET tool broker emits it when no custom install location is set; both reject explicit machine scope, so the current routes do not preserve UniGetUI's distinct `Local` and `Global` choices.
The .NET broker passes `--source` for install and update, which overrides NuGet configuration including Package Source Mapping.
The current Scoop broker rejects machine/global scope and elevated execution while its script is resolved from the target user's profile; those guards remain until a separately trusted route exists.
The current scope behavior is visible in the [npm broker builder], [.NET tool broker builder] and [Scoop broker builder]; the source override is documented in [dotnet tool install].
How each manager's scope maps to broker execution remains unresolved.
An operation result identifies the operation ID.
When the outcome is known, it reports success or failure with an error value on failure.
When the Agent cannot recover an operation's outcome, it reports `UNKNOWN`.
The Agent sends an `UNKNOWN` result in `DeviceManagementReport.package_operation_unknown` with field number 5.
It sends a known result with status `UNSPECIFIED` in `DeviceManagementReport.package_operation_result` with field number 2.
The Authority does not record success or failure for a result whose field and status disagree.
The Authority ignores `success` when the status is `UNKNOWN`.
Agent and Authority versions must both understand `UNKNOWN` when they exchange operation results, including queued results after reconnect or rollback.
Mixed versions that do not satisfy this requirement are unsupported.
The Agent records an operation before submitting it and does not submit another operation for the same operation ID.
Repeated deliveries with the same operation ID and payload return the recorded result or wait for the active operation to finish.
A repeated operation ID with a different payload is rejected.
When deduplication state cannot be recovered, the Agent does not treat an operation ID as new and reports `UNKNOWN`.
The Authority may submit a new operation ID after an `UNKNOWN` outcome only by explicitly accepting that the earlier operation may have completed.
The Broker's request-ID replay tracking does not replace this Authority operation-ID tracking.
The Broker status API requires the Broker-issued operation ID; if that ID is lost with the submission response and the outcome cannot otherwise be recovered, the Agent reports `UNKNOWN`.
A confirmed rejection before submission is a failure only when no earlier submission for that operation could have started.
A lost or malformed response after submission is not evidence of failure.
A missing or unrecoverable record is `UNKNOWN`, and any recovery query uses the same resolved instance.
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
`Forbidden` and `Conflict` do not establish that an earlier submission for the operation did not start.
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

The following defaults are proposals and are not normative until Benoit confirms them.
The operation target is the user SID alone, and the wire format omits an instance UUID.
Extension framing lands after beta; beta package-management messages remain in their own namespace.
The target extension framing has the Agent advertise each extension name and supported version range in `Hello`.
The Authority opens a channel with a channel ID, extension name and version, and the Agent accepts or refuses the open.
The Agent refuses an unknown extension or one disabled by local configuration.
Data messages carry a channel ID and opaque payload, and either party may close a channel with a reason.
Package management is the first separately versioned extension.
UniGetUI must preserve reported scope in its package model and identity as well as its IPC response so distinct installations are not collapsed.
The inventory key for unknown ownership and how each manager's scope maps to broker execution remain unresolved.
An operation result does not itself update package records.
The requested-version field is optional where an operation does not use a version; its exact meaning for each operation is unresolved.
The endpoint errors use the proposed codes in `CONTRACT.package-management.md §provisional-errors`, and neither permits retrying the write against another endpoint.
A transport disconnection does not prove that an operation failed.
The Agent does not replay an operation automatically after disconnection or restart.

<a id="external-changes"></a>
## Required changes outside this repository

UniGetUI must add `reportedScope` to its package model and installed IPC response while including it in package identity so distinct installations remain distinct.
UniGetUI must expose each safely reportable canonical Broker source name as `sourceName` independently of its display label.
UniGetUI must pass the Agent-minted operation token through IPC to the package broker's named pipe without elevating its process.
UniGetUI must reject remote operations when broker routing is disabled, the manager is unsupported, the source cannot use broker routing, or the token does not authorize all execution-affecting fields; it must not fall back to local process execution.
This fail-closed requirement covers the existing local-fallback paths in [PackageOperations.cs][UniGetUI operation fallback].
The current fixed mapping is in [`BrokerRequestBuilder.TryMapManagerName`][UniGetUI manager mapping] at commit `da6be7b86100302a79a208e7ab4d5c6fcd695fd5`.
A Broker route for the UniGetUI `Installer` manager requires feed-item resolution, installer hash, identity and signature verification, and installed-version receipt handling; adding a manager enum value alone is insufficient.
These operations are implemented in the pinned [WinInstaller runner], [WinInstaller manager] and [Installer receipt] sources.
DVLS must store the target user SID and package scope in its beta database schema.
DVLS/RDM must show the Agent-reported user and session in an instance picker and send the selected target user SID with every operation.

[UniGetUI IPC package types]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.Interface.IpcApi/IpcPackageApi.cs#L16-L35
[UniGetUI package model]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Interfaces/IPackage.cs#L10-L42
[installed-package identity implementation]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.Interface.IpcApi/IpcPackageApi.cs#L156-L164
[UniGetUI manager mapping]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.AgentBroker/BrokerRequestBuilder.cs#L201-L221
[UniGetUI operation fallback]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Operations/PackageOperations.cs#L387-L514
[UniGetUI broker request fields]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.AgentBroker/BrokerRequestBuilder.cs#L53-L84
[UniGetUI package scope aliases]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Enums/Enums.cs#L11-L18
[npm broker builder]: https://github.com/Devolutions/devolutions-gateway/blob/c45dd6698116854c32b1881ce9a74bb79e43f8c0/crates/now-package-broker/src/command_builder/npm.rs#L19-L50
[.NET tool broker builder]: https://github.com/Devolutions/devolutions-gateway/blob/c45dd6698116854c32b1881ce9a74bb79e43f8c0/crates/now-package-broker/src/command_builder/dotnet.rs#L19-L86
[Scoop broker builder]: https://github.com/Devolutions/devolutions-gateway/blob/c45dd6698116854c32b1881ce9a74bb79e43f8c0/crates/now-package-broker/src/command_builder/scoop.rs#L78-L86
[dotnet tool install]: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-tool-install#options
[WinInstaller runner]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/Internal/WinInstallerRunner.cs#L30-L106
[WinInstaller manager]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/WinInstaller.cs
[Installer receipt]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/Internal/InstallReceipts.cs
