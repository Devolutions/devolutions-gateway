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
- **Scope**: a manager-reported package scope value; manager-relative labels do not by themselves establish machine-wide or user-specific installed ownership.

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
| `UniGetUiInstance` | Agent to Authority | `user_sid`, `display_name`, `session_id`, `signature_verified` |
| `SyncInventory` | Authority to Agent | `target_user_sid` |
| `InventoryReport` | Agent to Authority | `report_id`, `last`, `target_user_sid`, `packages`, `managers`, `sources` |
| `InstalledPackage` | Agent to Authority | `manager`, `source`, `source_name`, `id`, `name`, `version`, `available_version`, `scope` |
| `PackageOperationRequest` | Authority to Agent | `operation_id`, `type`, `manager`, `source`, `package_id`, `version`, `scope`, `target_user_sid` |
| `UniGetUIOperationRequest` | Agent to UniGetUI | `operation`, `bypass_token` |
| `BrokerOperationRequest` | UniGetUI to Broker | `operation`, `bypass_token` |
| `PackageOperationResult` | Agent to Authority | `operation_id`, `success`, `error`, `status` |

<a id="instances"></a>
## Instance discovery and targeting

The Agent reports discovered, unelevated UniGetUI instances in logged-on user sessions with their target user SID, session ID, display name and signature-verification result.
The Agent obtains the SID and session ID from the Windows token of the endpoint-owning process, not from a value reported by UniGetUI.
The Agent verifies the executable signature before reporting an instance or accepting it as a target.
The Authority stores and selects the target user SID, and displays it as `DOMAIN\user (session N)`.
Every package operation includes a target user SID, including a machine-scope operation.
The Agent resolves the target SID to a live instance when it executes the request.
The Agent sends the write at most once to one resolved instance and does not retry it against that or another endpoint.
Inventory covers the package managers and scopes exposed by UniGetUI.
Remote writes are limited to operations supported by the existing package broker and fail closed when unsupported.
Remote writes never fall back to local package execution.

<a id="inventory"></a>
## Inventory

Each package entry contains its manager, source, package ID, name, installed version, available version and scope.
`source` is a display label; `source_name` is the canonical Broker `Source.Name` or empty when that identity is unavailable.
UniGetUI supplies the canonical name as `sourceName`; the Agent preserves both fields without deriving one from the other.
Every inventory request includes the target user SID, as do install, update and uninstall requests.
Values with confirmed machine or user semantics distinguish those installations; other manager-relative values are not interpreted without a mapping.
Inventory preserves the scope values UniGetUI exposes without conversion to a narrower set.
UniGetUI aliases `Global` to `Machine` and `Local` to `User`, but those labels do not establish device-wide ownership across managers.
The scope-label definitions are in [UniGetUI package scope aliases].
Unknown-scope handling and the placement of the reporting instance SID are listed in `CONTRACT.package-management.md §provisional-decisions`.
Pages in one complete inventory share a report ID, and the final page sets `last` to true.
The Authority stores an entry once per device when a manager-specific mapping confirms machine-wide ownership, and once per device and target user SID when it confirms user ownership.
An unmapped scope does not establish either ownership class.
The exact inventory record key is provisional, but it must preserve manager, source, package ID and scope so machine and user installations are not collapsed.
Inventory pagination and replacement semantics are provisional as described in `CONTRACT.package-management.md §provisional-decisions`.
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
The existing event pipe permits access by the target user SID, SYSTEM and Administrators and does not authenticate the connecting process or session.
The required privacy boundary for grant-operation output remains unresolved; remote execution must not begin until it is settled.

The npm broker always emits `--global`, while the .NET tool broker emits it when no custom install location is set; both reject explicit machine scope, so the current routes do not preserve UniGetUI's distinct `Local` and `Global` choices.
The .NET broker passes `--source` for install and update, which overrides NuGet configuration including Package Source Mapping.
The current Scoop broker rejects machine/global scope and elevated execution while its script is resolved from the target user's profile; those guards remain until a separately trusted route exists.
The current scope behavior is visible in the [npm broker builder], [.NET tool broker builder] and [Scoop broker builder]; the source override is documented in [dotnet tool install].
How each manager's scope maps to broker execution remains unresolved.
An operation result identifies the operation ID.
When the outcome is known, it reports success or failure with an error value on failure.
When the Agent cannot recover an operation's outcome, it reports `UNKNOWN`.
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
Package scope must come from a per-package value supplied by UniGetUI, which must preserve scope in its package model and identity as well as its IPC response so distinct installations are not collapsed.
How an inventory entry with unknown scope is represented or keyed, and how each manager's scope maps to broker execution, remain unresolved.
The proposed inventory page carries the SID of its reporting instance.
The Authority initializes or replaces stored inventory only after the final page arrives, and an operation result does not itself update package records.
The requested-version field is optional where an operation does not use a version; its exact meaning for each operation is unresolved.
The endpoint errors use the proposed codes in `CONTRACT.package-management.md §provisional-errors`, and neither permits retrying the write against another endpoint.
A transport disconnection does not prove that an operation failed.
The Agent does not replay an operation automatically after disconnection or restart.

<a id="external-changes"></a>
## Required changes outside this repository

UniGetUI must add scope to its package model and installed IPC response while including scope in package identity so user and machine installations remain distinct.
UniGetUI must expose each package's canonical Broker source name as `sourceName` independently of its display label.
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
