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
The extension framing and the UniGetUI-to-Broker request details remain provisional.

| Message | Direction | Fields |
| --- | --- | --- |
| `DiscoverUniGetUiInstances` | Authority to Agent | none |
| `UniGetUiInstances` | Agent to Authority | `instances` |
| `UniGetUiInstance` | Agent to Authority | `user_sid`, `display_name`, `session_id`, `signature_verified` |
| `SyncInventory` | Authority to Agent | `target_user_sid` |
| `InventoryReport` | Agent to Authority | `report_id`, `last`, `target_user_sid`, `packages`, `managers`, `sources` |
| `InstalledPackage` | Agent to Authority | `manager`, `source`, `id`, `name`, `version`, `available_version`, `scope` |
| `PackageOperationRequest` | Authority to Agent | `operation_id`, `type`, `manager`, `source`, `package_id`, `version`, `scope`, `target_user_sid` |
| `UniGetUIOperationRequest` | Agent to UniGetUI | `operation`, `bypass_token` |
| `BrokerOperationRequest` | UniGetUI to Broker | `operation`, `bypass_token` |
| `PackageOperationResult` | Agent to Authority | `operation_id`, `success`, `error` |

<a id="instances"></a>
## Instance discovery and targeting

The Agent reports every running UniGetUI instance with its target user SID, session ID, display name and signature-verification result.
The Agent obtains the SID and session ID from the Windows token of the endpoint-owning process, not from a value reported by UniGetUI.
The Agent verifies the executable signature before accepting an instance as a target.
The Authority stores and selects the target user SID, and displays it as `DOMAIN\user (session N)`.
Every package operation includes a target user SID, including a machine-scope operation.
The Agent resolves the target SID to a live instance when it executes the request.
The Agent sends the write to exactly one resolved instance and does not retry against another endpoint.
The package-management contract requires the Agent and Broker to support every package manager and scope exposed by UniGetUI; listing a manager in inventory alone does not satisfy this requirement.

<a id="inventory"></a>
## Inventory

Each package entry contains its manager, source, package ID, name, installed version, available version and scope.
Every inventory request includes the target user SID, as do install, update and uninstall requests.
Values with confirmed machine or user semantics distinguish those installations; other manager-relative values are not interpreted without a mapping.
Scope values supported for package operations must include every value UniGetUI exposes, without conversion to a narrower set.
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
The Agent mints a short-lived, single-use bypass token for that operation and sends it with the operation to UniGetUI over IPC.
UniGetUI passes the operation and token to the Broker over a named pipe while running unelevated as the target user.
The Broker validates the token and rejects the request when the pipe caller SID differs from its target user SID before executing the operation.
The token is bound to the complete canonical operation request, including its type, manager, source, package ID, requested version, scope, target user SID and every execution-affecting option.
The Agent, UniGetUI and Broker reject an execution-affecting field that is not covered by the token.
Remote operations do not carry custom parameters or pre-operation, post-operation or kill-before-operation commands unless the token explicitly authorizes them.
UniGetUI's broker request builder maps source, custom parameters and pre-operation, post-operation and kill-before-operation commands into the request.
These execution-affecting fields are visible in the [UniGetUI broker request builder][UniGetUI broker request fields].
The npm broker always emits `--global`, while the .NET tool broker emits it when no custom install location is set; both reject explicit machine scope, so the current routes do not preserve UniGetUI's distinct `Local` and `Global` choices.
The current Scoop broker rejects machine/global scope and elevated execution while its script is resolved from the target user's profile; those guards remain until a separately trusted route exists.
The current scope behavior is visible in the [npm broker builder], [.NET tool broker builder] and [Scoop broker builder].
How each manager's scope maps to broker execution remains unresolved.
An operation result identifies the operation ID and reports success or failure with an error value when it fails.
Local broker policy is bypassed only for a valid DVLS-authorized operation; local policy continues to govern user self-service operations.
The exact requested-version semantics for each operation are provisional as described in `CONTRACT.package-management.md §provisional-decisions`.

<a id="provisional-errors"></a>
## Provisional error-code proposal

No error-code spelling or operation-status vocabulary is agreed yet.
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
When the Agent cannot establish an operation's outcome, the proposed status is `UNKNOWN`, not a confirmed failure, and the Authority decides whether to resubmit with a new token.

<a id="external-changes"></a>
## Required changes outside this repository

UniGetUI must add scope to its package model and installed IPC response while including scope in package identity so user and machine installations remain distinct.
UniGetUI must pass the Agent-minted operation token through IPC to the package broker's named pipe without elevating its process.
UniGetUI must reject remote operations when broker routing is disabled, the manager is unsupported, the source cannot use broker routing, or the token does not authorize all execution-affecting fields; it must not fall back to local process execution.
This fail-closed requirement covers the existing local-fallback paths in [PackageOperations.cs][UniGetUI operation fallback].
UniGetUI must extend its broker mapping beyond the current fixed manager list to cover every exposed manager and scope.
The current fixed mapping is in [`BrokerRequestBuilder.TryMapManagerName`][UniGetUI manager mapping] at commit `da6be7b86100302a79a208e7ab4d5c6fcd695fd5`.
The UniGetUI `Installer` manager also requires feed-item resolution, installer hash, identity and signature verification, and installed-version receipt handling; adding a manager enum value alone is insufficient.
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
[WinInstaller runner]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/Internal/WinInstallerRunner.cs#L30-L106
[WinInstaller manager]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/WinInstaller.cs
[Installer receipt]: https://github.com/Devolutions/UniGetUI/blob/da6be7b86100302a79a208e7ab4d5c6fcd695fd5/src/UniGetUI.PackageEngine.Managers.WinInstaller/Internal/InstallReceipts.cs
