<a id="device-management-discovery"></a>
## Discovery and targeting

The Agent discovers all running UniGetUI instances from their IPC endpoints and derives each instance's user SID and session ID from the Windows token of the process that owns the endpoint.

The Agent verifies the UniGetUI executable's signature before reporting an instance.

The stable target for DVLS and package-management operations is the user SID, not an instance UUID.

When a SID has multiple live instances, the Agent may resolve an operation to any instance for that SID.

Each package write targets exactly one resolved instance, and the Agent does not retry that write through another endpoint.

UniGetUI must be running in a logged-on user session for the device to be manageable.

UniGetUI runs unelevated.

The Agent may start UniGetUI in the background at logon, but a device at the logon screen is not manageable.

<a id="device-management-inventory"></a>
## Inventory

The Agent obtains package inventory through UniGetUI IPC rather than querying WinGet separately.

Each inventory request targets one user SID, and DVLS requests inventory separately for each SID.

Package scope describes installation ownership: machine scope means the package is genuinely device-wide, while a manager's `global` label alone does not establish machine scope.

When installation ownership cannot be determined, the inventory entry's scope is unknown.

<a id="device-management-remote-operations"></a>
## Remote operations

DVLS-authorized package operations bypass local broker policy, while local policy continues to govern user self-service.

The Agent routes package install, update, and uninstall requests through UniGetUI IPC rather than executing them directly through WinGet.

The Agent's short-lived, single-use authorization token is bound to the target SID and the complete effectful execution payload, including custom parameters and command hooks.

The broker rejects an operation when the named-pipe caller's SID does not match the token's target SID.

Remote writes are limited to operations supported by the existing package broker and fail closed when unsupported.

Remote writes never fall back to local package execution.

Repeated delivery of an operation ID returns its recorded status and never starts a second execution.

When an operation's outcome cannot be recovered after a crash or disconnection, its status is `UNKNOWN`.

<a id="device-management-later"></a>
## Later

Persistent UniGetUI registration through the broker is a future direction, not the beta discovery mechanism.

Removing the Agent-to-UniGetUI dependency to support unattended operation is a future direction.
