<a id="device-management-discovery"></a>
## Discovery and targeting

UniGetUI connects to the Agent's registration pipe and keeps the connection open.
The Agent discovers UniGetUI instances from these connections and derives each instance's user SID and session ID from the Windows token of the process that owns the connection.

The Agent verifies the UniGetUI executable's signature before reporting an instance.

The target for DVLS and package-management operations is an opaque Agent-issued user UUID, not a user SID or an instance UUID.
The Agent maps that UUID to the user identity, and UUIDs may change over time.
A stale UUID is never reassigned to a different user.

When a user has multiple live instances, the Agent may resolve an operation to any instance for that user.

Each package write targets exactly one resolved instance, and the Agent does not retry that write through another endpoint.

UniGetUI must be running in a logged-on user session for the device to be manageable.

UniGetUI runs unelevated.

The Agent may start UniGetUI in the background at logon, but a device at the logon screen is not manageable.

<a id="device-management-inventory"></a>
## Inventory

The Agent obtains package inventory through UniGetUI IPC rather than querying WinGet separately.

Each inventory request targets one user, and DVLS requests inventory separately for each user.

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

<a id="device-management-operation-journal"></a>
## Operation journal

The operation journal is the Agent's durable record, on the device, of the remote package operations it has accepted, with one entry per operation ID and its status.
It exists so that an operation is executed at most once and its recorded status can be returned again.

Repeated delivery of an operation ID recorded in the journal returns its recorded status and never starts a second execution.

When the operation journal is missing, the Agent creates a new journal; operations recorded in the missing journal may execute again.

The journal's index is what keeps an operation from running twice; an operation's record only holds its details and status.
When an operation's index entry survives but its record is missing or unreadable, its status is `UNKNOWN`, because its outcome is lost, and it never runs again, because its index entry still identifies it.
Other operations continue, because each keeps its own index entry, so the damage removes no protection against running twice.
A missing record alone never stops remote package writes on the device, because a crash between writing an index entry and its record leaves exactly that state, and refusing would stop remote package management until someone repairs the journal by hand.
When the index itself is shown unreliable (a record with no index entry, an index that is corrupt, missing, replaced or could not be written, or a records directory that is missing or replaced), the Agent refuses new remote package writes on the device until it starts again and finds the index reliable, because an operation the index no longer lists could run again; discovery and inventory remain available.

When an operation's outcome cannot be recovered after a crash or disconnection, its status is `UNKNOWN`, except when its record was lost with a missing journal.

<a id="device-management-later"></a>
## Later

Removing the Agent-to-UniGetUI dependency to support unattended operation is a future direction.
