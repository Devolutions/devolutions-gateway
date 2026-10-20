# PSU Agent Run As

PowerShell Universal (PSU) sends Windows process credentials only to a Devolutions Agent on a device-authenticated connection with verified TLS and the exact Run As capability.
This contract defines that exchange over `devolutions.psu.agent.poc.v1.AgentControl.Connect`.
It does not define enrollment, administrative interfaces, or the credential-free process protocol.
Declarative statements in this document are requirements.

## Definitions

**Connection**: one live bidirectional `AgentControl.Connect` stream, including its authentication result, TLS transport, and Agent registration.
A replacement stream is a different connection, even when it represents the same device.

**Device-authenticated connection**: a connection for which PSU accepted the enrolled device's certificate-backed authentication and bound the registered Agent identity to that authenticated device.
An app-token-authenticated connection is not device-authenticated, even if enrollment is enabled or an enrollment record exists for the reported Agent.

**Run As request**: a PSU job with a selected credential, represented on the wire by a present `StartProcess.credential` message.
An empty credential message is present, not omitted.

## Credential message

The protobuf package is `devolutions.psu.agent.poc.v1`.
The credential extends the existing `StartProcess` message without changing its other fields.

| Message | Field | Number | Type |
|---|---|---|---|
| `StartProcess` | `credential` | 9 | `ProcessCredential`, with message presence |
| `ProcessCredential` | `username` | 1 | `string` |
| `ProcessCredential` | `password` | 2 | `string` |
| `ProcessCredential` | `domain` | 3 | `string` |

Encoding and field defaults follow [proto3][proto3].
An omitted `credential` requests execution as the Agent service identity.
Its omission preserves existing credential-free execution on Windows, Linux, and macOS, including permitted app-token and HTTP connections.
Run As eligibility checks do not become prerequisites for credential-free execution.

A present `credential` requests the supplied Windows identity.
The username is nonempty and not whitespace-only, the password is nonempty, and none of the three strings contains a NUL character.
An omitted string has its protobuf default, the empty string.
Passwordless credentials and managed service account credentials marked `PasswordNotRequired` are not supported.

PSU maps a selected `DOMAIN\user` name to `username=user` and `domain=DOMAIN`.
It maps `.\user` to `username=user` and `domain=.`.
It preserves a UPN in `username` with an empty `domain`.
An unqualified username with an empty `domain` identifies an account local to the Agent.
The password is transmitted without trimming or other transformation.

## Connection eligibility

The Run As capability is an `AgentCapability` entry with `name` exactly `job_execution_run_as` and `version` exactly `poc.v1`.
Both comparisons are case-sensitive.
A different version or a name without the matching version does not authorize Run As.
The Agent advertises this capability in the connection's `RegisterAgent.capabilities` if and only if it runs on Windows and opens that connection using device authentication over verified HTTPS.
PSU uses the capability from that connection's registration, not a stored capability tag.
Capability advertisement alone does not establish authentication or transport security.

Before retrieving a selected credential from its secret vault, PSU requires all of the following for the connection selected to execute the job:

- It is live and device-authenticated.
- Its registration identifies Windows.
- Its registration contains the exact Run As capability.
- Its actual incoming gRPC transport uses TLS 1.2 or TLS 1.3.

If any condition is false or cannot be established at that check, PSU refuses the Run As request without retrieving the credential.
PSU also enforces those conditions when sending a credential-bearing `StartProcess` and does not send it if any condition no longer holds.
An enrollment setting, stored device record, reported Agent identifier, URL scheme, or forwarded header does not substitute for these connection facts.
A proxy-to-PSU plaintext final hop is ineligible, including when a proxy reports the original request as HTTPS.

The Agent verifies the PSU server's TLS certificate chain and hostname using normal TLS validation.
An insecure-certificate bypass, HTTP retry, or enrollment server proof does not replace that validation.
The Agent accepts a credential-bearing `StartProcess` only on its device-authenticated, verified HTTPS connection and only on Windows.
It refuses the launch if these conditions do not hold, even if PSU sent the message.
Connection eligibility does not transfer to an app-token connection or survive replacement by another stream.

## PSU credential selection

PSU selects the job's explicit credential when its name is not empty or whitespace-only; otherwise it selects the environment credential.
If neither selects a credential, PSU sends a credential-free launch without retrieving a Run As secret.
If an explicitly selected job credential is invalid, PSU does not substitute the environment credential.

After connection eligibility is established, PSU looks up the selected variable by name, case-insensitively.
Before retrieving its secret, PSU requires that the variable exists, allows Run As, is a secret of type `PSCredential` with a nonblank vault, and is not marked `PasswordNotRequired`.
The `PSCredential` type comparison is case-insensitive.
When the variable restricts roles, at least one of its nonblank role names matches a complete execution-role name on the job, case-insensitively.
Job execution-role names are comma-separated, with surrounding whitespace and empty entries ignored.
Substring role matches do not grant access.
PSU retrieves the secret only after these checks succeed.
An unavailable secret or a secret without a nonblank username and nonempty password fails the request.
PSU encodes the retrieved credential only for the job's process launch.

## Launch and failure behavior

For an eligible Run As request, the Agent uses Windows batch logon and native process creation under the supplied identity.
The job's PowerShell runspace, startup scripts, and script execute under that identity.
The Agent does not load the user's Windows profile, create an interactive desktop or UAC prompt, or grant rights beyond that identity's Windows permissions.
The target account requires batch-logon rights and access to the executable, working directory, scripts, and repository used by the job.
The executable is a native Windows program, not a `.cmd` or `.bat` launcher.
The process receives the target user's base environment plus the requested environment overrides.

A PSU-side refusal or credential-resolution failure produces an unsuccessful job result with an explanatory error and no credential-bearing launch.
A requested Run As job does not become a credential-free job after any failure.
Neither endpoint retries it under the service identity or silently ignores a present credential.

For a credential-bearing `StartProcess` with otherwise valid, unused process and stream identifiers, the Agent treats ineligible connection or platform, invalid credential fields, failed Windows logon, and failed process creation as launch failures.
It starts no job under a substitute identity and sends no `ProcessStarted` for a failed launch.
While the connection remains writable, it sends these existing responses in order:

1. `StreamClosed` with the request's `stream_id`, `error=true`, and a nonempty explanatory `reason`.
2. `ProcessCompleted` with the request's `correlation_id`, `exit_code=-1`, `canceled=false`, and the same explanation in `error_message`.

The diagnostic text is not a machine-readable error code and its wording is not fixed.
PSU reports the launch failure as an unsuccessful job rather than waiting for the failed process to acknowledge runspace closure.
Loss of the connection is not evidence that a process did or did not start and does not authorize a credential-free retry.
This contract does not add retry or deduplication semantics to `StartProcess`.

## Credential confidentiality

The credential is carried only in `StartProcess.credential` on the eligible connection.
Neither endpoint copies it into process arguments, environment variables, metadata, persisted job or Agent configuration, or diagnostic messages.
Neither endpoint logs the credential message or its password; debugging output redacts the credential message.
The credential's existing PSU secret-vault storage is not changed by this exchange.
Job stdout, stderr, and other application output are controlled by the job and are not automatically secret-redacted by this protocol.

[proto3]: https://protobuf.dev/programming-guides/proto3/
