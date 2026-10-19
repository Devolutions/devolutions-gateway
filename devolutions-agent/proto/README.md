# PSU process credentials

Credentialed jobs require a Windows Devolutions Agent connected to PSU using HTTPS with a trusted certificate and a matching server hostname.
The agent advertises `job_execution_run_as` with version `poc.v1` only on Windows over HTTPS.
PSU must check this capability and the actual TLS transport before resolving or sending credentials.
Older agents ignore unknown protobuf fields, so sending credentials without capability negotiation could run a job under the service account instead.

`StartProcess.credential` is an optional `ProcessCredential` message at field 9.
Its string fields are `username` (1), `password` (2), and `domain` (3).
Omitting the message preserves service-account execution, including existing credential-free HTTP connections.
Presence requests alternate-identity execution; HTTP, unsupported platforms, missing usernames or passwords, invalid logons, and process-creation failures produce the existing `StreamClosed(error=true)` and `ProcessCompleted(exit_code=-1)` responses without a service-account fallback.

Use an unqualified username with an empty domain for an account local to the agent, a username and explicit domain for a domain account, or a UPN with an empty domain.
Passwords must be nonempty; passwordless and managed service accounts are unsupported.
Windows uses [batch logon][logon] and [`CreateProcessAsUserW`][process], so the target account needs **Log on as a batch job** and access to the executable, working directory, scripts, and any shared repository.
The agent service normally runs as LocalSystem; a custom service identity needs the Windows privileges required by `CreateProcessAsUserW`.
The executable must be a native Windows program, such as `pwsh.exe` or `powershell.exe`, not a `.cmd` or `.bat` launcher.
The user's profile is not loaded, no interactive desktop or UAC prompt is created, and the process receives the user's base environment plus the requested overrides.
Run As changes the process identity; it does not bypass Windows logon policy or grant additional privileges.

Windows briefly creates an always-suspended copy of the Agent as a pipe-handle donor so concurrent process launches cannot inherit another job's streams.
The donor is terminated after launch or failure and belongs to a kill-on-close job for Agent-exit cleanup.

Credentials travel only in the protobuf message on the authenticated TLS stream, not in metadata, environment variables, command-line arguments, or configuration.
The agent redacts the credential message in debug output and clears its decoded credential strings and temporary UTF-16 password after use.
Child stdout, stderr, and other job output remain application-controlled; scripts must not print secrets.
Standard TLS certificate verification is mandatory, with no HTTP retry or insecure-certificate option.
PSU additionally requires TLS on its live gRPC server connection, not a forwarded scheme header.
A proxy that terminates TLS and forwards plaintext to PSU cannot carry credentialed jobs; use TLS on that hop too.

[logon]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
[process]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
