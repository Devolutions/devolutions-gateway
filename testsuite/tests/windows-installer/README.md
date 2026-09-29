# Gateway service-account lab

Run this opt-in suite only on a disposable, elevated Windows host.
It installs and removes Gateway, creates temporary accounts, and preserves diagnostics.
It refuses to overwrite an existing Gateway service or data directory.
It does not provision a domain, create KDS root keys, change domain policy, or intentionally reboot.

Use two complete Gateway MSIs with the same UpgradeCode and increasing ProductVersion values.
Candidate MSI versions must differ even when testing the same application payload.
Record reused payload versions separately from installer versions.
Pester 5.7.1 or newer and Windows PowerShell 5.1 are required.
AD scenarios also require the ActiveDirectory module and permissions to create the run-owned objects.

```powershell
# Read-only discovery and prerequisite validation.
.\ci\Test-GatewayServiceAccounts.ps1 `
    -Msi C:\lab\candidate-a.msi -NextMsi C:\lab\candidate-b.msi `
    -OutputDirectory C:\lab\results\run-01

# Run only after reviewing the selected host and artifacts.
.\ci\Test-GatewayServiceAccounts.ps1 `
    -Msi C:\lab\candidate-a.msi -NextMsi C:\lab\candidate-b.msi `
    -OutputDirectory C:\lab\results\run-01 `
    -AccountKinds NetworkService,Virtual,Local,LocalDollar,Domain,Smsa,Gmsa `
    -Execute
```

The matrix covers fresh installation, real process identity, loopback HTTP health, file access under the service token, upgrade, unchanged repair, missing-password rejection, direct downgrade rejection, and uninstall.
Local test passwords contain quotes, backslashes, and shell metacharacters; failures must not expose them in reports.
No test concludes that runtime access works merely from an ACL string or an administrator's access.
A short-lived SYSTEM task acquires the running service token and impersonates it for the file probes.
Only run these helpers from a trusted checkout; the probe tasks execute that checkout's code as SYSTEM.

Provide `-AgentExecutable` with a locally built Devolutions Agent executable to enable actual passwordless upgrades, unsigned-package rejection, and the password-account rejection scenario.
This uses a run-local Agent configuration and productinfo file, not a machine-wide Agent installation.
Unsigned lab MSI acceptance is explicit in that isolated configuration; hash-check bypass remains disabled.
These runs do not establish production signing trust or Agent MSI packaging compatibility.
The existing Agent downgrade path is exercised only for passwordless accounts.
Signed baseline targets retain signature validation; unsigned candidate targets use the explicit lab bypass.
The Agent's existing explicit-version path does not carry a productinfo hash, so those downgrade artifacts rely on the runner's recorded SHA-256 and, for signed targets, the normal signature check.

Add `-TestCertificateMigration` and include the `Local` fixture to test account changes with existing CNG and CSP system-store certificates.
Each case verifies the unchanged configuration, the new process identity, and a real TLS health request pinned to the disposable certificate.
Use `-TestFilter '*System certificate*'` to run only those cases.
Use `-LegacyBaseline` when the first MSI predates service-SID enablement; this skips only the initial service-SID membership assertion, not process-identity or runtime checks.

`manifest.json` records run-owned local SIDs and AD object GUIDs, but no passwords.
`results.xml` and `summary.json` distinguish passed, failed, skipped, and blocked coverage.
The artifact directory is restricted to Administrators and SYSTEM.
MSI logs, token-probe results, configuration copies, and event data can contain sensitive deployment information; do not publish the directory unredacted.
KDS-dependent gMSA scenarios are reported blocked when the domain has no root key.
The gMSA fixture authorizes both its run-owned host group and the test computer directly to retrieve its managed password.
Direct host authorization avoids depending on refreshed machine group membership, without a reboot or ticket purge.
This does not test propagation of group-only authorization.

The runner serializes product installation and stops the remaining tests on failure.
Repairs use `/i {ProductCode} REINSTALL=ALL REINSTALLMODE=omus REBOOT=ReallySuppress`, with the service stopped first.
Using the installed product code preserves Windows Installer's source identity after Agent installs from a UUID-named temporary MSI.
Do not replace this with `/fa`: the initial lab repair ignored `/norestart` and initiated a reboot when files remained in use.
All MSI invocations explicitly suppress restarts, and `3010` or `1641` stops further installation and cleanup for operator recovery.
Forced repair of a running service and destructive rollback fault injection require explicit approval for the test host.

## Controlled rollback failures

Generate fault-injection source outside the repository, then build it using the normal installer build procedure.
Use a higher MSI ProductVersion and a different, working Gateway executable so the probes can distinguish replacement files from restored files.
The generator copies the installer source and adds three deferred failure actions only to that copy.
Do not distribute the resulting MSI as a product installer.

```powershell
.\testsuite\src\windows-installer\New-RollbackFixture.ps1 `
    -OutputDirectory C:\lab\rollback-source

# After building the copied source as rollback-fault.msi:
.\ci\Test-GatewayServiceAccounts.ps1 `
    -Msi C:\lab\baseline.msi -NextMsi C:\lab\rollback-fault.msi `
    -OutputDirectory C:\lab\results\rollback-01 `
    -AccountKinds NetworkService,Local -TestRollback -RollbackAccountChanges -Execute
```

`-TestRollback` requires a marked fault-injection MSI and cannot be combined with Agent or certificate scenarios.
`-RollbackFailurePoints` selects `after-remove`, `after-service`, or `after-permissions`; all three run by default.
Each injected action records the observed service account, executable hash, and directory DACL before returning failure.
The test rejects failures that did not reach the intended phase.

`rollback.json` captures the state immediately after MSI rollback, before attempting to start or recover the service.
It compares product ownership, executable/data hashes, account, startup/running state, DACLs, explicit service-logon rights, and runtime access.
Reordering Allow ACEs is not treated as a permission change, but protection and ACE flags remain significant.

The harness can reapply the disposable account's known credentials through SCM, repair the old MSI, and restore backed-up data/DACLs to recover the lab.
It never extracts a stored service password.
Manual recovery is recorded separately and does not turn a failed rollback assertion into a pass.
Extra rights granted to another test account are recorded as deviations and removed during fixture-account cleanup.
Rollback mode continues to the next case only when the previous installation can be recovered and removed; uncertain MSI state or failed recovery stops further installation.
The suite may deliberately finish with failing assertions when it has reproduced an installer defect.

## Interrupted runs

After an interruption, inspect the manifest, installed ProductCode, service, and remaining `GatewayLabProbe-*` or `GatewayLabAgent-*` tasks before resuming.
Do not rerun setup over an uncertain installation or delete accounts still used by a service.
Verify and uninstall only the recorded lab product, retain its data, then remove only the recorded accounts and empty OU.
Automatic resumption after interruption is not implemented; use a new output directory after recovery.

## Helper tests

Run non-installing helper tests separately:

```powershell
Invoke-Pester .\powershell\pester\ServiceAccount.Tests.ps1
$container = New-PesterContainer `
    -Path .\testsuite\tests\windows-installer\InstallerHelpers.Tests.ps1 `
    -Data @{ InstallerAssembly = 'C:\lab\DevolutionsGateway.exe' }
Invoke-Pester -Container $container
```

The installer assembly above is the compiled packaging executable, not the Gateway service binary.
Use a new PowerShell process for each assembly version because .NET cannot unload an assembly from that process.

The Rust `service_accounts` tests run account-lookup checks, including unknown names ending in `$`, and read-only service-configuration checks in normal Windows CI.
The two managed-account classification checks are ignored by default because `NetIsServiceAccount` queries the local Netlogon store, which may be unavailable on standalone runners.
Run them explicitly on a configured account-lab host with Netlogon already running, as an ordinary user whose account name does not end in `$`:

```powershell
cargo test --locked -p testsuite --test integration_tests service_accounts:: -- --ignored
```

These checks do not start services or configure domain membership.
An API error still fails an explicitly requested check; it is never treated as an unmanaged account.
