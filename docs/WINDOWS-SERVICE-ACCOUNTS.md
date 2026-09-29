# Windows service accounts for Devolutions Gateway

Keep `NT AUTHORITY\NetworkService` unless you have a specific reason to use another identity.
For a domain identity with a managed password, prefer a group managed service account (gMSA).
Changing the Windows service account changes the process's access to files and network resources; it does not replace Gateway tokens, application authentication, or remote-session credentials.

This guide covers two deployment models:

| Version | How to configure the account | Maintenance implications |
| --- | --- | --- |
| **Current release: 2026.3.0** | Configure the Windows service and permissions manually after installation. | Assume customization must be reapplied after every Gateway update, reinstall, or repair. Agent updates/restarts can also reset update-channel permissions. |
| **Forthcoming custom-account feature** | Select the account through MSI properties or the updated PowerShell module. | Same-account upgrades preserve the identity; password accounts require credentials again. Failed upgrades and account changes have the limitations described below. |

**The forthcoming interface is not available in 2026.3.0.**
Do not pass `P.SERVICEACCOUNT` to an older MSI and assume it took effect.
Use the manual procedure until the release notes explicitly announce support, and verify both Gateway and Agent versions when transitioning.

## Choose an identity

| Account | Suitable use | Password and prerequisites |
| --- | --- | --- |
| `NT AUTHORITY\NetworkService` | Default and lowest-maintenance choice. On a domain member, network access normally uses the computer's domain identity. | No supplied password. |
| `NT SERVICE\DevolutionsGateway` | A local identity dedicated to this service. Network access normally still uses the computer's domain identity. | No supplied password or AD account. The Gateway service must already exist for the manual procedure. |
| `CONTOSO\svc-gateway$` (gMSA) | A dedicated domain identity with automatic password management. | Domain membership, KDS readiness, and authorization for this computer to retrieve the managed password. |
| Standalone managed service account (sMSA) | An existing deployment that requires an account tied to one computer. | Provision and install it for the specific host; verify its readiness. |
| Dedicated local/domain user | Integrations that cannot use managed accounts. | Supply and rotate the password yourself, update the SCM credentials, and plan manual recovery after failed upgrades. |

Do not use a personal account, Domain Admin, or another privileged administrator account.
`LocalSystem`, `LocalService`, groups, computer accounts, and another service's virtual account are not supported selections in the forthcoming installer.
A name ending in `$` is not proof that an account is an MSA.

## Before changing a working installation

Schedule a maintenance window and drain active sessions.
Stopping Gateway interrupts connections it is relaying.
Use an elevated, 64-bit PowerShell session on the Gateway host.

Pause Gateway updates in every tool that manages this deployment: the Agent schedule, management console, RMM, or installation automation.
Disabling a schedule does not prevent an administrator or management tool from submitting an explicit update.
Do not disable the entire Agent service without considering its other functions.

Record the installed Gateway/Agent versions, desired account, startup mode, and service state.
Use service and uninstall-registry queries rather than `Win32_Product`, which can trigger MSI repairs.

```powershell
$ErrorActionPreference = 'Stop'
$ServiceName = 'DevolutionsGateway'
$DataPath = Join-Path $env:ProgramData 'Devolutions\Gateway'
$Account = 'CONTOSO\svc-gateway$' # Replace with your selected account.

$Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $Service) { throw 'Install Devolutions Gateway before following the manual procedure' }
$Service | Select-Object Name, StartName, State, StartMode, PathName

Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object DisplayName -In @('Devolutions Gateway', 'Devolutions Agent') |
    Select-Object DisplayName, DisplayVersion

Get-Acl -LiteralPath $DataPath | Format-List Owner, Sddl
```

The default data location is shown above.
If you use `DGATEWAY_CONFIG_PATH` or custom paths in `gateway.json`, inventory those locations too.
Check the service's actual deployment configuration rather than assuming your interactive shell has the same environment.

Take an organization-approved backup or snapshot before maintenance.
Include configuration, provisioning/delegation keys, the user database, required state/recordings, certificate recovery material, and relevant NTFS permissions.
Record the selected certificate's store and thumbprint.
A copy of `gateway.json` alone is not a complete backup.
Protect backups and recovery records: configuration and key files can contain credentials or other sensitive material.
For non-exportable or hardware-backed keys, use the certificate provider's recovery procedure.

### Prepare managed accounts

Have an AD administrator provision the account and authorize this host according to your organization's policy.
Follow Microsoft's [managed-account guidance][msa-overview] and [KDS requirements][kds].
A new KDS key may require a readiness/replication interval; do not apply single-DC lab backdating shortcuts to production.

Install and test the account on the Gateway host using the AD PowerShell module:

```powershell
Import-Module ActiveDirectory
Install-ADServiceAccount -Identity 'svc-gateway'
if (-not (Test-ADServiceAccount -Identity 'svc-gateway')) {
    throw 'The host cannot use the managed service account'
}
```

Do not continue if installation or password retrieval fails.
Check host authorization, DC connectivity, DNS/time synchronization, KDS readiness, and AD replication.
New group membership can require a refreshed computer authentication context.
An AD administrator can authorize the computer directly where policy permits; do not purge machine tickets or restart shared infrastructure blindly.

### Prepare service-logon rights

The selected custom account needs **Log on as a service** (`SeServiceLogonRight`).
Configure this through the applicable local or domain security policy.
For local policy, use `secpol.msc` → **Local Policies** → **User Rights Assignment**.
The Services console may grant this right when applying logon credentials, but verify the effective policy.

**Deny log on as a service** takes precedence over an Allow.
Domain policy can replace local assignments.
Do not grant interactive/RDP logon, administrative membership, or broad file access merely to make the service start.

## Customize the current release

This is an administrator-managed workaround for 2026.3.0, not a persistent MSI configuration setting.
Complete the ordinary Gateway configuration first, then perform the steps below.

### 1. Stop Gateway and prevent an automatic start during maintenance

Record the original startup mode outside the current shell.
The following example assumes an installed service that you intend to run; do not enable an intentionally disabled service without approval.

```powershell
$OriginalStartMode = $Service.StartMode
Set-Service -Name $ServiceName -StartupType Manual
$Controller = Get-Service -Name $ServiceName
try {
    if ($Controller.Status -ne 'Stopped') { $Controller.Stop() }
    $Controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromMinutes(2))
} finally {
    $Controller.Dispose()
}
```

Do not continue if the service cannot stop.
Avoid killing the process or forcing a repair against files still in use.

### 2. Grant access to Gateway data

Resolve the account to a SID so the grants do not depend on localized account names.
Grant Modify access only to the dedicated Gateway data tree.
The recursive grant also covers existing files with protected ACLs, such as `users.txt`.

```powershell
$Sid = ([System.Security.Principal.NTAccount]::new($Account)).
    Translate([System.Security.Principal.SecurityIdentifier])
$Grant = '*{0}:(OI)(CI)M' -f $Sid.Value
& "$env:SystemRoot\System32\icacls.exe" $DataPath /grant:r $Grant /T /C /L
if ($LASTEXITCODE -ne 0) {
    throw 'Some Gateway permissions were not applied; inspect the icacls output before continuing'
}
```

Review the target tree for links and junctions before a recursive grant.
Handle linked/external locations separately.
Never apply this command to all of `C:\ProgramData`, `C:\Program Files`, a certificate-key directory, or a shared parent directory.
Do not remove SYSTEM or Administrators access, disable inheritance globally, or grant Everyone Full Control.
These commands add/replace the selected identity's Allow entries; they do not remove older identities' grants or override Deny entries.

For custom paths, grant only the required access:

| Resource | Access to verify |
| --- | --- |
| Gateway executable, DLLs, and web assets | Read/execute, not permission to modify program binaries. |
| Configuration and writable state directories | Modify where Gateway writes state; SQLite also needs access to the containing directory for journal/WAL files. |
| Logs and recordings | Create/write/delete as required by retention, in their dedicated directories. |
| External provisioning/delegation/TLS private-key files | Read on the particular files; protect them from unrelated users. |
| Custom user database | Required read/write access, including its protected ACL if present. |
| UNC/remote storage | Both share and NTFS permissions for the identity actually used over the network. |

Local file permissions do not grant access to a remote share.
NETWORK SERVICE and the virtual account normally authenticate to a domain resource as `DOMAIN\GATEWAYHOST$`; a gMSA uses its own domain identity.

### 3. Grant access to the TLS private key

For a certificate in the Windows store, prefer an appropriate **Local Computer** store for a service.
`CurrentUser` refers to the identity using the store, not necessarily the administrator who imported the certificate.

Open `certlm.msc`, locate the certificate selected by Gateway, and use **All Tasks → Manage Private Keys** to grant the selected account Read access.
Verify the store, subject/selection settings, thumbprint, and presence of a private key.
If multiple certificates match, check which one Gateway selects.
Grant access again when renewal creates a new key.
Use provider-specific controls for HSM or other keys that do not expose the normal file-permission dialog.

Do not grant access to the entire machine key store or disable TLS validation to bypass a permissions problem.
For file-based TLS, grant access to the configured certificate and key files instead.

### 4. Change the service logon identity

The Services console (`services.msc`) is suitable for this step.
Open **Devolutions Gateway Service → Properties → Log On** and select **This account**.
For a virtual account or MSA, use its full name and leave both password boxes empty.
For a regular user, enter the account's password.

Alternatively, for a prepared **gMSA, sMSA, or Gateway virtual account**:

```powershell
$Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($Service.State -ne 'Stopped') { throw 'Gateway must be stopped before changing its account' }
$Result = Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments @{
    StartName = $Account
    StartPassword = $null
}
if ($Result.ReturnValue -ne 0) {
    throw "Win32_Service.Change failed with return value $($Result.ReturnValue)"
}
```

For a **password-based** account, use the Services console or prompt instead of embedding the password in a command:

```powershell
$Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($Service.State -ne 'Stopped') { throw 'Gateway must be stopped before changing its account' }
$Credential = Get-Credential -UserName $Account -Message 'Gateway service account'
if ($Credential.UserName -ine $Account) { throw 'Use the selected account name in the credential prompt' }
$Arguments = @{
    StartName = $Credential.UserName
    StartPassword = $Credential.GetNetworkCredential().Password
}
try {
    $Result = Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments $Arguments
    if ($Result.ReturnValue -ne 0) {
        throw "Win32_Service.Change failed with return value $($Result.ReturnValue)"
    }
} finally {
    $Arguments.Remove('StartPassword')
    $Credential = $null
}
```

This still supplies a password to Windows; it is not a guarantee against privileged memory inspection or instrumentation that records arguments.
Do not put passwords in scripts, shell history, tickets, transcripts, or screenshots.
The CIM method's return values are defined by [Win32_Service.Change][service-change], not the MSI exit-code table.
A successful change does not prove the service can log on or access its resources.
To return to NETWORK SERVICE, select that identity in the Services console and clear the password.
If using CIM for that change, supply `StartName = 'NT AUTHORITY\NetworkService'` and `StartPassword = ''` rather than `$null`.

### 5. Handle the current Agent's update-channel permissions

Skip this step if the deployment does not use Devolutions Agent's update integration.
The 2026.3.0 Agent grants update-file access to NETWORK SERVICE, not an arbitrary Gateway account.
If the custom Gateway needs this integration, grant access to the two existing files:

```powershell
$AgentData = Join-Path $env:ProgramData 'Devolutions\Agent'
$UpdateFile = Join-Path $AgentData 'update.json'
$StatusFile = Join-Path $AgentData 'update_status.json'
if (-not (Test-Path -LiteralPath $UpdateFile) -or -not (Test-Path -LiteralPath $StatusFile)) {
    throw 'Check Agent version, configuration, data location, and updater startup; do not create placeholder channel files'
}
& "$env:SystemRoot\System32\icacls.exe" $UpdateFile /grant:r ('*{0}:(GR,GW)' -f $Sid.Value)
if ($LASTEXITCODE -ne 0) { throw 'Could not grant Gateway access to update.json' }
& "$env:SystemRoot\System32\icacls.exe" $StatusFile /grant:r ('*{0}:R' -f $Sid.Value)
if ($LASTEXITCODE -ne 0) { throw 'Could not grant Gateway read access to update_status.json' }
```

Adjust the location if the Agent uses `DAGENT_CONFIG_PATH`.
**Do not grant Gateway write access to `agent.json`, `update_status.json`, or the whole Agent directory.**
The Agent is privileged; writable configuration there would cross the intended trust boundary.

These file grants can be reset when the current Agent restarts or is updated.
They do not make the current Gateway MSI preserve a custom account.
Keep Gateway updates under your maintenance procedure rather than treating these ACL changes as support for unattended customized upgrades.

### 6. Validate, then restore the intended startup mode

```powershell
Start-Service -Name $ServiceName
$Controller = Get-Service -Name $ServiceName
try {
    $Controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30))
} finally {
    $Controller.Dispose()
}
Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" |
    Select-Object StartName, State, StartMode, ProcessId
```

A brief Running state is not enough.
Verify the configured health endpoint, TLS handshake, actual relay operation, logs, recordings/state, user database, and any remote resources you depend on.
For example, use `Invoke-WebRequest` against your configured `/jet/health` URL without suppressing certificate validation.
A health response alone does not test every file path or a real session.
Reading files as Administrator does not prove the service account can read them.

Check the Windows event logs if the service stops immediately or cannot create its own log.
Once validation succeeds, restore the recorded startup mode; for an originally automatic service:

```powershell
Set-Service -Name $ServiceName -StartupType Automatic
```

## Maintain a customized 2026.3.0 deployment

Treat every Gateway update, reinstall, and repair as a maintenance event that may invalidate the account or its permissions.
The current MSI recreates the service during a major upgrade with NETWORK SERVICE.
Some settings may survive a repair while ACLs are reset; do not depend on partial preservation.
In the validated 2026.3.0 repair cases, virtual-account, local-user, and gMSA customizations all reverted to NETWORK SERVICE and the data-directory ACL changed.

Before each update, record the desired identity and state, take the required backup, set the service to Manual, and stop it.
Run the signed installer with a persistent log and explicit reboot suppression:

```powershell
$Msi = 'C:\Installers\DevolutionsGateway.msi' # Replace with the verified installer.
$Log = 'C:\Gateway-maintenance\gateway-install.log' # Create and secure the parent directory first.
$Process = Start-Process -FilePath msiexec.exe -ArgumentList @(
    '/i', "`"$Msi`"", '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*v', "`"$Log`""
) -Wait -PassThru
if ($Process.ExitCode -eq 3010) {
    throw 'Installation requires a planned restart; do not assume maintenance is complete'
}
if ($Process.ExitCode -ne 0) {
    throw "MSI failed with exit code $($Process.ExitCode); retain $Log"
}
```

Reapply the desired account, service-logon right, data/key permissions, and current-Agent channel grants before returning the service to operation.
Revalidate functionality and restore startup mode.
Do not assume that running an older `Install-DGatewayPackage` wrapper retained the log or surfaced the MSI result; direct `msiexec` is preferable for this maintenance procedure.

If this repeated work is unacceptable, keep NETWORK SERVICE until the supported feature ships.

## Transition to the forthcoming feature

Use release notes to identify the first supported Gateway installer, PowerShell module, and Agent builds.
The test MSI version numbers used during development are not release identifiers.

1. Inventory the manually configured account, SID, paths, certificate, startup mode, and custom grants.
2. Update the Agent to a version that understands custom Gateway accounts before relying on its automatic updater.
   Recheck the old Gateway's channel access during this transition.
3. Keep the existing Gateway identity for the first feature-aware upgrade where possible.
   Avoid combining a version upgrade, account migration, certificate replacement, and path migration in one operation.
4. Upgrade Gateway using the supported interface, supplying the password again if the existing account requires one.
5. Verify the resulting identity, permissions, TLS, state, and update integration before removing your old reapplication procedure.

For a passwordless account, an explicit selection with the forthcoming MSI is:

```powershell
# Forthcoming feature only; not supported by the 2026.3.0 MSI.
msiexec /i DevolutionsGateway.msi /qn /norestart REBOOT=ReallySuppress `
    P.SERVICEACCOUNT="CONTOSO\svc-gateway$" /l*v C:\Gateway-maintenance\gateway-install.log
```

Omitting `P.SERVICEACCOUNT` on an upgrade preserves the existing service's account in the forthcoming installer.
On a fresh install, the default remains NETWORK SERVICE.
There is no account-selection wizard.

The updated PowerShell module adds:

```powershell
# Forthcoming module only.
Install-DGatewayPackage -RequiredVersion '<supported-version>' -ServiceAccount 'CONTOSO\svc-gateway$' -Quiet

$Credential = Get-Credential -UserName 'CONTOSO\svc-gateway' -Message 'Gateway service account'
Install-DGatewayPackage -RequiredVersion '<supported-version>' -ServiceCredential $Credential -Quiet
```

For regular users, `P.SERVICEPASSWORD` supplies the MSI password.
The forthcoming wrapper handles MSI quoting and surfaces failures, but it still passes the password to `msiexec`.
The password is hidden from ordinary MSI logs, **not** from process command lines or Windows Installer's `Debug=7` logging policy.
Keep diagnostics appropriately protected.

The forthcoming installer grants the selected identity access to the standard data directory and default user database.
It adjusts system-certificate key permissions only when `TlsCertificateStoreLocation` is explicitly `LocalMachine`.
An omitted or `null` location means `CurrentUser` at runtime, not `LocalMachine` or the installer's SYSTEM profile.
When the existing service and selected account resolve to the same SID and no reconfiguration is requested, setup leaves retained `CurrentUser` or `CurrentService` configuration and private-key ACLs unchanged and unmanaged.
It logs that it skips certificate discovery, permission grants, and runtime access verification; this does not establish certificate or runtime availability.
If the identity changes, the service is missing, or reconfiguration is requested, setup rejects retained non-machine-store configuration before modifying the installation.
Setup also aborts if configuration approved for retention changes or is removed after validation.
Migrate to explicit `LocalMachine` or external certificate/key files first.
New wizard selections of `CurrentUser` are rejected because the interactive administrator's profile is not the service's profile.
External/custom resources still need your permissions.
Review old manual grants deliberately; the installer does not remove every earlier account grant or service-logon right.
Do not remove permissions still required by another service or deployment.

The updated Agent supports automatic Gateway updates only under NETWORK SERVICE, the Gateway virtual account, or verified managed accounts.
Password-based accounts remain a manual-upgrade path.
After an external identity change, Agent file-permission refresh normally occurs on its five-minute status interval; check the files or use a planned Agent restart if immediate refresh is required.

### Accepted limitations and failed-upgrade recovery

Successful same-account installs/upgrades were validated for the default and custom-account paths.
The following are failure-recovery limitations, not claims that normal upgrades fail:

| Situation | What to expect and plan for |
| --- | --- |
| Unchanged NETWORK SERVICE or gMSA | Tested rollback restored a working service. A late failure could retain the installer's tightened `users.txt` ACL rather than its prior inherited ACL. |
| Unchanged password account | Even with valid credentials supplied to the upgrade, rollback can restore the old files/account name without usable service logon credentials. Reapply the known password through SCM, then validate. |
| Changing identities during an upgrade | Failed rollback can leave DACLs for the new SID on the restored old installation. Restore the original identity and recorded permissions; a password account may need its password reapplied too. |
| Repair | The forthcoming installer preserves an existing account/password but rejects account/password changes during repair. Missing-service repair requires an explicit account and credentials when applicable. |
| Downgrade | Direct MSI downgrades remain blocked. The Agent retains its existing uninstall/reinstall path for passwordless accounts; older target MSIs can discard custom-account settings. |

The SID-change permission risk is not specific to password accounts; it also matters when planning a migration to a managed account.
Do not treat a failed MSI transaction as proof that the service is operational.
Preserve logs and inspect the installed version, service identity, startup state, and ACLs before retrying.

When recovering, reapply credentials only to the intended service, restore data/key permissions from the maintenance record, and verify real operation.
Do not work around failures by switching to LocalSystem, granting broad administrator rights, disabling TLS validation, or weakening the Agent's configuration permissions.
If service repair is necessary, use the installed ProductCode and an available matching source package with explicit reboot suppression.
Agent-installed packages may have a UUID source name; a differently named MSI can produce a source/secure-repair error.
If the required source or recovery state is uncertain, stop and escalate with the evidence below rather than repeatedly installing over it.

## Diagnose problems and collect support evidence

Collect evidence **before** restarting the Agent or rebooting.
The forthcoming `Products.Gateway.LastUpdateError` status field is reset when the Agent restarts.
Agent-generated MSI logs are scheduled for deletion at reboot.
Application logs also rotate, so preserve the relevant files promptly.

| Source | What it tells you |
| --- | --- |
| Explicit MSI `/l*v` log | Account discovery, selected name/SID/type in the new installer, validation failures, custom-action results, permission operations, and rollback. A generic 1603 alone is not the root cause. |
| Windows **System** log, **Service Control Manager** | Logon/start failures even when Gateway cannot create a log; examples include 1069/logon failure and events 7000/7038. |
| Windows **Application** log, **Devolutions Gateway** | Configuration, TLS, startup, and state/database errors. If the rendered message is unavailable, inspect the event's Details/XML data. |
| Gateway `gateway*.log` | Runtime failures and affected paths, normally under `%ProgramData%\Devolutions\Gateway`; `LogFile` can override the location/prefix. |
| Agent `agent*.log` | Update attempts, account/ACL decisions, package validation, MSI log locations, exit outcomes, and errors; normally under `%ProgramData%\Devolutions\Agent`. |
| Agent `update_status.json` | The forthcoming per-product `LastUpdateError`, when present. It is not exposed by the current Gateway update HTTP response and is not durable history. |

A configured account name in SCM is not sufficient evidence of actual runtime access.
Correlate it with the running process and the failing operation.

```powershell
$Service = Get-CimInstance Win32_Service -Filter "Name='DevolutionsGateway'"
$Service | Select-Object StartName, State, StartMode, ProcessId, ExitCode
if ($Service.ProcessId -gt 0) {
    $Process = Get-CimInstance Win32_Process -Filter "ProcessId=$($Service.ProcessId)"
    $Owner = Invoke-CimMethod -InputObject $Process -MethodName GetOwner
    if ($Owner.ReturnValue -ne 0) { throw "Could not query process owner: $($Owner.ReturnValue)" }
    $Owner | Select-Object Domain, User
}

Get-WinEvent -LogName System -MaxEvents 300 |
    Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -like '*Devolutions Gateway*' } |
    Select-Object TimeCreated, Id, Message

Get-WinEvent -LogName Application -MaxEvents 300 |
    Where-Object ProviderName -eq 'Devolutions Gateway' |
    Select-Object TimeCreated, Id, Message, @{Name='Data'; Expression={ @($_.Properties | ForEach-Object Value) }}
```

For escalation, provide timestamps/time zone, Gateway/Agent/MSI versions, account type and SID, the exact failing operation, the MSI result and log, relevant application/SCM events, affected-path ACLs, and managed-account readiness results.
State whether an account, password, certificate, or path changed in the same maintenance window.
Distinguish configuration failure, logon failure, file access failure, and update-package validation failure.

Redact passwords, tokens, private keys, connection strings, and sensitive configuration before sharing.
Do not send an entire unredacted data directory or export a managed password.
Do not enable the Agent's unsafe URL, hash, or signature bypass settings to diagnose a production deployment.

## References

- [Gateway configuration][gateway-readme]
- [Gateway Windows installer reference][installer]
- [Managed service accounts][msa-overview]
- [KDS root-key requirements][kds]
- [Win32_Service.Change return values][service-change]
- [Windows service account configuration][change-service-config]
- [MSI service installation and password rollback limitations][service-install]
- [Windows Installer hidden-property limits][hidden-properties]
- [icacls permissions reference][icacls]

[gateway-readme]: ../README.md#configuration
[installer]: ../package/WindowsManaged/README.md
[msa-overview]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview
[kds]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key
[service-change]: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/change-method-in-class-win32-service
[change-service-config]: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw
[service-install]: https://learn.microsoft.com/en-us/windows/win32/msi/serviceinstall-table
[hidden-properties]: https://learn.microsoft.com/en-us/windows/win32/msi/msihiddenproperties
[icacls]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
