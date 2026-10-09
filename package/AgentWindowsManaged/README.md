# Devolutions Agent Windows Installer

Windows Installer project for Devolutions Agent.

## Overview

Project structure is the same as Devolutions Gateway, see [README.md](../WindowsManaged/README.md) for more info.

Localization works the same way; see the Localization section of that README.
Run `package\Update-InstallerLocalization.ps1 -Product agent` to regenerate the Agent files.

## Features

Pass feature IDs to `ADDLOCAL` to choose features in an unattended install.
`ADDLOCAL` installs only the features it lists, so list every feature you want:

```powershell
msiexec /i DevolutionsAgent.msi /qn ADDLOCAL=F.Agent,F.Updater,F.Session,F.PackageBroker
```

| Feature | Default | Description |
| --- | --- | --- |
| `F.Agent` | Required | The Devolutions Agent service. |
| `F.Updater` | On | Devolutions Gateway updater. |
| `F.Session` | On | RDP Extension. |
| `F.Tunnel` | Off | Agent Tunnel. |
| `F.PsuAgent` | Off | PowerShell Universal Agent. |
| `F.PackageBroker` | Off | UniGetUI Package Broker. Sets `PackageBroker.Enabled` in `agent.json`. |
| `F.Pedm` | Off | Devolutions PEDM (experimental). |

The Package Broker rejects package requests until a package policy is deployed, by default in `%ProgramData%\Devolutions\PackageBroker\`.
The installer neither installs nor changes that policy.

An upgrade without `ADDLOCAL` or `REMOVE` keeps the previous feature selection.
When upgrading from a release without the UniGetUI Package Broker option, setup selects `F.PackageBroker` if `agent.json` already enables the broker.

## Build

### MSBuild

`msbuild` must be in your PATH; it's easiest to use the Developer Command Prompt for VS 2022.

The following environment variables should be defined:

`DAGENT_EXECUTABLE`
The absolute path to the main executable (DevolutionsAgent.exe) to be packaged

`DAGENT_VERSION`
The version to use for the installer. Note that in Windows Installer, the product version is restricted as follows:

[0-255].[0-255].[0-65535]

## Artwork

`Resources/DevolutionsAgent.ico` supplies the MSI product icon and the Agent executable icons.
`Resources/WixUIDialog.jpg` is the welcome illustration, while `Resources/AgentDialogSide.png` appears on the exit screen.
`Resources/WixUIBanner.jpg` appears across the other wizard screens.
The Desktop Agent uses `dotnet/DesktopAgent/Resources/AppIcon.ico` for its window and tray icon and `devolutions-agent-icon-shadow.png` for its About dialog.

An MSI built with placeholder payloads is only for reviewing the wizard UI; do not install it.

## Testing PSU device enrollment without installing a service

Build this branch with Rust 1.90, MSVC C++ tools, the Windows SDK, and CMake available in the same Visual Studio developer shell:

```powershell
cargo build --locked -p devolutions-agent
cargo test --locked -p testsuite --test integration_tests psu_device
```

Use a disposable PSU instance that implements the PSU-1337 enrollment protocol and returns the full leaf-first issuing chain in the signed bootstrap assertion.
Obtain its root certificate's SHA-256 DER fingerprint through a trusted, separate channel.
Do not discover the pin from the same untrusted enrollment connection.
The MSI wizard still configures legacy app-token authentication; device enrollment is an explicit `agent.json` setting.

Set `DAGENT_CONFIG_PATH` to a new, access-restricted writable directory, not the installed agent's data directory.
Create `agent.json` there with the following configuration, replacing the endpoint, pin, and short-lived enrollment token:

```json
{
  "Updater": { "Enabled": false },
  "Session": { "Enabled": false },
  "Pedm": { "Enabled": false },
  "PackageBroker": { "Enabled": false },
  "Tunnel": { "Enabled": false },
  "RemoteDesktop": { "Enabled": false },
  "PsuAgent": {
    "Enabled": true,
    "ServerUrl": "http://127.0.0.1:5006",
    "DeviceEnrollment": {
      "RootThumbprint": "<64-hex-digit-root-fingerprint>",
      "EnrollmentToken": "<short-lived-enrollment-token>"
    },
    "PowerShell": {
      "ExecutablePath": "C:\\Program Files\\PowerShell\\7\\pwsh.exe"
    }
  }
}
```

The token must have PSU's `AgentEnrollment` role and `AgentEnrollment` purpose, with a bounded use count and expiry.
Do not configure `PsuAgent.AppToken` in device mode.
Use HTTP only for a local HTTP/2 endpoint; a pinned proof does not encrypt traffic or prevent an active relay.
Remote HTTPS connections still require a valid, normally trusted TLS server certificate.

```powershell
$env:DAGENT_CONFIG_PATH = 'C:\temp\psu-device-smoke'
.\target\debug\devolutions-agent.exe psu-device enroll
.\target\debug\devolutions-agent.exe psu-device status
.\target\debug\devolutions-agent.exe run
```

Check that PSU shows the server-issued device UUID and an online agent, then run a small PowerShell job.
Stop the foreground agent with Ctrl+C, remove `EnrollmentToken` from the test configuration, and restart `run`.
The device UUID and token use count must stay unchanged.
For a renewal smoke test, stop the agent, run `psu-device renew`, then restart `run` and confirm the new certificate is accepted.
No command above installs or starts a Windows service.

State defaults to `psu-device\<SHA256-of-ServerUrl>\identity.json` inside `DAGENT_CONFIG_PATH`.
`DeviceEnrollment.StateDirectory` overrides the base directory; keep it writable, private, and persistent.
Files use restricted permissions and atomic replacement, and an exclusive lock prevents concurrent agent and CLI operations on one identity.
The private key, issuing chain, pinned root, UUID, and expiry stay together.
The hardware identifier is an independent persisted installation UUID unless `DeviceEnrollment.HardwareId` supplies a stable provisioning identifier.
Do not copy one identity volume to multiple machines.

Pending devices keep their issued credentials and retry connection with fresh proofs without consuming another enrollment token.
Automatic renewal starts seven days before expiry, or one fifth of the certificate lifetime for shorter-lived certificates; startup also renews an expired certificate before connecting.
Revocation, reset, corrupt state, a changed pin, or an ambiguous enrollment result stops device authentication and requires operator recovery.
There is no automatic re-enrollment, deletion, or Bearer fallback.
If an enrollment response was lost, reconcile the saved key and PSU device record before deliberately provisioning a new identity.
