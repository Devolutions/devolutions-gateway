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

The Package Broker rejects local self-service requests until a package policy is deployed, by default in `%ProgramData%\Devolutions\PackageBroker\`.
The installer neither installs nor changes that policy.

For device management, enable the Package Broker and install UniGetUI for all users in an administrator-protected directory, such as `C:\Program Files\UniGetUI`.
The Agent refuses to register an instance if standard users can modify its executable or add files to its containing directory.

An upgrade without `ADDLOCAL` or `REMOVE` keeps the previous feature selection.
When upgrading from a release without the UniGetUI Package Broker option, setup selects `F.PackageBroker` if `agent.json` already enables the broker.

## Package operation journal recovery

When its operation journal cannot be trusted, the Agent refuses new remote package writes and reports `UNKNOWN` to the authority.
Previously recorded operations with intact records retain their recorded results.
It logs `Cannot open the device-management operation journal; package writes are unavailable` or `Package operation journal is unrecoverable; package writes are unavailable` when it detects damage.
The refusal remains until the journal is recovered and the Agent is restarted.
Discovery and inventory remain available when their own dependencies are healthy.
An `UNKNOWN` result does not prove that an earlier operation with the same ID did not run.

To recover the journal, use an elevated administrator session:

1. Stop submitting package operations, wait for active operations to finish, and inspect any operations whose outcomes are unknown.
2. Stop the `DevolutionsAgent` service and any other Agent instance using that data directory.
3. Restore a trusted, complete and current backup of `%ProgramData%\Devolutions\Agent\package-operations`, including its original permissions.
   If the Agent uses `DAGENT_CONFIG_PATH`, the journal is under that directory instead.
   If no complete backup is available, move or delete the entire `package-operations` directory to create a new journal.
4. Start the service and check the Agent log for journal errors.

Resetting the journal, or restoring a backup that lacks recent records, allows previously recorded operation IDs to execute again.
Accept that risk before resetting or restoring the journal; do not remove only individual journal files.
If the log names the initialization lock, remove `.package-operations-initialization.lock` beside the journal while all Agent instances are stopped.
The lock file holds no operation records.

## Agent Identity

To enroll the device with Agent Identity during an install or a major upgrade, put the enrollment token on the first line of a file and set `IDENTITY_ENROLLMENT_TOKEN_FILE` to the file's path:

```powershell
msiexec /i DevolutionsAgent.msi /qn IDENTITY_ENROLLMENT_TOKEN_FILE=enrollment-token.txt
```

A relative path resolves against the folder of the `.msi`, so a deployment tool such as Intune can ship the file beside the installer.
The file keeps the token off msiexec's command line, which security tools and process auditing record and Intune shows in the app's install command.
The installer never deletes the file, so protect it like the token.
An upgrade whose command sets the property again reads the file again, so keep the file or leave the property out of that command.
The install fails if the file is missing or its first line holds no token.

You can instead set `IDENTITY_ENROLLMENT_TOKEN` to the token itself, but not both properties:

```powershell
$Token = (Get-Content -Raw 'C:\Secure\enrollment-token.txt').Trim()
msiexec /i DevolutionsAgent.msi /qn "IDENTITY_ENROLLMENT_TOKEN=$Token"
```

Take the token from a protected file or a secure channel, such as your deployment tool's secret store, never from a literal in a shared script or command line.
msiexec's command line then holds the token while the install runs, so run it elevated or from your deployment tool, where only administrators can read it.

Either way, the installer keeps the token out of its log and passes it to the agent through standard input.
The install fails if the agent rejects the token's format or can't store it.
The agent then enrolls in the background once its service starts, and re-running the command later with the same token enrolls nothing new.

A full uninstall deletes the device's Agent Identity state and keys without contacting the authority, so a later install enrolls the device as new and uses up a token use.
A major upgrade, a repair or a maintenance run keeps them.

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
