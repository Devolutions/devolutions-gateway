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
