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
| `F.PackageBroker` | Off | Package Broker. Sets `PackageBroker.Enabled` in `agent.json`. |
| `F.Pedm` | Off | Devolutions PEDM (experimental). |

The Package Broker rejects package requests until a package policy is deployed, by default in `%ProgramData%\Devolutions\PackageBroker\`.
The installer neither installs nor changes that policy.

An upgrade without `ADDLOCAL` or `REMOVE` keeps the previous feature selection.
When upgrading from a release without the Package Broker option, setup selects `F.PackageBroker` if `agent.json` already enables the broker.

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
