# Devolutions Agent Windows Installer

Windows Installer project for Devolutions Agent.

## Overview

Project structure is the same as Devolutions Gateway, see [README.md](../WindowsManaged/README.md) for more info.

Localization works the same way; see the Localization section of that README.
Run `package\Update-InstallerLocalization.ps1 -Product agent` to regenerate the Agent files.
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
