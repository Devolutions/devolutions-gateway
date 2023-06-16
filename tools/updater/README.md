# Devolutions Gateway Updater

The Devolutions Gateway Updater is a tool to automatically check, download and install new versions of Devolutions Gateway, making it easier to keep a large number of Devolutions Gateway servers up-to-date without manual work. It is a simple, adaptable PowerShell script meant to be registered as a scheduled task that runs once a day.

## Installing

Open an elevated PowerShell terminal, move to the directory containing the GatewayUpdater.ps1 script, and then run it with the 'install' parameter:

```powershell
PS > .\GatewayUpdater.ps1 install

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\                                              Devolutions Gateway Updater       Ready
Updater script installed to 'C:\Program Files\Devolutions\Gateway Updater\GatewayUpdater.ps1' and registered as 'Devolutions Gateway Updater' scheduled task
```

The GatewayUpdater.ps1 script will be copied to "$Env:ProgramFiles\Devolutions\Gateway Updater" and registered as a scheduled task named 'Devolutions Gateway Updater" that runs once per day at 3AM.

## Running

You can wait for the scheduled task to run automatically at 3AM, or manually trigger it to see if it works:

```powershell
& schtasks.exe /Run /TN "Devolutions Gateway Updater"
```

You can then query the status of the 'Devolutions Gateway Updater' scheduled task:

```powershell
PS > schtasks.exe /Query /TN "Devolutions Gateway Updater"

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
Devolutions Gateway Updater              2023-06-17 3:00:00 AM  Ready
```

The updater checks if a new version of Devolutions Gateway has been published, and then proceeds to automatically download the installer, check its file hash before running it silently.

## Uninstalling

To uninstall the Devolutions Gateway Updater, run the GatewayUpdater.ps1 script with the 'uninstall' parameter:

```powershell
PS > .\GatewayUpdater.ps1 uninstall

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
Devolutions Gateway Updater              2023-06-17 3:00:00 AM  Ready
SUCCESS: The scheduled task "Devolutions Gateway Updater" was successfully deleted.
```

This will unregister the scheduled task, and delete the GatewayUpdater.ps1 script from 'C:\Program Files\Devolutions\Gateway Updater'
