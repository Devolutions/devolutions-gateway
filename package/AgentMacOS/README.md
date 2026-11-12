# Devolutions Agent for macOS

The installer package runs Devolutions Agent as the `com.devolutions.agent` launchd daemon, as root.
There is one package per architecture; install the one that matches the Mac.

```sh
sudo installer -pkg devolutions-agent-<version>-arm64.pkg -target /
```

The package installs these files:

| Path | Content |
| --- | --- |
| `/usr/local/bin/devolutions-agent` | Agent executable |
| `/usr/local/bin/devolutions-agent-uninstall` | Uninstall script |
| `/Library/LaunchDaemons/com.devolutions.agent.plist` | launchd daemon definition |
| `/Library/Application Support/Devolutions Agent` | Configuration and credentials, readable by root only |
| `/Library/Logs/Devolutions Agent` | Standard output and error of the daemon |

The Agent writes its own log files to the configuration directory.
Installing creates a default `agent.json` when none exists, then starts the daemon; launchd restarts it after a crash and at boot.
Upgrading keeps the existing configuration.

Start and stop the daemon with the Agent itself or with `launchctl`:

```sh
sudo devolutions-agent stop
sudo devolutions-agent start
sudo launchctl kickstart -k system/com.devolutions.agent
```

PowerShell Universal jobs require PowerShell 7 installed with [Microsoft's macOS package][powershell-macos].
The root daemon searches `/usr/local/microsoft/powershell/7` and system directories, not Homebrew prefixes.

Uninstall the Agent and keep its configuration, or remove everything with `--purge`:

```sh
sudo devolutions-agent-uninstall
sudo devolutions-agent-uninstall --purge
```

Build a package from a built executable on macOS:

```sh
DAGENT_EXECUTABLE=target/release/devolutions-agent pwsh ./ci/tlk.ps1 package -Product agent -Platform macos -Architecture arm64
```

Set `DAGENT_PKG_SIGNING_IDENTITY` to a Developer ID Installer identity to sign the package.
`Test-Package.sh` installs a package, checks the daemon, upgrades, and uninstalls it; run it only on a disposable machine.

[powershell-macos]: https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-macos?view=powershell-7.6
