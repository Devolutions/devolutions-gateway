---
name: run-gateway-local
description: Launch Devolutions Gateway from source for local coding-agent tests with loopback listeners by default; require explicit opt-in before binding to non-localhost addresses.
---

# Run Devolutions Gateway Locally

Use this skill whenever a coding agent needs to run the Gateway from the repository for local development or testing.

The production configuration template intentionally uses wildcard listener hosts, so do not change
`ConfFile::generate_new` or installed service configuration to solve a local testing problem.
Instead, use a separate working configuration under the repository's ignored `config\` directory
and bind its listeners to `127.0.0.1` by default.

## Default launch

1. Build the Gateway binary:

   ```powershell
   cargo build -p devolutions-gateway
   ```

2. Use a known-good `config\gateway.json` containing the provisioner key material required by the
   test. If a configuration does not exist yet, initialize it with
   `cargo run -p devolutions-gateway -- --config-path .\config --config-init-only`, then complete
   the normal local key setup before starting the service.

3. Before launching, normalize both `InternalUrl` and `ExternalUrl` hosts in the working copy.
   The following template keeps the configured schemes and ports while replacing wildcard,
   hostname, and other interface hosts:

   ```powershell
   $BindHost = '127.0.0.1'
   $AllowRemoteBinding = $false
   $LoopbackHosts = @('127.0.0.1', 'localhost', '::1')

   if ($BindHost -notin $LoopbackHosts -and -not $AllowRemoteBinding) {
       throw "Refusing non-localhost Gateway binding. Set `$AllowRemoteBinding only for an intentional remote test."
   }

   $ConfigDir = Join-Path $PWD 'config'
   $ConfigFile = Join-Path $ConfigDir 'gateway.json'
   $Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json

   foreach ($Listener in $Config.Listeners) {
       $Listener.InternalUrl = $Listener.InternalUrl -replace '(?<=://)(\[[^\]]+\]|[^/:]+)', $BindHost
       $Listener.ExternalUrl = $Listener.ExternalUrl -replace '(?<=://)(\[[^\]]+\]|[^/:]+)', $BindHost
   }

   $Config | ConvertTo-Json -Depth 20 | Set-Content $ConfigFile
   $Env:DGATEWAY_CONFIG_PATH = $ConfigDir
   cargo run -p devolutions-gateway
   ```

Use `Invoke-WebRequest http://127.0.0.1:7171/jet/health` or the endpoint required by the test
to verify readiness, and stop the foreground process with `Ctrl+C`.

## Remote-device testing

Binding to a machine address is an explicit exception, not a default. Set `$BindHost` to the
specific address or hostname that the other device must reach and set `$AllowRemoteBinding = $true`
in the launch template only for that test. Do not use `*`, `0.0.0.0`, or `[::]` unless the test
specifically requires all interfaces and the opt-in is documented in the agent's test notes.
Expect Windows Firewall to prompt when a non-loopback listener is started, and restore the
loopback configuration after the remote test.

Never point this workflow at the installed `%ProgramData%\Devolutions\Gateway` configuration or
modify production listener defaults.
