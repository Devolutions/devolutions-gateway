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

2. From the repository or a child directory, run this complete preparation block.
   It creates the ignored `config\` directory, generates the required provisioner key pair on
   first use, rewrites every listener to the selected host, and refuses unapproved remote binds.
   The first run requires the .NET SDK to build the local PowerShell module.

   ```powershell
   $RepoRoot = (git rev-parse --show-toplevel).Trim()
   if ($LASTEXITCODE -ne 0) {
       throw 'Run this command from the Devolutions Gateway repository or one of its child directories.'
   }

   $ErrorActionPreference = 'Stop'
   $ConfigDir = Join-Path $RepoRoot 'config'
   $ConfigFile = Join-Path $ConfigDir 'gateway.json'
   $BindHost = '127.0.0.1'
   $AllowRemoteBinding = $false
   $LoopbackHosts = @('127.0.0.1', 'localhost', '::1')
   $BindHost = $BindHost.TrimStart('[').TrimEnd(']')
   $UrlBindHost = if ($BindHost.Contains(':')) { "[$BindHost]" } else { $BindHost }

   if ($BindHost -notin $LoopbackHosts -and -not $AllowRemoteBinding) {
       throw "Refusing non-localhost Gateway binding. Set `$AllowRemoteBinding only for an intentional remote test."
   }

   if (-not (Test-Path -LiteralPath $ConfigFile)) {
       New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
       cargo run -p devolutions-gateway -- --config-path $ConfigDir --config-init-only
       if ($LASTEXITCODE -ne 0) {
           throw 'Gateway configuration initialization failed.'
       }
   }

   $Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
   if ($null -eq $Config.Listeners -or $Config.Listeners.Count -eq 0) {
       throw "No Gateway listeners are configured in $ConfigFile."
   }

   $HasProvisionerPublicKeyFile = -not [string]::IsNullOrWhiteSpace($Config.ProvisionerPublicKeyFile)
   $HasProvisionerPublicKeyData = -not [string]::IsNullOrWhiteSpace($Config.ProvisionerPublicKeyData)
   $ProvisionerPublicKeyPath = $null
   $NeedsProvisionerKey = -not $HasProvisionerPublicKeyFile -and -not $HasProvisionerPublicKeyData
   if ($HasProvisionerPublicKeyFile) {
       $ProvisionerPublicKeyPath = if ([IO.Path]::IsPathRooted($Config.ProvisionerPublicKeyFile)) {
           $Config.ProvisionerPublicKeyFile
       } else {
           Join-Path $ConfigDir $Config.ProvisionerPublicKeyFile
       }
       $NeedsProvisionerKey = -not (Test-Path -LiteralPath $ProvisionerPublicKeyPath -PathType Leaf)
   }

   if ($NeedsProvisionerKey) {
       # The PowerShell module honors this variable even when -ConfigPath is supplied.
       $Env:DGATEWAY_CONFIG_PATH = $ConfigDir
       & (Join-Path $RepoRoot 'powershell\build.ps1')
       if ($LASTEXITCODE -ne 0) {
           throw 'Building the Devolutions Gateway PowerShell module failed.'
       }
       $ModuleDir = Join-Path $RepoRoot 'powershell\package\DevolutionsGateway'
       $ModuleManifest = Join-Path $ModuleDir 'DevolutionsGateway.psd1'
       $PickyAssembly = Join-Path $ModuleDir 'bin\Devolutions.Picky.dll'
       if (-not (Test-Path -LiteralPath $ModuleManifest -PathType Leaf) -or
           -not (Test-Path -LiteralPath $PickyAssembly -PathType Leaf)) {
           throw 'The Devolutions Gateway PowerShell module build did not produce its required artifacts.'
       }
       Import-Module $ModuleManifest
       New-DGatewayProvisionerKeyPair -ConfigPath $ConfigDir
       # Preserve all original config fields after the module writes the generated key paths.
       $Config | Add-Member -NotePropertyName ProvisionerPublicKeyFile -NotePropertyValue 'provisioner.pem' -Force
       $Config | Add-Member -NotePropertyName ProvisionerPrivateKeyFile -NotePropertyValue 'provisioner.key' -Force
   }

   foreach ($Listener in $Config.Listeners) {
       $Listener.InternalUrl = $Listener.InternalUrl -replace '(?<=://)(\[[^\]]+\]|[^/:]+)', $UrlBindHost
       $Listener.ExternalUrl = $Listener.ExternalUrl -replace '(?<=://)(\[[^\]]+\]|[^/:]+)', $UrlBindHost
   }

   $HttpListener = $Config.Listeners |
       Where-Object { $_.InternalUrl -match '^https?://' } |
       Select-Object -First 1
   if ($null -eq $HttpListener) {
       throw 'Gateway configuration has no HTTP listener for the health check.'
   }
   $HealthListenerMatch = [regex]::Match(
       $HttpListener.InternalUrl,
       '^(?<Scheme>https?)://(?:\[[^\]]+\]|[^/:]+):(?<Port>\d+)/?$'
   )
   if (-not $HealthListenerMatch.Success) {
       throw "Unable to determine a health-check URL from $($HttpListener.InternalUrl)."
   }
   $HealthProbeHost = switch ($BindHost) {
       '*' { '127.0.0.1' }
       '0.0.0.0' { '127.0.0.1' }
       '::' { '[::1]' }
       default { $UrlBindHost }
   }
   $HealthUrl = '{0}://{1}:{2}/jet/health' -f `
       $HealthListenerMatch.Groups['Scheme'].Value, `
       $HealthProbeHost, `
       $HealthListenerMatch.Groups['Port'].Value

   [IO.File]::WriteAllText(
       $ConfigFile,
       ($Config | ConvertTo-Json -Depth 20),
       $(New-Object System.Text.UTF8Encoding $False)
   )
   Write-Output "Gateway health URL: $HealthUrl"
   ```

3. Start the Gateway in a dedicated terminal:

   ```powershell
   $RepoRoot = (git rev-parse --show-toplevel).Trim()
   $ConfigDir = Join-Path $RepoRoot 'config'
   cargo run -p devolutions-gateway -- --config-path $ConfigDir
   ```

4. From a second terminal, use the `Gateway health URL` printed by the preparation block with
   `Invoke-WebRequest -Uri <health-url>` or use the endpoint required by the test. Stop the
   foreground process with `Ctrl+C` when testing is complete.

## Remote-device testing

Binding to a machine address is an explicit exception, not a default. Set `$BindHost` to the
specific address or hostname that the other device must reach and set `$AllowRemoteBinding = $true`
in the launch block only for that test. Do not use `*`, `0.0.0.0`, or `[::]` unless the test
specifically requires all interfaces and the opt-in is documented in the agent's test notes.
Expect Windows Firewall to prompt when a non-loopback listener is started, and restore the
loopback configuration after the remote test.

Never point this workflow at the installed `%ProgramData%\Devolutions\Gateway` configuration or
modify production listener defaults. Always use `--config-path $ConfigDir` when running the
Gateway through this workflow.
