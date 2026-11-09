# Installs Devolutions Agent, turns on Device Management and enrolls the device with Devolutions Server.
#
# Usage (PowerShell as administrator):
#   $env:DEVOLUTIONS_ENROLLMENT_TOKEN='dvaet1...'; irm https://raw.githubusercontent.com/Devolutions/devolutions-gateway/master/package/install/install-agent.ps1 | iex
#
# Optional environment variables:
#   DEVOLUTIONS_AGENT_INSTALLER_URL     Installs this MSI instead of the latest published one.
#   DEVOLUTIONS_AGENT_INSTALLER_SHA256  Expected SHA-256 of the MSI set by DEVOLUTIONS_AGENT_INSTALLER_URL.
#
# The script has no param block so that it also runs through `irm | iex`. It never writes the token.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $ProductInfoUrl = 'https://devolutions.net/productinfo.json'
    $ServiceName = 'DevolutionsAgent'

    function Stop-Install([string] $Message) {
        Remove-Item Env:\DEVOLUTIONS_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
        throw "Devolutions Agent installation failed: $Message"
    }

    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-Install 'run this command in PowerShell as administrator.'
    }

    $token = $env:DEVOLUTIONS_ENROLLMENT_TOKEN
    if ([string]::IsNullOrWhiteSpace($token) -or -not $token.Trim().StartsWith('dvaet1.')) {
        Stop-Install 'set DEVOLUTIONS_ENROLLMENT_TOKEN to the enrollment token from Remote Desktop Manager.'
    }

    $installerUrl = $env:DEVOLUTIONS_AGENT_INSTALLER_URL
    $expectedHash = $env:DEVOLUTIONS_AGENT_INSTALLER_SHA256
    if ([string]::IsNullOrWhiteSpace($installerUrl)) {
        $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        $arch = switch ($architecture) {
            'AMD64' { 'x64' }
            'ARM64' { 'arm64' }
            default { Stop-Install "the $architecture architecture is not supported." }
        }

        Write-Host 'Reading the latest Devolutions Agent version...'
        $productInfo = Invoke-RestMethod -Uri $ProductInfoUrl -UseBasicParsing
        $file = $productInfo.Agent.Current.Files | Where-Object { $_.Type -eq 'msi' -and $_.Arch -eq $arch } | Select-Object -First 1
        if (-not $file) {
            Stop-Install "no Devolutions Agent installer is available for Windows $arch."
        }

        $installerUrl = $file.Url
        $expectedHash = $file.Hash
    }

    $msiPath = Join-Path ([IO.Path]::GetTempPath()) ("DevolutionsAgent-{0}.msi" -f [guid]::NewGuid().ToString('N'))
    try {
        Write-Host "Downloading $installerUrl..."
        Invoke-WebRequest -Uri $installerUrl -OutFile $msiPath -UseBasicParsing

        if (-not [string]::IsNullOrWhiteSpace($expectedHash)) {
            $actualHash = (Get-FileHash -Path $msiPath -Algorithm SHA256).Hash
            if ($actualHash -ne $expectedHash.Trim().ToUpperInvariant()) {
                Stop-Install 'the SHA-256 hash of the downloaded installer is not correct.'
            }
        }
        else {
            Write-Warning 'The installer hash is not checked because DEVOLUTIONS_AGENT_INSTALLER_SHA256 is not set.'
        }

        Write-Host 'Installing Devolutions Agent...'
        $logPath = Join-Path ([IO.Path]::GetTempPath()) 'DevolutionsAgent-install.log'
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$logPath`"") -Wait -PassThru
        if ($process.ExitCode -notin @(0, 3010)) {
            Stop-Install "msiexec stopped with exit code $($process.ExitCode). See $logPath."
        }
    }
    finally {
        Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
    }

    $installDir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Devolutions\Agent' -Name 'InstallDir' -ErrorAction SilentlyContinue).InstallDir
    if (-not $installDir) {
        $installDir = Join-Path $env:ProgramFiles 'Devolutions\Agent'
    }

    $agentExe = Join-Path $installDir 'DevolutionsAgent.exe'
    if (-not (Test-Path $agentExe)) {
        Stop-Install "$agentExe is missing after the installation."
    }

    $configPath = Join-Path $env:ProgramData 'Devolutions\Agent\agent.json'
    if (-not (Test-Path $configPath)) {
        & $agentExe config init | Out-Null
    }

    Write-Host 'Turning on Device Management...'
    $config = $null
    if (Test-Path $configPath) {
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    }

    if (-not $config) {
        $config = [pscustomobject]@{}
    }

    $config | Add-Member -NotePropertyName 'DeviceManagement' -NotePropertyValue ([pscustomobject]@{ Enabled = $true }) -Force
    New-Item -ItemType Directory -Path (Split-Path $configPath) -Force | Out-Null
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))

    Write-Host 'Enrolling the device...'
    $token.Trim() | & $agentExe identity enroll - | Out-Null
    $enrollExitCode = $LASTEXITCODE
    $token = $null
    Remove-Item Env:\DEVOLUTIONS_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    if ($enrollExitCode -ne 0) {
        Stop-Install "the enrollment command stopped with exit code $enrollExitCode."
    }

    Write-Host 'Restarting the Devolutions Agent service...'
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Stop-Install "the $ServiceName service is missing."
    }

    Set-Service -Name $ServiceName -StartupType Automatic
    if ($service.Status -eq 'Running') {
        Restart-Service -Name $ServiceName -Force
    }
    else {
        Start-Service -Name $ServiceName
    }

    Write-Host 'Devolutions Agent is installed. The device enrolls with Devolutions Server in a few seconds.' -ForegroundColor Green
}
