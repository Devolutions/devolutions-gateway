# Installs Devolutions Agent, turns on Device Management and enrolls the device with Devolutions Server.
#
# Usage (PowerShell as administrator):
#   $env:DEVOLUTIONS_ENROLLMENT_TOKEN='dvaet1...'; irm https://raw.githubusercontent.com/Devolutions/devolutions-gateway/master/package/install/install-agent.ps1 | iex
#
# Optional environment variables:
#   DEVOLUTIONS_AGENT_INSTALLER_URL     Installs this MSI instead of the latest published one.
#   DEVOLUTIONS_AGENT_INSTALLER_SHA256  Expected SHA-256 of the MSI set by DEVOLUTIONS_AGENT_INSTALLER_URL.
#   DEVOLUTIONS_AGENT_DEV_URL           Development only. Base URL of a server that gives a locally built agent
#                                       (DevolutionsAgent.exe) and, optionally, the test root CA of the server (dvls-ca.pem).
#                                       See Start-DevInstallServer.ps1. No MSI is installed in this mode.
#
# The script has no param block so that it also runs through `irm | iex`. It never writes the token.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $ProductInfoUrl = 'https://devolutions.net/productinfo.json'
    $ServiceName = 'DevolutionsAgent'

    # Start-DevInstallServer.ps1 sets this value in the copy of the script that it serves.
    $DevUrl = ''
    if ($env:DEVOLUTIONS_AGENT_DEV_URL) {
        $DevUrl = $env:DEVOLUTIONS_AGENT_DEV_URL
    }
    $DevUrl = $DevUrl.TrimEnd('/')

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

    $configDir = Join-Path $env:ProgramData 'Devolutions\Agent'
    $configPath = Join-Path $configDir 'agent.json'
    $devCaFile = $null

    if ($DevUrl) {
        Write-Warning "Development mode: installing the Devolutions Agent build from $DevUrl."
        $installDir = Join-Path $env:ProgramFiles 'Devolutions\Agent'
        $agentExe = Join-Path $installDir 'DevolutionsAgent.exe'
        $downloadPath = Join-Path ([IO.Path]::GetTempPath()) ("DevolutionsAgent-{0}.exe" -f [guid]::NewGuid().ToString('N'))
        try {
            Write-Host "Downloading $DevUrl/DevolutionsAgent.exe..."
            Invoke-WebRequest -Uri "$DevUrl/DevolutionsAgent.exe" -OutFile $downloadPath -UseBasicParsing

            Write-Host 'Installing Devolutions Agent...'
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Stopped') {
                Stop-Service -Name $ServiceName -Force
                $service.WaitForStatus('Stopped', '00:00:30')
            }
            Get-Process -Name 'DevolutionsAgent' -ErrorAction SilentlyContinue | Stop-Process -Force

            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
            Get-ChildItem -Path "$agentExe.old*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            # Windows can lock the executable after the process stops. A locked file cannot be overwritten, but it can be renamed.
            if (Test-Path $agentExe) {
                Move-Item -Path $agentExe -Destination "$agentExe.old$([DateTime]::Now.Ticks)" -Force
            }
            Copy-Item -Path $downloadPath -Destination $agentExe -Force

            if (-not $service) {
                New-Service -Name $ServiceName -BinaryPathName "`"$agentExe`"" -DisplayName 'Devolutions Agent' -StartupType Automatic | Out-Null
            }
        }
        finally {
            Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue
        }

        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        try {
            Invoke-WebRequest -Uri "$DevUrl/dvls-ca.pem" -OutFile (Join-Path $configDir 'dvls-ca.pem') -UseBasicParsing
            $devCaFile = 'dvls-ca.pem'
            Write-Host 'The agent trusts the test root CA from the development server.'
        }
        catch {
            Write-Host 'The development server gives no test root CA. The agent uses the system trust store.'
        }
    }
    else {
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
    }

    if (-not (Test-Path $agentExe)) {
        Stop-Install "$agentExe is missing after the installation."
    }

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
    if ($DevUrl) {
        # Development builds of UniGetUI are not signed, so the broker does not validate the caller signature.
        $config | Add-Member -NotePropertyName 'PackageBroker' -NotePropertyValue ([pscustomobject]@{ Enabled = $true }) -Force
        $debug = [pscustomobject]@{ skip_broker_signature_validation = $true }
        if ($devCaFile) {
            $debug | Add-Member -NotePropertyName 'identity' -NotePropertyValue ([pscustomobject]@{ extra_trusted_root = $devCaFile })
        }
        $config | Add-Member -NotePropertyName '__debug__' -NotePropertyValue $debug -Force
    }

    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))

    if ($DevUrl) {
        $policyPath = Join-Path $env:ProgramData 'Devolutions\PackageBroker\package-broker-policy.json'
        $policyDir = Split-Path $policyPath
        New-Item -ItemType Directory -Path $policyDir -Force | Out-Null
        # The broker refuses a policy folder that inherits the ProgramData ACL, because users can create files there.
        icacls $policyDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
        icacls $policyDir /setowner '*S-1-5-32-544' /T | Out-Null
        if (-not (Test-Path $policyPath)) {
            [IO.File]::WriteAllText($policyPath, '{"PolicyFormatVersion":"1.0.0","Metadata":{"Id":"dev.allow-all","Publisher":"Development","Revision":1,"PublishedAt":"2026-10-21T00:00:00Z","Description":"Allow all package operations."},"Enforcement":{"DefaultDecision":"Allow"},"Rules":[]}')
        }
    }

    # The service creates the identity drop box when it starts, and enrollment needs it.
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Stop-Install "the $ServiceName service is missing."
    }

    if ($service.Status -ne 'Running') {
        Start-Service -Name $ServiceName
        $service.WaitForStatus('Running', '00:00:30')
    }

    Write-Host 'Enrolling the device...'
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        # Windows PowerShell turns native stderr into a terminating error when the preference is Stop.
        $ErrorActionPreference = 'Continue'
        $enrollOutput = $token.Trim() | & $agentExe identity enroll - 2>&1
        $enrollExitCode = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $notReady = $enrollExitCode -ne 0 -and ($enrollOutput | Out-String) -match 'has not prepared the enrollment directory'
        if ($notReady) {
            Start-Sleep -Seconds 2
        }
    } while ($notReady -and [DateTime]::UtcNow -lt $deadline)

    if ($enrollExitCode -ne 0) {
        $enrollOutput | ForEach-Object { Write-Host $_ }
    }
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
