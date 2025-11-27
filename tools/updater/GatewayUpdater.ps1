
function Install-DGatewayUpdater
{
    [CmdletBinding()]
    param (
    )

    $InstallPath = "$Env:ProgramFiles\Devolutions\Gateway Updater"
    $ScriptPath = Join-Path $InstallPath "GatewayUpdater.ps1"
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    Copy-Item -Path $PSCommandPath -Destination $ScriptPath -Force
    Register-DGatewayUpdater -ScriptPath $ScriptPath

    $TaskName = "Devolutions Gateway Updater"
    Write-Host "Updater script installed to '$ScriptPath' and registered as '$TaskName' scheduled task"
}

function Uninstall-DGatewayUpdater
{
    [CmdletBinding()]
    param (
    )

    Unregister-DGatewayUpdater

    $InstallPath = "$Env:ProgramFiles\Devolutions\Gateway Updater"
    $ScriptPath = Join-Path $InstallPath "GatewayUpdater.ps1"
    Remove-Item $ScriptPath -ErrorAction SilentlyContinue -Force | Out-Null
}

function Register-DGatewayUpdater
{
    [CmdletBinding()]
    param (
        [string] $ScriptPath
    )

    if ([string]::IsNullOrEmpty($ScriptPath)) {
        $ScriptPath = $PSCommandPath
    }

    Unregister-DGatewayUpdater

    $TaskName = "Devolutions Gateway Updater"
    $TaskUser = "NT AUTHORITY\SYSTEM"
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserID $TaskUser -LogonType ServiceAccount -RunLevel Highest
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $TaskTrigger = New-ScheduledTaskTrigger -Daily -At 3AM
    Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal
}

function Unregister-DGatewayUpdater
{
    [CmdletBinding()]
    param (
    )

    $TaskName = "Devolutions Gateway Updater"
    & schtasks.exe /Query /TN $TaskName 2>$null
    $TaskExists = [bool] ($LASTEXITCODE -eq 0)

    if ($TaskExists) {
        & schtasks.exe /Delete /TN $TaskName /F
    }
}

function Get-DGatewayInstalledVersion
{
    [CmdletBinding()]
    param(
    )

    $UninstallReg = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' `
    | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_ -Match 'Devolutions Gateway' }
    if ($UninstallReg) {
        $DGatewayVersion = '20' + $UninstallReg.DisplayVersion
    }
    $DGatewayVersion
}

function Get-DGatewayPackageLocation
{
    [CmdletBinding()]
    param(
        [string] $RequiredVersion
    )

    $VersionQuad = '';
    $ProductsUrl = "https://devolutions.net/productinfo.json"

    $ProductsJson = Invoke-RestMethod -Uri $ProductsUrl -Method 'GET' -ContentType 'application/json'
    $LatestVersion = $ProductsJson.Gateway.Current.Version

    if ($RequiredVersion) {
        if ($RequiredVersion -Match "^\d+`.\d+`.\d+$") {
            $RequiredVersion = $RequiredVersion + ".0"
        }
        $VersionQuad = $RequiredVersion
    } else {
        $VersionQuad = $LatestVersion
    }

    $VersionMatches = $($VersionQuad | Select-String -AllMatches -Pattern "(\d+)`.(\d+)`.(\d+)`.(\d+)").Matches
    $VersionMajor = $VersionMatches.Groups[1].Value
    $VersionMinor = $VersionMatches.Groups[2].Value
    $VersionPatch = $VersionMatches.Groups[3].Value
    $VersionTriple = "${VersionMajor}.${VersionMinor}.${VersionPatch}"

    # Find the MSI file for the current architecture
    $CurrentArchitecture = if ([Environment]::Is64BitProcess) { "x64" } else { "arm64" }
    $GatewayMsiFile = $ProductsJson.Gateway.Current.Files | Where-Object { $_.Type -eq 'msi' -and $_.Arch -eq $CurrentArchitecture } | Select-Object -First 1
    
    if ($GatewayMsiFile) {
        $DownloadUrl = $GatewayMsiFile.Url
        $DownloadHash = $GatewayMsiFile.Hash
    }

    if ($RequiredVersion) {
        $DownloadUrl = $DownloadUrl -Replace $LatestVersion, $RequiredVersion
    }
 
    [PSCustomObject]@{
        Url = $DownloadUrl
        Hash = $DownloadHash
        Version = $VersionTriple
    }
}

function Get-DGatewayPackageFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $DownloadUrl,
        [Parameter(Mandatory = $true)]
        [string] $DownloadHash,
        [string] $DownloadPath
    )

    $FileName = [System.IO.Path]::GetFileName($DownloadUrl)

    if ([string]::IsNullOrEmpty($DownloadPath)) {
        $TempPath = [System.IO.Path]::GetTempPath()
        $DownloadPath = Join-Path -Path $TempPath -ChildPath $FileName
    }

    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($DownloadUrl, $DownloadPath)
    $FileHash = (Get-FileHash -Path $DownloadPath -Algorithm SHA256).Hash

    if ($FileHash -ne $DownloadHash) {
        throw "$FileName hash mismatch: Actual: $FileHash, Expected: $DownloadHash"
    }

    $DownloadPath
}

function Install-DGatewayPackage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $InstallerPath,
        [switch] $Quiet,
        [switch] $Force
    )

    $Display = '/passive'
    if ($Quiet) {
        $Display = '/quiet'
    }

    $TempPath = Join-Path $([System.IO.Path]::GetTempPath()) "dgateway-${Version}"
    New-Item -ItemType Directory -Path $TempPath -ErrorAction SilentlyContinue | Out-Null
    $InstallLogFile = Join-Path $TempPath 'DGateway_Install.log'
    
    $MsiArgs = @(
        '/i', "`"$InstallerPath`"",
        $Display,
        '/norestart',
        '/log', "`"$InstallLogFile`""
    )

    Start-Process 'msiexec.exe' -ArgumentList $MsiArgs -Wait -NoNewWindow
    Remove-Item -Path $InstallLogFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempPath -Force -Recurse
}

function Uninstall-DGatewayPackage
{
    [CmdletBinding()]
    param(
        [switch] $Quiet
    )

    $UninstallReg = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' `
    | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_ -Match 'Devolutions Gateway' }
    if ($UninstallReg) {
        $UninstallString = $($UninstallReg.UninstallString `
                -Replace 'msiexec.exe', '' -Replace '/I', '' -Replace '/X', '').Trim()
        $Display = '/passive'
        if ($Quiet) {
            $Display = '/quiet'
        }
        $MsiArgs = @(
            '/X', $UninstallString, $Display
        )
        Start-Process 'msiexec.exe' -ArgumentList $MsiArgs -Wait
    }
}

function Invoke-DGatewayUpdater
{
    [CmdletBinding()]
    param(
    )

    $CurrentVersion = Get-DGatewayInstalledVersion
    $Package = Get-DGatewayPackageLocation

    if ($CurrentVersion -ne $Package.Version) {
        $DownloadPath = Get-DGatewayPackageFile -DownloadUrl $Package.Url -DownloadHash $Package.Hash

        if ($DownloadPath) {
            if ([Version] $Package.Version -lt [Version] $CurrentVersion) {
                Uninstall-DGatewayPackage -Quiet
            }
            Install-DGatewayPackage -InstallerPath $DownloadPath -Quiet
        }
    }
}

$CmdVerbs = @('run', 'install', 'uninstall', 'register', 'unregister')

if ($args.Count -lt 1) {
    $CmdVerb = "run"
    $CmdArgs = @()
} else {
    $CmdVerb = $args[0]
    $CmdArgs = $args[1..$args.Count]
}

if ($CmdVerbs -NotContains $CmdVerb) {
    throw "invalid verb $CmdVerb, use one of: [$($CmdVerbs -Join ',')]"
}

switch ($CmdVerb) {
    "run" { Invoke-DGatewayUpdater @CmdArgs }
    "install" { Install-DGatewayUpdater @CmdArgs }
    "uninstall" { Uninstall-DGatewayUpdater @CmdArgs }
    "register" { Register-DGatewayUpdater @CmdArgs }
    "unregister" { Unregister-DGatewayUpdater @CmdArgs }
}
