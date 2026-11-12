<#
.SYNOPSIS
    Serves a locally built Devolutions Agent and the install scripts to test machines. Development only.

.DESCRIPTION
    Copies the agent builds, the optional test root CA and the install scripts into a staging folder, sets the
    development URL in the served scripts, then starts an HTTP server. On a test machine, run the command that
    Remote Desktop Manager copies, with the script URL changed to this server:

      Windows: $env:DEVOLUTIONS_ENROLLMENT_TOKEN='dvaet1...'; irm http://<host>:<port>/install-agent.ps1 | iex
      Linux:   curl -fsSL http://<host>:<port>/install-agent.sh | sudo DEVOLUTIONS_ENROLLMENT_TOKEN='dvaet1...' sh

    The served scripts install the local builds instead of the published MSI or .deb package. The published
    scripts are not changed and keep the latest version from productinfo.json.

.EXAMPLE
    .\Start-DevInstallServer.ps1 -HostAddress 100.95.53.36 -LinuxAgent 'D:\Shared\linux\devolutions-agent' -CaPem .\dvls-ca.pem
#>
param(
    # The address that the test machines use to reach this computer. Default: the first IPv4 address that is not loopback.
    [string] $HostAddress,

    [int] $Port = 5002,

    [string] $WindowsAgent = (Join-Path $PSScriptRoot '..\..\target\release\devolutions-agent.exe'),

    # A Linux x64 build of devolutions-agent, for example from cargo zigbuild. Optional.
    [string] $LinuxAgent,

    # The root CA of a test Devolutions Server certificate. The agent trusts it in addition to the system store. Optional.
    [string] $CaPem,

    [string] $StagingPath = (Join-Path ([IO.Path]::GetTempPath()) 'devolutions-agent-dev')
)

$ErrorActionPreference = 'Stop'

if (-not $HostAddress) {
    $HostAddress = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
}

$devUrl = "http://${HostAddress}:$Port"

if (Test-Path $StagingPath) {
    Remove-Item -Path $StagingPath -Recurse -Force
}
New-Item -ItemType Directory -Path $StagingPath | Out-Null

if (Test-Path $WindowsAgent) {
    Copy-Item -Path $WindowsAgent -Destination (Join-Path $StagingPath 'DevolutionsAgent.exe')
}
else {
    Write-Warning "No Windows agent at $WindowsAgent. Windows machines cannot install."
}

if ($LinuxAgent) {
    Copy-Item -Path $LinuxAgent -Destination (Join-Path $StagingPath 'devolutions-agent')
}

if ($CaPem) {
    Copy-Item -Path $CaPem -Destination (Join-Path $StagingPath 'dvls-ca.pem')
}

$ps1 = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'install-agent.ps1'))
$ps1 = [regex]::Replace($ps1, "(?m)^(\s*)\`$DevUrl = ''", "`${1}`$`$DevUrl = '$devUrl'")
[IO.File]::WriteAllText((Join-Path $StagingPath 'install-agent.ps1'), $ps1)

$sh = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'install-agent.sh')).Replace("`r`n", "`n")
$sh = [regex]::Replace($sh, "(?m)^DEV_URL=''", "DEV_URL='$devUrl'")
[IO.File]::WriteAllText((Join-Path $StagingPath 'install-agent.sh'), $sh)

Write-Host "Serving $StagingPath at $devUrl" -ForegroundColor Cyan
Get-ChildItem -Path $StagingPath | ForEach-Object { Write-Host "  $devUrl/$($_.Name)" }
Write-Host 'Press Ctrl+C to stop.'

python -m http.server $Port --bind 0.0.0.0 --directory $StagingPath
