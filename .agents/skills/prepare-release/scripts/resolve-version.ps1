#!/usr/bin/env pwsh
# resolve-version.ps1
# Resolves the next release version given an argument and the current VERSION file.
#
# Usage:
#   ./resolve-version.ps1 [-Arg <argument>] [-VersionFile <path>]
#
# Argument values:
#   hotfix         Bump the patch number (third component). E.g. 2026.2.0 -> 2026.2.1
#   cycle          Bump the release number (second component), reset patch to 0.
#                  The release number must stay between 1 and 3.
#                  If already 3, roll over: bump year and set release to 1.
#                  E.g. 2026.2.1 -> 2026.3.0, 2026.3.0 -> 2027.1.0
#   <X.Y.Z>        Use the provided version string as-is (no calculation).
#   (empty)        Print the current version and exit with code 2 to signal
#                  that the caller should ask the user for input.
#
# Output:
#   Prints the resolved version string to stdout.
#   Exits with code 0 on success, 1 on error, 2 when no argument was provided.

param(
    [string] $Arg = "",
    [string] $VersionFile = "./VERSION"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $VersionFile)) {
    Write-Error "VERSION file not found at '$VersionFile'"
    exit 1
}

$current = (Get-Content $VersionFile -Raw).Trim()

if ($Arg -eq "") {
    Write-Output $current
    exit 2
}

if ($Arg -eq "hotfix") {
    $parts = $current -split '\.'
    if ($parts.Count -ne 3) {
        Write-Error "Unexpected version format in VERSION file: '$current'"
        exit 1
    }
    $release = [int]$parts[1]
    if ($release -lt 1 -or $release -gt 3) {
        Write-Error "Release component '$release' in VERSION file is out of range [1,3]: '$current'"
        exit 1
    }
    $parts[2] = [string]([int]$parts[2] + 1)
    Write-Output ($parts -join '.')
    exit 0
}

if ($Arg -eq "cycle") {
    $parts = $current -split '\.'
    if ($parts.Count -ne 3) {
        Write-Error "Unexpected version format in VERSION file: '$current'"
        exit 1
    }
    $year    = [int]$parts[0]
    $release = [int]$parts[1]

    if ($release -lt 1 -or $release -gt 3) {
        Write-Error "Release component '$release' in VERSION file is out of range [1,3]: '$current'"
        exit 1
    }
    if ($release -eq 3) {
        $year    = $year + 1
        $release = 1
    } else {
        $release = $release + 1
    }
    Write-Output "$year.$release.0"
    exit 0
}

# Explicit version string — parse components and validate consistently
if ($Arg -match '^\d{4}\.\d+\.\d+$') {
    $explicitParts = $Arg -split '\.'
    $year    = 0
    $release = 0
    $patch   = 0

    if (-not [int]::TryParse($explicitParts[0], [ref]$year) -or
        -not [int]::TryParse($explicitParts[1], [ref]$release) -or
        -not [int]::TryParse($explicitParts[2], [ref]$patch)) {
        Write-Error "Explicit version '$Arg' must contain numeric year, release, and patch components."
        exit 1
    }

    if ($release -lt 1 -or $release -gt 3) {
        Write-Error "Release component '$release' in explicit version argument is out of range [1,3]: '$Arg'"
        exit 1
    }

    Write-Output $Arg
    exit 0
}

Write-Error "Unrecognised argument '$Arg'. Expected 'hotfix', 'cycle', or an explicit version like '2026.2.0'."
exit 1
