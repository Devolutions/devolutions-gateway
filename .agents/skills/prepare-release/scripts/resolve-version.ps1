#!/bin/env pwsh
# resolve-version.ps1
# Resolves the next release version given an argument and the current VERSION file.
#
# Usage:
#   ./resolve-version.ps1 [-Arg <argument>] [-VersionFile <path>]
#
# Argument values:
#   minor          Bump the patch number (third component). E.g. 2026.2.0 -> 2026.2.1
#   major          Bump the minor number (second component), reset patch to 0.
#                  The minor number must stay between 1 and 3.
#                  If already 3, roll over: bump year and set minor to 1.
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

if ($Arg -eq "minor") {
    $parts = $current -split '\.'
    if ($parts.Count -ne 3) {
        Write-Error "Unexpected version format in VERSION file: '$current'"
        exit 1
    }
    $parts[2] = [string]([int]$parts[2] + 1)
    Write-Output ($parts -join '.')
    exit 0
}

if ($Arg -eq "major") {
    $parts = $current -split '\.'
    if ($parts.Count -ne 3) {
        Write-Error "Unexpected version format in VERSION file: '$current'"
        exit 1
    }
    $year  = [int]$parts[0]
    $minor = [int]$parts[1]

    if ($minor -eq 3) {
        $year  = $year + 1
        $minor = 1
    } else {
        $minor = $minor + 1
    }
    Write-Output "$year.$minor.0"
    exit 0
}

# Explicit version string — validate format then pass through
if ($Arg -match '^\d{4}\.\d+\.\d+$') {
    Write-Output $Arg
    exit 0
}

Write-Error "Unrecognised argument '$Arg'. Expected 'minor', 'major', or an explicit version like '2026.2.0'."
exit 1
