# This module contains shared code for building and packaging.

# Gets the native target triplet of the machine that is invoking cargo.
#
# Usage:
# $nativeTarget, $isNativeTarget = (Get-NativeTarget $Target).Values
function Get-NativeTarget {
    param (
        [string]$Target  # The specified target, used to check if it is the native target
    )

    $nativeTarget = (rustc -vV | Select-String 'host:').ToString().Split(':')[1].TrimStart()

    if (-Not $Target) {
        Write-Host "Target not specified; detected $nativeTarget"
        $isNativeTarget = $true
    }
    elseif ($Target -Eq $nativeTarget) {
        $isNativeTarget = $true
    }

    return @{
        NativeTarget   = $nativeTarget
        IsNativeTarget = $isNativeTarget
    }
}

# Reads the VERSION file and returns the version.
function Get-Version {
    # We are currently in ci/Build. Go two levels up.
    $repoDir = Split-Path -Parent $PSScriptRoot
    $repoDir = Split-Path -Parent $repoDir

    $f = Join-Path $repoDir 'VERSION'

    if (-Not (Test-Path $f)) {
        throw "VERSION file not found at $f"
    }
    return $(Get-Content -Path $f -Raw).Trim()
}

function Get-PackageLanguages {
    return @(
        [PSCustomObject]@{ Name = 'en-US'; LCID = 1033 },
        [PSCustomObject]@{ Name = 'fr-FR'; LCID = 1036 }
    )
}

# Sets the specified envrionment varaible to the given path.
#
# If the environment variable is not set, it is set to the path.
# If the environment variable is set to a different value than the path provided, an error is thrown.
# If the path does not exist, an error is thrown.
function Set-EnvVarPath {
    param (
        [string]$Var,
        [string]$Path
    )

    $envVar = ${Env:$Var}

    if (-not $envVar) {
        Write-Output "$Var is not set. Setting it to $Path"
        
        [Environment]::SetEnvironmentVariable($Var, $Path)
    }
    elseif ($envVar -ne $Path) {
        throw "$Var is set to $envVar but passed parameter is $Path"
    }

    if (-not (Test-Path $Path)) {
        throw "$Path not found"
    }
}

Export-ModuleMember -Function Get-NativeTarget
Export-ModuleMember -Function Get-Version
Export-ModuleMember -Function Get-PackageLanguages
Export-ModuleMember -Function Set-EnvVarPath
