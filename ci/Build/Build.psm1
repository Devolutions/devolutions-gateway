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

function Get-GatewayPackageLanguages {
    return @(
        [PSCustomObject]@{ Name = 'en-US'; LCID = 1033 },
        [PSCustomObject]@{ Name = 'fr-FR'; LCID = 1036 },
        [PSCustomObject]@{ Name = 'de-DE'; LCID = 1031 }
    )
}

# Sets the specified environment variable to the given path.
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

# Merges tokens into a text template.
#
# Usage
# Merge-Tokens -TemplateFile 'mytemplate' -Tokens @{ foo = 'bar' }
function Merge-Tokens {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "TemplateValue")]
        [string] $TemplateValue,
        [Parameter(Mandatory = $true, ParameterSetName = "TemplateFile")]
        [string] $TemplateFile,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Hashtable] $Tokens,
        [string] $OutputFile
    )

    if ($TemplateFile) {
        $TemplateValue = Get-Content -Path $TemplateFile -Raw -Encoding UTF8
    }

    $TokenPattern = '{{([^}]+)}}'
    $OutputValue = [regex]::Replace($TemplateValue, $TokenPattern, { param($Match)
            $TokenName = $Match.Groups[1].Value.Trim()
            $Tokens[$TokenName]
        })

    if ($OutputFile) {
        $AsByteStream = if ($PSEdition -Eq 'Core') { @{AsByteStream = $true } } else { @{'Encoding' = 'Byte' } }
        $OutputBytes = $([System.Text.Encoding]::UTF8).GetBytes($OutputValue)
        Set-Content -Path $OutputFile -Value $OutputBytes @AsByteStream
    }

    $OutputValue
}

Export-ModuleMember -Function Get-NativeTarget
Export-ModuleMember -Function Get-Version
Export-ModuleMember -Function Get-PackageLanguages
Export-ModuleMember -Function Get-GatewayPackageLanguages
Export-ModuleMember -Function Set-EnvVarPath
Export-ModuleMember -Function Merge-Tokens
