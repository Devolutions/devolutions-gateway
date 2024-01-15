
$ModuleName = $(Get-Item $PSCommandPath).BaseName
$Manifest = Import-PowerShellDataFile -Path $(Join-Path $PSScriptRoot "${ModuleName}.psd1")

if (-Not (Test-Path 'variable:global:IsWindows')) {
    $script:IsWindows = $true; # Windows PowerShell 5.1 or earlier
}

if ($IsWindows) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
}

if ($IsWindows -and ($PSEdition -eq 'Desktop')) {
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;

        public class NativeMethods {
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr LoadLibrary(string libname);
        }
"@ -PassThru

    $NativeDirName = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { "win-arm64" } else { "win-x64" }
    $PickyDllPath = "$PSScriptRoot\bin\$NativeDirName\DevolutionsPicky.dll"
    [NativeMethods]::LoadLibrary($PickyDllPath) | Out-Null
}

Export-ModuleMember -Cmdlet @($manifest.CmdletsToExport)

$Public = @(Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -Recurse)
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -Recurse)

Foreach ($Import in @($Public + $Private))
{
    Try
    {
        . $Import.FullName
    }
    Catch
    {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

Export-ModuleMember -Function @($Manifest.FunctionsToExport)
