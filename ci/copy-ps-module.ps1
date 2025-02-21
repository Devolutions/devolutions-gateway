param(
    [parameter(Mandatory = $true)]
    [string] $ModulePath
)

Import-Module (Join-Path $PSScriptRoot 'Build')

# Copies the PS module to the staging directory, located at `$Env:Temp/Devolutions-Gateway`.
#
# The PS module must be build already.
# After copying to the staging directory, `Program.cs` reads $Env:DGATEWAY_PSMODULE_PATH to find the module for inclusion in the MSI.
function Copy-PsModuleToStaging() {
    param(
        [Parameter(Mandatory = $true)]
        # The path to the built PS module. This is like `powershell/package/Devolutions-Gateway`.
        [string] $ModulePath
    )

    if ($Null -Eq (Get-Command "MSBuild.exe" -ErrorAction SilentlyContinue)) {
        throw 'MSBuild was not found in the PATH'
    }

    $version = Get-Version
    
    # Package the PowerShell module.
    $manifestFile = $(@(Get-ChildItem -Path $ModulePath -Depth 1 -Filter "*.psd1")[0]).FullName
    $manifest = Import-PowerShellDataFile -Path $manifestFile
    if ($version -ne $manifest.ModuleVersion) {
        Write-Warning "PowerShell module version mismatch: $($manifest.ModuleVersion) (expected: $version"
    }
    $stagingDir = Join-Path $Env:Temp "DevolutionsGateway"
    New-Item -Force -Type Directory $stagingDir
    Copy-Item -Force -Recurse $ModulePath/* $stagingDir
    Get-Item "$stagingDir\bin\*\*DevolutionsPicky*" | Where-Object { $_.Directory.Name -ne 'win-x64' } | ForEach-Object { Remove-Item $_.Directory -Recurse }
    Remove-Item $(Join-Path $stagingDir "src") -Recurse -ErrorAction Stop
    Write-Output "Copied PS module to $stagingDir"
}

Copy-PsModuleToStaging -modulePath $ModulePath

