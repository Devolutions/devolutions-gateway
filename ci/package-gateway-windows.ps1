param(
    [switch] $Generate,
    [parameter(Mandatory = $true)]
    [string] $Exe,
    [parameter(Mandatory = $true)]
    [string]$LibxmfFile,
    [parameter(Mandatory = $true)]
    [string]$PsModuleDir,
    [parameter(Mandatory = $true)]
    [string]$WebClientDir,
    [parameter(Mandatory = $true)]
    [string]$WebPlayerDir,
    [string] $OutputDir
)

# Use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

Import-Module (Join-Path $PSScriptRoot 'Build')

# Usage
#
# Regular build:
# New-GatewayMsi -Exe $Exe -LibXmfFile $LibXmfFile -PsModuleDir $PsModuleDir -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir -OutputDir $OutputDir
#
# Generate:
# New-GatewayMsi -Generate -Exe $Exe -LibXmfFile $LibXmfFile -PsModuleDir $PsModuleDir -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir
function New-GatewayMsi() {
    param(
        [switch]
        # Generates additional files for the MSI. The MSI is not copied to the output directory if this is set. This produces files `package\WindowsManaged\Release\en-US`, `package\WindowsManaged\Release\fr-FR`, and `package\WindowsManaged\Release\de-DE`.
        $Generate,
        [parameter(Mandatory = $true)]
        # The path to devolutions-gateway.exe.
        [string] $Exe,
        [parameter(Mandatory = $true)]
        # The path to libxmf.so.
        [string]$LibxmfFile,
        [parameter(Mandatory = $true)]
        # The path to the PowerShell module.
        [string]$PsModuleDir,
        [parameter(Mandatory = $true)]
        # The path to the Angular-built web app client.
        [string]$WebClientDir,
        [parameter(Mandatory = $true)]
        # The path to the Angular-built web app player.
        [string]$WebPlayerDir,
        # The path to the output directory. Only required if `Generate` is not set.
        [string] $OutputDir
    )

    if ($Generate) {
        if ($OutputDir) {
            throw 'Output directory must not be specified when called with -Generate'
        }
    }
    else {
        if (-not $OutputDir) {
            throw 'Output directory must be specified when called without -Generate'
        }
        elseif (-not (Test-Path $OutputDir)) {
            throw "Output directory does not exist: $OutputDir"
        }
    }
    
    Set-EnvVarPath 'DGATEWAY_EXECUTABLE' $Exe
    Set-EnvVarPath 'DGATEWAY_LIB_XMF_PATH' $LibxmfFile
    Set-EnvVarPath 'DGATEWAY_PSMODULE_PATH' $PsModuleDir
    Set-EnvVarPath 'DGATEWAY_WEBCLIENT_PATH' $WebClientDir
    Set-EnvVarPath 'DGATEWAY_WEBPLAYER_PATH' $WebPlayerDir

    $version = Get-Version

    Push-Location

    $repoDir = Split-Path -Parent $PSScriptRoot # currently in `ci`
    Set-Location (Join-Path $repoDir 'package\WindowsManaged')

    # Set the MSI version, which is read by `package/WindowsManaged/Program.cs`.
    $Env:DGATEWAY_VERSION = $version.Substring(2)
    if ($Generate) {
        # This is used by `package/WindowsManaged/Program.cs`.
        $Env:DGATEWAY_MSI_SOURCE_ONLY_BUILD = '1'
       
        foreach ($lang in Get-GatewayPackageLanguages) {
            $Env:DGATEWAY_MSI_LANG_ID = $lang.Name
            & 'MSBuild.exe' 'DevolutionsGateway.sln' '/t:restore,build' '/p:Configuration=Release' | Out-Host
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to build MSI for language $lang"
            }
        }
    }
    else {
        & 'MSBuild.exe' 'DevolutionsGateway.sln' '/t:restore,build' '/p:Configuration=Release' | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build MSI"
        }

        # When called without `Generate` switch, such as in the regular CI flow, copy the MSI to the output directory.
        $msi = Join-Path 'Release' 'DevolutionsGateway.msi'
        Copy-Item -Path $msi -Destination $OutputDir -ErrorAction Stop
        Write-Output "Copied MSI to $(Join-Path $OutputDir $msi)"
    }
    Pop-Location
}

New-GatewayMsi -Generate:($Generate.IsPresent) -Exe $Exe -LibXmfFile $LibXmfFile -PsModuleDir $PsModuleDir -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir -OutputDir $OutputDir
