param(
    [switch] $Generate,
    [parameter(Mandatory = $true)]
    [string] $Exe,
    [parameter(Mandatory = $true)]
    [string] $PedmDll,
    [parameter(Mandatory = $true)]
    [string] $PedmMsix,
    [parameter(Mandatory = $true)]
    [string] $SessionExe,
    [string] $OutputDir
)

# Use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

Import-Module (Join-Path $PSScriptRoot 'Build')

# Builds an MSI for Agent.
#
# Usage
#
# Regular build:
# New-AgentMsi -Exe $Exe -PedmDll $PedmDll -PedmMsix $PedmMsix -SessionExe $SessionExe -OutputDir $OutputDir
#
# Generate:
# New-AgentMsi -Generate -Exe $Exe -PedmDll $PedmDll -PedmMsix $PedmMsix -SessionExe $SessionExe
function New-AgentMsi() {
    param(
        # Generates additional files for the MSI. The MSI is not copied to the output directory if this is set. This produces files `package\WindowsManaged\Release\en-US` and `package\WindowsManaged\Release\fr-FR`.
        [switch] $Generate,
        [parameter(Mandatory = $true)]
        # The path to the devolutions-agent.exe file.
        [string] $Exe,
        [parameter(Mandatory = $true)]
        # The path to the devolutions_pedm_shell_ext.dll file.
        [string] $PedmDll,
        [parameter(Mandatory = $true)]
        # The path to the devolutions-agent-pedm.msix.
        [string] $PedmMsix,
        [parameter(Mandatory = $true)]
        # The path to the devolutions-session.exe file.
        [string] $SessionExe,
        # Only required if `Generate` is not set.
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

    $repoDir = Split-Path -Parent $PSScriptRoot # currently in `ci`

    Set-EnvVarPath 'DAGENT_EXECUTABLE' $Exe
    Set-EnvVarPath 'DAGENT_PEDM_SHELL_EXT_DLL' $PedmDll
    Set-EnvVarPath 'DAGENT_PEDM_SHELL_EXT_MSIX' $PedmMsix
    Set-EnvVarPath 'DAGENT_SESSION_EXECUTABLE' $SessionExe
    Set-EnvVarPath 'DAGENT_DESKTOP_AGENT_PATH' "$repoDir\dotnet\DesktopAgent"
  
    $version = Get-Version

    Push-Location
    Set-Location (Join-Path $repoDir 'package\AgentWindowsManaged')

    # Set the MSI version, which is read by `package/WindowsManaged/Program.cs`.
    $Env:DAGENT_VERSION = $version.Substring(2)
    if ($Generate) {
        # This is used by `package/WindowsManaged/Program.cs`.
        $Env:DAGENT_MSI_SOURCE_ONLY_BUILD = '1'
       
        foreach ($lang in Get-PackageLanguages) {
            $Env:DAGENT_MSI_LANG_ID = $lang.Name
            & 'MSBuild.exe' 'DevolutionsAgent.sln' '/t:restore,build' '/p:Configuration=Release' | Out-Host
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to build MSI for language $lang"
            }
        }
    }
    else {
        & 'MSBuild.exe' 'DevolutionsAgent.sln' '/t:restore,build' '/p:Configuration=Release' | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build MSI"
        }

        # When called without `Generate` switch, such as in the regular CI flow, copy the MSI to the output directory.
        $msi = Join-Path 'Release' 'DevolutionsAgent.msi'
        Copy-Item -Path $msi -Destination $OutputDir -ErrorAction Stop
        Write-Output "Copied MSI to $(Join-Path $OutputDir 'DevolutionsAgent.msi')"
    }
    Pop-Location
}

New-AgentMsi -Generate:($Generate.IsPresent) -Exe $Exe -PedmDll $PedmDll -PedmMsix $PedmMsix -SessionExe $SessionExe -OutputDir $OutputDir
