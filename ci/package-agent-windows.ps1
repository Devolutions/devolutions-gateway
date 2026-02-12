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
    [parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string] $Architecture,
    [string] $Outfile
)

# Use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

Import-Module (Join-Path $PSScriptRoot 'Build')


# Renames a file to a specified name if it is not already.
#
# if the file needs to be renamed, a copy is made in the temp directory.
# The path is returned.
#
# This is useful when we need our file to have a specific name for an intermediate step.
function Set-FileNameAndCopy {
    param (
        [string]$Path,
        [string]$NewName
    )
    
    if (-Not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    $dir = Split-Path -Path $Path -Parent
    $currName = Split-Path -Path $Path -Leaf

    # If the name is already correct, return the original path without copying
    if ($currName -ieq $NewName) {
        Write-Host "Using $Path without copying"
        return $Path
    }

    # Copy to a temporary directory.
    $tmpDir = [System.IO.Path]::GetTempPath()

    # tmpFile is in the temp directory with the original file name
    $tmpFile = Join-Path -Path $tmpDir -ChildPath (Split-Path -Path $Path -Leaf)
    Copy-Item -Path $Path -Destination $tmpFile -Force -ErrorAction Stop

    # Ensure the destination doesn't already exist so renaming will succeed.
    $dest = Join-Path -Path $tmpDir -ChildPath $NewName
    if (Test-Path $dest) {
        Remove-Item -Path $dest -Force -ErrorAction Stop
    }
    # Rename the file in the temp dir.
    Rename-Item -Path $tmpFile -NewName $NewName -Force -ErrorAction Stop
    Write-Host "Copied $Path to $dest"
    return $dest
}

# Normalizes the path to be Windows-style.
function Convert-Path {
    param (
        [string]$Path
    )
    return $Path -replace '/', '\'
}


# Builds an MSI for Agent.
#
# Our .NET code expects environment variables so they are set by this function if they are not already set.
# The package is particular about the input file names, but all of the proper renaming and linking is handled by this function.
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
        [parameter(Mandatory = $true)]
        [ValidateSet('x64', 'arm64')]
        # Architecture: x64 or arm64
        [string] $Architecture,
        # Only required if `Generate` is not set.
        [string] $Outfile
    )

    if ($Generate) {
        if ($Outfile) {
            throw 'Output path must not be specified when called with -Generate'
        }
    }
    elseif (-not $Outfile) {
        throw 'Output path must be specified when called without -Generate'
    }

    # Convert slashes. This does not affect function. It's just for display.
    $Exe = Convert-Path -Path $Exe
    $PedmDll = Convert-Path -Path $PedmDll
    $PedmMsix = Convert-Path -Path $PedmMsix
    $SessionExe = Convert-Path -Path $SessionExe
    if ($Outfile) {
        $Outfile = Convert-Path -Path $Outfile
    }

    $repoDir = Split-Path -Parent $PSScriptRoot # currently in `ci`

    # The DLL and MSIX must have specifics name when passed to MSBuild.
    $myPedmDll = Set-FileNameAndCopy -Path $PedmDll -NewName 'DevolutionsPedmShellExt.dll'
    $myPedmMsix = Set-FileNameAndCopy -Path $PedmDll -NewName 'DevolutionsPedmShellExt.msix'

    # These file names don't matter for building, but we will clean them up anyways for consistency. The names can be seen if inspecting the MSI.
    # The Agent exe will get copied to `C:\Program Files\Devolutions\Agent\DevolutionsAgent.exe` after install.
    $myExe = Set-FileNameAndCopy -Path $Exe -NewName 'DevolutionsAgent.exe'
    # The session is a service that gets launched on demand.
    $mySessionExe = Set-FileNameAndCopy -Path $SessionExe -NewName 'DevolutionsSession.exe'

    Write-Output "$repoDir\dotnet\DesktopAgent\bin\Release\net48\DevolutionsDesktopAgent.exe"

    Set-EnvVarPath 'DAGENT_EXECUTABLE' $myExe
    Set-EnvVarPath 'DAGENT_PEDM_SHELL_EXT_DLL' $myPedmDll
    Set-EnvVarPath 'DAGENT_PEDM_SHELL_EXT_MSIX' $myPedmMsix
    Set-EnvVarPath 'DAGENT_SESSION_EXECUTABLE' $mySessionExe

    # The actual DevolutionsDesktopAgent.exe will be `\dotnet\DesktopAgent\bin\Release\net48\DevolutionsDesktopAgent.exe`.
    # After install, the contsnts of `net48` will be copied to `C:\Program Files\Devolutions\Agent\desktop\`. 
    Set-EnvVarPath 'DAGENT_DESKTOP_AGENT_PATH' "$repoDir\dotnet\DesktopAgent\bin\Release\net48"
  
    $version = Get-Version

    Push-Location
    Set-Location "$repoDir\package\AgentWindowsManaged"

    # Set the MSI version and platform, which are read by `package/AgentWindowsManaged/Program.cs`.
    $Env:DAGENT_VERSION = $version.Substring(2)
    $Env:DAGENT_PLATFORM = $Architecture
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
        & 'MSBuild.exe' 'DevolutionsAgent.sln' '/t:clean,restore,build' '/p:Configuration=Release' | Tee-Object -FilePath "msbuild_$(Get-Date -Format 'yyyyMMdd_HHmm').log"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build MSI"
        }

        # When called without `Generate` switch, such as in the regular CI flow, copy the MSI to the output directory.
        Write-Output "Built MSI at $(Get-Location)\Release\DevolutionsAgent.msi"
        Copy-Item -Path 'Release\DevolutionsAgent.msi' -Destination $Outfile -ErrorAction Stop
        Write-Output "Copied MSI to $Outfile"
    }
    Pop-Location
}

New-AgentMsi -Generate:($Generate.IsPresent) -Exe $Exe -PedmDll $PedmDll -PedmMsix $PedmMsix -SessionExe $SessionExe -Architecture $Architecture -Outfile $Outfile
