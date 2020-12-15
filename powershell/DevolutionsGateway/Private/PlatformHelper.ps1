function Get-IsWindows
{
    if (-Not (Test-Path 'variable:global:IsWindows')) {
        return $true # Windows PowerShell 5.1 or earlier
    } else {
        return $IsWindows
    }
}

# Work only with windows, use the check Get-IsWindows before call this one
function Get-IsRunAsAdministrator  
{
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}

function Get-CmdletVersion() {
    $ManifestPath = "$PSScriptRoot/../DevolutionsGateway.psd1"
    $Manifest = Import-PowerShellDataFile -Path $ManifestPath
    $Manifest.ModuleVersion
}

function Get-PSVersion() {
    $PSVersionTable.PSVersion.ToString()
}

function Get-DockerVersion() {
    $(docker version --format '{{.Server.Version}}').trim()
}

function Get-OsVersionInfo() {
    if (Get-IsWindows) {
        $ProductName = (Get-ItemProperty -path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        $ReleaseId = (Get-ItemProperty -path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
        return "$ProductName $ReleaseId"
	} elseif ($IsMacOS) {
        $ProductVersion = $(sw_vers -productVersion).trim()
        $BuildVersion = $(sw_vers -buildVersion).trim()
        return "macOS $ProductVersion $BuildVersion"
	} elseif ($IsLinux) {
        $LsbRelease = $(lsb_release -d -s).trim()
        return "Linux $LsbRelease"
    }
}
