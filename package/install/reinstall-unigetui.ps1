# Reinstalls UniGetUI on this Windows machine from the development install server. Development only.
# Usage: irm http://<host>:<port>/reinstall-unigetui.ps1 | iex
# A machine-wide install needs an elevated PowerShell window. A per-user install keeps its scope.

& {
    $ErrorActionPreference = 'Stop'
    # Start-DevInstallServer.ps1 sets this value in the served copy.
    $DevUrl = ''

    if (-not $DevUrl) {
        Write-Host 'Run the copy of this script served by Start-DevInstallServer.ps1.' -ForegroundColor Red
        return
    }

    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{889610CC-4337-4BDB-AC3B-4F21806C0BDE}_is1',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{889610CC-4337-4BDB-AC3B-4F21806C0BDE}_is1'
    )
    $current = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Select-Object -First 1
    $machineWide = $current -and $current.PSPath -like '*HKEY_LOCAL_MACHINE*'

    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($machineWide -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'UniGetUI is installed for all users. Run this script from an elevated PowerShell window.' -ForegroundColor Red
        return
    }

    if ($current) {
        Write-Host "Installed: UniGetUI $($current.DisplayVersion) ($(if ($machineWide) { 'all users' } else { 'current user' }))"
    } else {
        Write-Host 'UniGetUI is not installed. Installing it for the current user.'
    }

    $installer = Join-Path ([IO.Path]::GetTempPath()) 'UniGetUI.Installer.x64.exe'
    Write-Host "Downloading $DevUrl/UniGetUI.Installer.x64.exe..."
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "$DevUrl/UniGetUI.Installer.x64.exe" -OutFile $installer -UseBasicParsing

    Write-Host 'Stopping UniGetUI...'
    Get-Process UniGetUI, UniGetUI.Avalonia, UniGetUI.PolicyElevator -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2

    Write-Host 'Installing UniGetUI...'
    $scope = if ($machineWide) { '/ALLUSERS' } else { '/CURRENTUSER' }
    $arguments = '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', $scope
    $exitCode = (Start-Process $installer -ArgumentList $arguments -Wait -PassThru).ExitCode
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
    if ($exitCode -ne 0) {
        Write-Host "The installer failed with exit code $exitCode." -ForegroundColor Red
        return
    }

    $installed = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Select-Object -First 1
    # The installer starts UniGetUI in the background. The agent needs it running to reach its IPC API.
    for ($i = 0; $i -lt 10 -and -not (Get-Process UniGetUI -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
    if (-not (Get-Process UniGetUI -ErrorAction SilentlyContinue) -and $installed.InstallLocation) {
        Start-Process (Join-Path $installed.InstallLocation 'UniGetUI.exe') -ArgumentList '--daemon'
    }

    Write-Host "UniGetUI $($installed.DisplayVersion) is installed. Build date: $((Get-Item (Join-Path $installed.InstallLocation 'UniGetUI.exe')).LastWriteTime)." -ForegroundColor Green
}
