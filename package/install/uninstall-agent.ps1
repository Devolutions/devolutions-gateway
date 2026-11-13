# Removes the Devolutions Agent and its data from this Windows machine.
# Usage (elevated PowerShell): irm https://<host>/uninstall-agent.ps1 | iex

& {
    $ErrorActionPreference = 'Stop'
    $serviceName = 'DevolutionsAgent'

    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Run this script from an elevated PowerShell window.' -ForegroundColor Red
        return
    }

    $uninstallKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $products = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object DisplayName -like 'Devolutions Agent*'
    foreach ($product in $products) {
        Write-Host "Removing $($product.DisplayName) $($product.DisplayVersion)..."
        $exitCode = (Start-Process msiexec.exe -ArgumentList "/x $($product.PSChildName) /qn /norestart" -Wait -PassThru).ExitCode
        if ($exitCode -notin 0, 1605, 3010) {
            Write-Host "msiexec failed with exit code $exitCode." -ForegroundColor Yellow
        }
    }

    $service = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host 'Removing the service...'
        if ($service.Status -ne 'Stopped') {
            Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus('Stopped', '00:00:30')
        }
        sc.exe delete $serviceName | Out-Null
    }

    Get-Process DevolutionsAgent -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2

    $failed = $false
    foreach ($path in 'C:\Program Files\Devolutions\Agent', 'C:\ProgramData\Devolutions\Agent', 'C:\ProgramData\Devolutions\PackageBroker') {
        if (-not (Test-Path $path)) { continue }
        Write-Host "Removing $path..."
        # The agent protects its identity folder with a SYSTEM-only DACL, so delete it as SYSTEM.
        $taskName = 'DevolutionsAgentCleanup'
        $action = New-ScheduledTaskAction -Execute cmd.exe -Argument "/c rmdir /s /q `"$path`""
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 15 -and (Test-Path $path); $i++) { Start-Sleep -Seconds 1 }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        if (Test-Path $path) {
            Write-Host "Could not remove $path." -ForegroundColor Yellow
            $failed = $true
        }
    }

    if ($failed -or (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
        Write-Host 'The Devolutions Agent was not fully removed.' -ForegroundColor Yellow
    } else {
        Write-Host 'The Devolutions Agent is removed.' -ForegroundColor Green
    }
}
