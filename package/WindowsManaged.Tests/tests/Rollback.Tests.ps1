param([hashtable] $Lab)

BeforeAll {
    Import-Module "$PSScriptRoot\..\src\GatewayLab.psm1" -Force
    $Lab.RecoveryFailed = $false

    function Get-RollbackSnapshot {
        $state = Get-GatewayLabState
        $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
        $files = [ordered]@{}
        foreach ($name in 'gateway.json', 'provisioner.pem', 'provisioner.key', 'users.txt', 'rollback-sentinel.txt') {
            $path = Join-Path $data $name
            $files[$name] = if (Test-Path -LiteralPath $path) {
                @{ Hash = (Get-FileHash -LiteralPath $path).Hash
                    Dacl = (Get-Acl -LiteralPath $path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) }
            } else { $null }
        }
        $installDirectory = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Devolutions\Gateway').InstallDir
        $executable = Join-Path $installDirectory 'DevolutionsGateway.exe'
        [pscustomobject]@{
            Service = $state.Service
            OldProductRegistered = Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($Lab.Msi.ProductCode)"
            NewProductRegistered = Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($Lab.NextMsi.ProductCode)"
            ExecutableHash = if (Test-Path -LiteralPath $executable) { (Get-FileHash -LiteralPath $executable).Hash } else { $null }
            DataDacl = if (Test-Path -LiteralPath $data) {
                (Get-Acl -LiteralPath $data).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            } else { $null }
            Files = $files
        }
    }

    function Get-AccountProperties($Account) {
        $properties = @{ 'P.SERVICEACCOUNT' = $Account.Name; 'P.SERVICESTART' = 'Manual' }
        if ($Account.Credential) { $properties['P.SERVICEPASSWORD'] = $Account.Credential.GetNetworkCredential().Password }
        $properties
    }

    function Restore-RollbackBaseline($Before, $Original, $Record, [string] $Directory) {
        $state = Get-RollbackSnapshot
        if ($state.Service) { Stop-GatewayLabService }
        if ($state.NewProductRegistered) {
            Invoke-GatewayLabMsi -Msi $Lab.NextMsi -Action Uninstall -LogPath "$Directory\recovery-remove-new.log" | Out-Null
            $Record.RecoveryActions.Add('Uninstalled the remaining new product')
            $state = Get-RollbackSnapshot
        }
        if ($state.Service -and -not $Record.Checks.RuntimeUsable) {
            $password = if ($Original.Credential) { $Original.Credential.GetNetworkCredential().Password }
                elseif ($Original.Kind -eq 'NetworkService') { '' } else { $null }
            [GatewayInstallerTests.ServiceProbe]::RestoreGatewayAccount($Original.Name, $password)
            $Record.RecoveryActions.Add('Reapplied the known original account and credentials through SCM')
        }
        if (-not $state.OldProductRegistered) {
            Invoke-GatewayLabMsi -Msi $Lab.Msi -LogPath "$Directory\recovery-install-old.log" -Properties (Get-AccountProperties $Original) | Out-Null
            $Record.RecoveryActions.Add('Reinstalled the original MSI')
        } elseif (-not $state.Service -or $state.ExecutableHash -ne $Before.ExecutableHash) {
            $properties = if ($state.Service) { @{} } else { Get-AccountProperties $Original }
            Invoke-GatewayLabMsi -Msi $Lab.Msi -Action Repair -LogPath "$Directory\recovery-repair-old.log" -Properties $properties | Out-Null
            $Record.RecoveryActions.Add('Repaired the original MSI')
        }

        $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
        $acl = Get-Acl -LiteralPath $data
        $acl.SetSecurityDescriptorSddlForm($Before.DataDacl, [Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -LiteralPath $data -AclObject $acl
        foreach ($name in $Before.Files.Keys) {
            if (-not $Before.Files[$name]) { continue }
            $path = Join-Path $data $name
            if (-not (Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path).Hash -ne $Before.Files[$name].Hash) {
                Copy-Item -LiteralPath "$Directory\before-data\$name" -Destination $path -Force
                $Record.RecoveryActions.Add("Restored $name from the restricted backup")
            }
            $acl = Get-Acl -LiteralPath $path
            $acl.SetSecurityDescriptorSddlForm($Before.Files[$name].Dacl, [Security.AccessControl.AccessControlSections]::Access)
            Set-Acl -LiteralPath $path -AclObject $acl
        }
        $Record.RecoveryActions.Add('Restored the original data and file DACLs')
        Set-Service -Name DevolutionsGateway -StartupType Manual
        Start-Service DevolutionsGateway
        Test-GatewayLabRuntime -Account $Original -Port $Lab.Port -OutputDirectory $Directory | Out-Null
        $restored = Get-RollbackSnapshot
        if (-not $restored.OldProductRegistered -or $restored.NewProductRegistered -or $restored.ExecutableHash -ne $Before.ExecutableHash) {
            throw 'Manual recovery did not restore original product ownership and executable'
        }
        if ((Get-GatewayLabDaclKey $restored.DataDacl) -ne (Get-GatewayLabDaclKey $Before.DataDacl)) { throw 'Manual recovery did not restore the data directory DACL' }
        foreach ($name in $Before.Files.Keys) {
            if ($Before.Files[$name] -and ($restored.Files[$name].Hash -ne $Before.Files[$name].Hash -or (Get-GatewayLabDaclKey $restored.Files[$name].Dacl) -ne (Get-GatewayLabDaclKey $Before.Files[$name].Dacl))) {
                throw "Manual recovery did not restore $name"
            }
        }
        $Record.AfterRecovery = $restored
        $Record.RecoveryVerified = $true
    }
}

Describe 'Rollback <CaseName>' -ForEach @(
    foreach ($original in $Lab.Accounts) {
        $targets = @($original)
        if ($Lab.RollbackAccountChanges) {
            $other = $Lab.Accounts | Where-Object Sid -ne $original.Sid | Select-Object -First 1
            if ($other) { $targets += $other }
        }
        foreach ($target in $targets) {
            foreach ($point in $Lab.RollbackFailurePoints) {
                @{ CaseName = "$($original.Kind)-to-$($target.Kind)-$point"; Original = $original; Target = $target; Point = $point }
            }
        }
    }
) {
    It 'restores the original working installation after the injected failure' {
        if ($Lab.RecoveryFailed) { throw 'A previous case could not be recovered; no further installation is allowed' }
        $directory = (New-Item -ItemType Directory -Path "$($Lab.Output)\$CaseName").FullName
        $started = Get-Date
        $record = [ordered]@{
            Case = $CaseName; OriginalAccount = $Original.Name; RequestedAccount = $Target.Name; FailurePoint = $Point
            Before = $null; AtFault = $null; AfterRollback = $null; RuntimeError = $null; HarnessError = $null
            Checks = [ordered]@{}; ManualStartNeeded = $false
            RecoveryActions = [Collections.Generic.List[string]]::new(); RecoveryVerified = $false; RecoveryError = $null
            TargetLogonRightBefore = $null; TargetLogonRightAfter = $null; AfterRecovery = $null
        }
        $before = $null
        $installed = $false
        try {
            Invoke-GatewayLabMsi -Msi $Lab.Msi -LogPath "$directory\install-old.log" -Properties (Get-AccountProperties $Original) | Out-Null
            $installed = $true
            Initialize-GatewayLabConfiguration -Port $Lab.Port
            $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
            Set-Content -LiteralPath "$data\users.txt" -Value 'rollback-fixture:unused' -Encoding ASCII
            Set-Content -LiteralPath "$data\rollback-sentinel.txt" -Value $Lab.RunId -Encoding ASCII
            Start-Service DevolutionsGateway
            Test-GatewayLabRuntime -Account $Original -Port $Lab.Port -OutputDirectory $directory | Out-Null
            $before = Get-RollbackSnapshot
            $record.Before = $before
            $record.TargetLogonRightBefore = [GatewayInstallerTests.ServiceProbe]::HasExplicitServiceLogonRight($Target.Sid)
            New-Item -ItemType Directory -Path "$directory\before-data" | Out-Null
            foreach ($name in $before.Files.Keys) {
                if ($before.Files[$name]) { Copy-Item -LiteralPath "$data\$name" -Destination "$directory\before-data\$name" }
            }
            Protect-GatewayLabArtifacts "$directory\before-data"

            $properties = Get-AccountProperties $Target
            $properties['DGWLAB_FAILURE_PHASE'] = $Point
            Invoke-GatewayLabMsi -Msi $Lab.NextMsi -LogPath "$directory\failed-upgrade.log" -Properties $properties -ExpectedExitCode 1603 -TimeoutSeconds 600 | Out-Null
            $marker = 'DGWLAB_FAULT '
            $faultLine = Get-Content -LiteralPath "$directory\failed-upgrade.log" | Where-Object { $_.Contains($marker) } | Select-Object -Last 1
            if (-not $faultLine) { throw 'The MSI failed without reaching the requested injected fault' }
            $fault = $faultLine.Substring($faultLine.IndexOf($marker) + $marker.Length) | ConvertFrom-Json
            $record.AtFault = $fault
            if ($fault.Phase -ne $Point) { throw 'The wrong fault action ran' }
            if ($Point -eq 'after-remove') {
                if ($fault.ServiceExists -or $fault.ExecutableHash) { throw 'The early fault ran before old-service/file removal' }
            } else {
                if (-not $fault.ServiceExists -or -not $fault.ExecutableHash -or $fault.ExecutableHash -eq $before.ExecutableHash) {
                    throw 'The late fault did not observe the replacement service and distinct new executable'
                }
                $name = $fault.Account
                if ($name.StartsWith('.\')) { $name = $env:COMPUTERNAME + $name.Substring(1) }
                $sid = ([Security.Principal.NTAccount]::new($name).Translate([Security.Principal.SecurityIdentifier])).Value
                if ($sid -ne $Target.Sid) { throw 'The replacement service did not use the requested account' }
            }
            $after = Get-RollbackSnapshot
            $record.AfterRollback = $after
            $record.Checks.OldProductRestored = $after.OldProductRegistered -and -not $after.NewProductRegistered
            $record.Checks.ExecutableRestored = $after.ExecutableHash -eq $before.ExecutableHash
            $record.Checks.ServiceAccountRestored = $after.Service -and $after.Service.StartName -eq $before.Service.StartName
            $record.Checks.StartupModeRestored = $after.Service -and $after.Service.StartMode -eq $before.Service.StartMode
            $record.Checks.RunningStateRestored = $after.Service -and $after.Service.State -eq $before.Service.State
            $record.Checks.DataDaclRestored = (Get-GatewayLabDaclKey $after.DataDacl) -eq (Get-GatewayLabDaclKey $before.DataDacl)
            $record.TargetLogonRightAfter = [GatewayInstallerTests.ServiceProbe]::HasExplicitServiceLogonRight($Target.Sid)
            $record.Checks.TargetLogonRightRestored = $record.TargetLogonRightAfter -eq $record.TargetLogonRightBefore
            foreach ($name in $before.Files.Keys) {
                $record.Checks["$name-content"] = $after.Files[$name] -and $after.Files[$name].Hash -eq $before.Files[$name].Hash
                $record.Checks["$name-dacl"] = $after.Files[$name] -and (Get-GatewayLabDaclKey $after.Files[$name].Dacl) -eq (Get-GatewayLabDaclKey $before.Files[$name].Dacl)
            }
            $record.Checks.RuntimeUsable = $false
            try {
                if (-not $after.Service) { throw 'The old service was not restored' }
                if ($after.Service.State -ne 'Running') {
                    $record.ManualStartNeeded = $true
                    Start-Service DevolutionsGateway
                }
                Test-GatewayLabRuntime -Account $Original -Port $Lab.Port -OutputDirectory $directory | Out-Null
                $record.Checks.RuntimeUsable = $true
            } catch { $record.RuntimeError = $_.Exception.Message }
        } catch {
            $record.HarnessError = $_.Exception.Message
        } finally {
            try {
                if (Test-GatewayLabRecoveryRequired) { throw 'MSI state is uncertain or requires a reboot; retaining the installation' }
                if ($installed) {
                    if ($before) {
                        if ($record.HarnessError -or @($record.Checks.Values | Where-Object { -not $_ }).Count) {
                            Restore-RollbackBaseline $before $Original $record $directory
                        } else { $record.RecoveryVerified = $true }
                    }
                    if ((Get-GatewayLabState).Service) { Stop-GatewayLabService }
                    Invoke-GatewayLabMsi -Msi $Lab.Msi -Action Uninstall -LogPath "$directory\uninstall-old.log" | Out-Null
                }
                if ((Get-GatewayLabState).Service) { throw 'A service remains after cleanup' }
                $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
                if (Test-Path -LiteralPath $data) {
                    Move-Item -LiteralPath $data -Destination "$directory\retained-data"
                    Protect-GatewayLabArtifacts "$directory\retained-data"
                }
            } catch {
                $record.RecoveryError = $_.Exception.Message
                $Lab.RecoveryFailed = $true
            }
            $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath "$directory\rollback.json" -Encoding UTF8
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 200 |
                Where-Object { $_.TimeCreated -ge $started -and $_.Message -like '*Devolutions Gateway*' } |
                Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath "$directory\service-events.json" -Encoding UTF8
        }
        $record.HarnessError | Should -BeNullOrEmpty
        $record.RecoveryError | Should -BeNullOrEmpty
        $failed = @($record.Checks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
        $failed | Should -BeNullOrEmpty -Because "rollback must restore the original state without manual recovery; see $directory"
    }
}
