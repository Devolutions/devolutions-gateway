param([hashtable] $Lab)

BeforeAll {
    Import-Module "$PSScriptRoot\..\src\GatewayLab.psm1" -Force
}

Describe 'Gateway lifecycle under <Kind>' -ForEach @($Lab.Accounts | ForEach-Object {
    @{ Kind = $_.Kind; Name = $_.Name; Credential = $_.Credential; Account = $_ }
}) {
    BeforeAll {
        $script:account = $Account
        $script:caseDirectory = (New-Item -ItemType Directory -Path "$($Lab.Output)\$Kind").FullName
        $script:installed = $null
        $script:configHash = $null
        $script:properties = @{
            'P.SERVICEACCOUNT' = $Name
            'P.SERVICESTART' = 'Manual'
        }
        if ($Credential) { $script:properties['P.SERVICEPASSWORD'] = $Credential.GetNetworkCredential().Password }
    }

    It 'rejects a missing password before creating a password-account service' {
        if (-not $Credential) { Set-ItResult -Skipped -Because 'Passwordless account'; return }
        Invoke-GatewayLabMsi -Msi $Lab.Msi -LogPath "$script:caseDirectory\missing-password.log" `
            -Properties @{ 'P.SERVICEACCOUNT' = $Name } -ExpectedExitCode 1603 | Should -Be 1603
        (Get-GatewayLabState).Service | Should -BeNullOrEmpty
    }

    It 'installs with the requested account without autostart' {
        Invoke-GatewayLabMsi -Msi $Lab.Msi -LogPath "$script:caseDirectory\install.log" -Properties $script:properties | Should -Be 0
        $script:installed = $Lab.Msi
        $state = Get-GatewayLabState
        $state.Service.State | Should -Be 'Stopped'
        $state.Service.StartMode | Should -Be 'Manual'
        Initialize-GatewayLabConfiguration -Port $Lab.Port
        $script:configHash = (Get-GatewayLabState).ConfigHash
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:caseDirectory\installed.json" -Encoding UTF8
    }

    It 'starts, serves HTTP, and accesses data as the requested identity' {
        Start-Service DevolutionsGateway
        $probe = Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory
        $serviceSid = ([Security.Principal.NTAccount]::new('NT SERVICE\DevolutionsGateway').Translate([Security.Principal.SecurityIdentifier])).Value
        if (-not $Lab.LegacyBaseline) {
            @($probe.GroupSids) + @($probe.UserSid) | Should -Contain $serviceSid
        }
    }

    It 'leaves a running installation untouched when an upgrade password is missing' {
        if (-not $Credential) { Set-ItResult -Skipped -Because 'Passwordless account'; return }
        $before = Get-GatewayLabState
        Invoke-GatewayLabMsi -Msi $Lab.NextMsi -LogPath "$script:caseDirectory\upgrade-missing-password.log" `
            -ExpectedExitCode 1603 | Should -Be 1603
        $after = Get-GatewayLabState
        $after.Service.StartName | Should -Be $before.Service.StartName
        $after.Service.ProcessId | Should -Be $before.Service.ProcessId
        $after.ConfigHash | Should -Be $before.ConfigHash
        $after.DataSddl | Should -Be $before.DataSddl
        Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory | Out-Null
    }

    It 'rejects a wrong upgrade password before changing the service' {
        if (-not $Credential) { Set-ItResult -Skipped -Because 'Passwordless account'; return }
        $before = Get-GatewayLabState
        Invoke-GatewayLabMsi -Msi $Lab.NextMsi -LogPath "$script:caseDirectory\upgrade-wrong-password.log" `
            -Properties @{ 'P.SERVICEPASSWORD' = 'Wrong-' + [guid]::NewGuid().ToString('N') } -ExpectedExitCode 1603 | Should -Be 1603
        $after = Get-GatewayLabState
        $after.Service.ProcessId | Should -Be $before.Service.ProcessId
        $after.ConfigHash | Should -Be $before.ConfigHash
        $after.DataSddl | Should -Be $before.DataSddl
    }

    It 'upgrades without respecifying the account and preserves configuration' {
        $properties = @{}
        if ($Credential) { $properties['P.SERVICEPASSWORD'] = $Credential.GetNetworkCredential().Password }
        if ($Lab.AgentExecutable -and -not $Credential) {
            $allowUnsigned = $Lab.NextMsi.Signature -ne 'Valid'
            $agent = Start-GatewayLabAgent -Executable $Lab.AgentExecutable -Directory "$script:caseDirectory\agent-trust" -Target $Lab.NextMsi
            try {
                $service = Wait-GatewayLabService Running
                $access = Invoke-GatewayLabServiceProbe -ProcessId ([int]$service.ProcessId) -OutputDirectory $script:caseDirectory -AgentDirectory $agent.Directory
                $access.UpdateCommandWritable | Should -BeTrue
                $access.UpdateStatusReadable | Should -BeTrue
                $access.UpdateStatusWritable | Should -BeFalse
                if ($allowUnsigned) {
                    Invoke-GatewayLabAgentUpdate -Agent $agent -ExpectedError '*signature*' | Out-Null
                    (Get-GatewayLabState).ConfigHash | Should -Be $script:configHash
                } else {
                    Invoke-GatewayLabAgentUpdate -Agent $agent -ExpectedVersion "20$($Lab.NextMsi.ProductVersion)" | Out-Null
                }
            } finally { Stop-GatewayLabAgent $agent }
            if ($allowUnsigned) {
                $agent = Start-GatewayLabAgent -Executable $Lab.AgentExecutable -Directory "$script:caseDirectory\agent-upgrade" -Target $Lab.NextMsi -AllowUnsigned
                try {
                    Invoke-GatewayLabAgentUpdate -Agent $agent -ExpectedVersion "20$($Lab.NextMsi.ProductVersion)" | Out-Null
                } finally { Stop-GatewayLabAgent $agent }
            }
        } else {
            Invoke-GatewayLabMsi -Msi $Lab.NextMsi -LogPath "$script:caseDirectory\upgrade.log" -Properties $properties | Should -Be 0
        }
        $script:installed = $Lab.NextMsi
        (Get-GatewayLabState).ConfigHash | Should -Be $script:configHash
        Start-Service DevolutionsGateway
        Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory | Out-Null
    }

    It 'enforces the passwordless boundary in the real Agent updater' {
        if (-not $Lab.AgentExecutable) { Set-ItResult -Skipped -Because 'AgentExecutable was not supplied'; return }
        if (-not $Credential) { Set-ItResult -Skipped -Because 'Passwordless update was checked by the upgrade scenario'; return }
        $agent = Start-GatewayLabAgent -Executable $Lab.AgentExecutable -Directory "$script:caseDirectory\agent" -Target $Lab.Msi -AllowUnsigned
        try {
            if ($Credential) {
                # An explicit lower target exercises the same gate without permitting an uninstall.
                [IO.File]::WriteAllText("$($agent.Directory)\update.json",
                    ('{{"VersionMajor":2,"VersionMinor":2,"Products":{{"Gateway":{{"Version":"20{0}"}}}}}}' -f $Lab.Msi.ProductVersion),
                    [Text.UTF8Encoding]::new($false))
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                do {
                    Start-Sleep -Milliseconds 500
                    $status = Get-Content -LiteralPath "$($agent.Directory)\update_status.json" -Raw | ConvertFrom-Json
                    $errorProperty = $status.Products.Gateway.PSObject.Properties['LastUpdateError']
                } while (-not $errorProperty -and [DateTime]::UtcNow -lt $deadline)
                $errorProperty.Value | Should -BeLike '*logs on with a password*'
                $service = Wait-GatewayLabService Running
                $access = Invoke-GatewayLabServiceProbe -ProcessId ([int]$service.ProcessId) -OutputDirectory $script:caseDirectory -AgentDirectory $agent.Directory
                $access.UpdateCommandWritable | Should -BeTrue
                $access.UpdateStatusReadable | Should -BeTrue
                $access.UpdateStatusWritable | Should -BeFalse
                (Get-GatewayLabState).ConfigHash | Should -Be $script:configHash
                Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory | Out-Null
            }
        } finally {
            Stop-GatewayLabAgent $agent
        }
    }

    It 'repairs an existing service without requesting its password' {
        Stop-GatewayLabService
        Invoke-GatewayLabMsi -Msi $Lab.NextMsi -Action Repair -LogPath "$script:caseDirectory\repair.log" | Should -Be 0
        (Get-GatewayLabState).ConfigHash | Should -Be $script:configHash
        Start-Service DevolutionsGateway
        Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory | Out-Null
    }

    It 'rejects changing the service identity during repair' {
        $before = Get-GatewayLabState
        $other = if ($Kind -eq 'NetworkService') { 'NT SERVICE\DevolutionsGateway' } else { 'NT AUTHORITY\NetworkService' }
        Invoke-GatewayLabMsi -Msi $Lab.NextMsi -Action Repair -LogPath "$script:caseDirectory\repair-change-account.log" `
            -Properties @{ 'P.SERVICEACCOUNT' = $other } -ExpectedExitCode 1603 | Should -Be 1603
        $after = Get-GatewayLabState
        $after.Service.StartName | Should -Be $before.Service.StartName
        $after.DataSddl | Should -Be $before.DataSddl
        $after.ConfigHash | Should -Be $before.ConfigHash
    }

    It 'keeps direct MSI downgrade rejection unchanged' {
        $before = Get-GatewayLabState
        Invoke-GatewayLabMsi -Msi $Lab.Msi -LogPath "$script:caseDirectory\direct-downgrade.log" `
            -Properties $script:properties -ExpectedExitCode 1603 | Should -Be 1603
        (Get-GatewayLabState).ConfigHash | Should -Be $before.ConfigHash
        Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory | Out-Null
    }

    It 'preserves passwordless identity through the existing Agent downgrade path' {
        if (-not $Lab.AgentExecutable -or $Credential) {
            Set-ItResult -Skipped -Because 'Requires AgentExecutable and a passwordless account'
            return
        }
        $agent = Start-GatewayLabAgent -Executable $Lab.AgentExecutable -Directory "$script:caseDirectory\agent-downgrade" `
            -Target $Lab.Msi -AllowUnsigned:($Lab.Msi.Signature -ne 'Valid')
        try {
            $version = "20$($Lab.Msi.ProductVersion)"
            Invoke-GatewayLabAgentUpdate -Agent $agent -RequestedVersion $version -ExpectedVersion $version | Out-Null
            $script:installed = $Lab.Msi
            (Get-GatewayLabState).ConfigHash | Should -Be $script:configHash
            Test-GatewayLabRuntime -Account $script:account -Port $Lab.Port -OutputDirectory $script:caseDirectory | Out-Null
        } finally { Stop-GatewayLabAgent $agent }
    }

    AfterAll {
        if (Test-GatewayLabRecoveryRequired) { throw 'Retaining the installation for recovery after a reboot-required result or timeout' }
        $state = Get-GatewayLabState
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:caseDirectory\final.json" -Encoding UTF8
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 100
        $events | Where-Object Message -Match 'Devolutions Gateway' |
            Select-Object TimeCreated, Id, LevelDisplayName, Message |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$script:caseDirectory\service-events.json" -Encoding UTF8
        if ($script:installed) {
            Stop-GatewayLabService
            Invoke-GatewayLabMsi -Msi $script:installed -Action Uninstall -LogPath "$script:caseDirectory\uninstall.log" | Out-Null
        }
        if ((Get-GatewayLabState).Service) { throw 'Service remains installed; stop and recover before continuing' }
        $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
        if (Test-Path -LiteralPath $data) {
            Move-Item -LiteralPath $data -Destination "$script:caseDirectory\retained-data"
            Protect-GatewayLabArtifacts -Directory "$script:caseDirectory\retained-data"
        }
        if ($Credential) {
            $password = $Credential.GetNetworkCredential().Password
            foreach ($log in Get-ChildItem -LiteralPath $script:caseDirectory -Filter '*.log' -File) {
                $content = Get-Content -LiteralPath $log.FullName -Raw
                if ($content.Contains($password) -or $content.Contains($password.Replace('"', '""'))) {
                    throw "Disposable password was exposed in an MSI log; artifacts are restricted: $($log.Name)"
                }
            }
        }
    }
}
