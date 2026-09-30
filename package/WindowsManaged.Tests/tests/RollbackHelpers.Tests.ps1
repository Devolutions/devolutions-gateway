BeforeAll {
    Import-Module "$PSScriptRoot\..\src\GatewayLab.psm1" -Force
}

Describe 'Rollback DACL comparison' {
    It 'ignores ordering of Allow ACEs' {
        Get-GatewayLabDaclKey 'D:P(A;;FA;;;SY)(A;;FR;;;BU)' |
            Should -BeExactly (Get-GatewayLabDaclKey 'D:P(A;;FR;;;BU)(A;;FA;;;SY)')
    }

    It 'preserves access-mask changes' {
        Get-GatewayLabDaclKey 'D:P(A;;FA;;;SY)(A;;FR;;;BU)' |
            Should -Not -BeExactly (Get-GatewayLabDaclKey 'D:P(A;;FA;;;SY)(A;;FA;;;BU)')
    }

    It 'preserves DACL protection' {
        Get-GatewayLabDaclKey 'D:P(A;;FA;;;SY)' |
            Should -Not -BeExactly (Get-GatewayLabDaclKey 'D:(A;;FA;;;SY)')
    }

    It 'preserves ACE inheritance flags' {
        Get-GatewayLabDaclKey 'D:(A;ID;FA;;;SY)' |
            Should -Not -BeExactly (Get-GatewayLabDaclKey 'D:(A;;FA;;;SY)')
    }

    It 'does not reorder an ACL containing Deny ACEs' {
        $sddl = 'D:P(A;;FA;;;SY)(D;;FR;;;BU)'
        Get-GatewayLabDaclKey $sddl | Should -BeExactly $sddl
        Get-GatewayLabDaclKey $sddl | Should -Not -BeExactly (Get-GatewayLabDaclKey 'D:P(D;;FR;;;BU)(A;;FA;;;SY)')
    }

    It 'does not equate a missing DACL snapshot with an empty ACL' {
        Get-GatewayLabDaclKey '' | Should -Not -BeExactly (Get-GatewayLabDaclKey 'D:')
    }
}

Describe 'Rollback source isolation' {
    It 'rejects output inside the repository before writing files' {
        $repository = (Resolve-Path "$PSScriptRoot\..\..\..").Path
        { & "$PSScriptRoot\..\src\New-RollbackFixture.ps1" -OutputDirectory "$repository\rollback-forbidden-output" } |
            Should -Throw '*outside the repository*'
        Test-Path -LiteralPath "$repository\rollback-forbidden-output" | Should -BeFalse
    }

    It 'rejects an existing output directory' {
        { & "$PSScriptRoot\..\src\New-RollbackFixture.ps1" -OutputDirectory $TestDrive } |
            Should -Throw '*must not exist*'
    }
}

Describe 'Account fixture recovery guard' {
    It 'retains fixtures before attempting any account, rights, or AD cleanup' {
        InModuleScope GatewayLab {
            Mock Test-GatewayLabRecoveryRequired { $true }
            Mock Get-GatewayLabState { [pscustomobject]@{ Service = $null } }
            Mock Save-GatewayLabManifest {}
            $resource = [pscustomobject]@{ CleanupAttempts = 0 }
            # Fail before any native cleanup even if the recovery guard regresses.
            $resource | Add-Member -MemberType ScriptProperty -Name Type -Value {
                $this.CleanupAttempts++
                throw 'Fixture cleanup must not be attempted'
            }
            $resources = [Collections.Generic.List[object]]::new()
            $resources.Add($resource)
            $lab = @{ Resources = $resources }

            { Remove-GatewayLabAccounts $lab } | Should -Throw '*retaining test accounts for recovery*'

            $resource.CleanupAttempts | Should -Be 0
            $resources.Count | Should -Be 1
            Should -Invoke Get-GatewayLabState -Times 0 -Exactly
            Should -Invoke Save-GatewayLabManifest -Times 0 -Exactly
        }
    }
}
