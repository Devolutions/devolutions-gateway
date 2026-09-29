BeforeAll {
    Import-Module "$PSScriptRoot\..\..\src\windows-installer\GatewayLab.psm1" -Force
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
        { & "$PSScriptRoot\..\..\src\windows-installer\New-RollbackFixture.ps1" -OutputDirectory "$repository\rollback-forbidden-output" } |
            Should -Throw '*outside the repository*'
        Test-Path -LiteralPath "$repository\rollback-forbidden-output" | Should -BeFalse
    }

    It 'rejects an existing output directory' {
        { & "$PSScriptRoot\..\..\src\windows-installer\New-RollbackFixture.ps1" -OutputDirectory $TestDrive } |
            Should -Throw '*must not exist*'
    }
}
