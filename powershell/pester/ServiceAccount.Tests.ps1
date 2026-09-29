BeforeAll {
    . "$PSScriptRoot\..\DevolutionsGateway\Private\Msi.ps1"
    . "$PSScriptRoot\..\DevolutionsGateway\Public\DGateway.ps1"
}

Describe 'Gateway service account MSI arguments' {
    It 'quotes <Label> without changing the MSI property value' -TestCases @(
        @{ Label = 'spaces'; Value = 'a b'; Expected = 'P.SERVICEPASSWORD="a b"' }
        @{ Label = 'quotes'; Value = 'a"b'; Expected = 'P.SERVICEPASSWORD="a""b"' }
        @{ Label = 'backslashes'; Value = 'a\b\'; Expected = 'P.SERVICEPASSWORD="a\b\"' }
        @{ Label = 'metacharacters'; Value = 'a$;b'; Expected = 'P.SERVICEPASSWORD="a$;b"' }
        @{ Label = 'empty strings'; Value = ''; Expected = 'P.SERVICEPASSWORD=""' }
    ) {
        param($Value, $Expected)
        ConvertTo-DGatewayMsiProperty 'P.SERVICEPASSWORD' $Value | Should -BeExactly $Expected
    }

    It 'preserves non-ASCII characters' {
        $value = 'Pass' + [char]0x00e9 + '123!'
        ConvertTo-DGatewayMsiProperty 'P.SERVICEPASSWORD' $value |
            Should -BeExactly ('P.SERVICEPASSWORD="' + $value + '"')
    }

    It 'rejects embedded null characters' {
        { ConvertTo-DGatewayMsiProperty 'P.SERVICEPASSWORD' ("a" + [char]0 + "b") } | Should -Throw
    }
}

Describe 'Gateway installer results' -Skip:($PSEdition -ne 'Desktop' -and -not $IsWindows) {
    BeforeAll {
        function Get-DGatewayVersion { param($Type) }
        if (-not (Test-Path 'variable:global:IsWindows')) {
            $script:IsWindows = $true
        }
        $script:source = Join-Path $TestDrive 'input.msi'
        Set-Content -LiteralPath $script:source -Value 'test package'
    }

    BeforeEach {
        $script:version = [guid]::NewGuid().ToString('N')
        Mock Get-DGatewayVersion { 'not-installed' }
        Mock Get-DGatewayPackage { [pscustomobject]@{ Url = ([uri]$script:source).AbsoluteUri } }
        Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
    }

    AfterEach {
        $path = Join-Path ([IO.Path]::GetTempPath()) "dgateway-$script:version"
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }

    It 'passes credentials through the MSI escaping helper' {
        $credential = [pscredential]::new('.\test', (ConvertTo-SecureString 'a"b\$;' -AsPlainText -Force))
        Install-DGatewayPackage -RequiredVersion $script:version -ServiceCredential $credential
        Should -Invoke Start-Process -Times 1 -ParameterFilter {
            $PassThru -and
            ($ArgumentList -contains 'P.SERVICEACCOUNT=".\test"') -and
            ($ArgumentList -contains 'P.SERVICEPASSWORD="a""b\$;"')
        }
    }

    It 'rejects mismatched credential and account names' {
        $credential = [pscredential]::new('.\test', (ConvertTo-SecureString 'test' -AsPlainText -Force))
        { Install-DGatewayPackage -ServiceAccount '.\different' -ServiceCredential $credential } | Should -Throw '*must match*'
        Should -Invoke Start-Process -Times 0
    }

    It 'throws on MSI failure and retains the diagnostic directory' {
        Mock Start-Process { [pscustomobject]@{ ExitCode = 1603 } }
        { Install-DGatewayPackage -RequiredVersion $script:version } | Should -Throw '*1603*Log:*'
        Test-Path -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) "dgateway-$script:version") | Should -BeTrue
    }

    It 'reports a required reboot without rebooting' {
        Mock Start-Process { [pscustomobject]@{ ExitCode = 3010 } }
        Mock Write-Warning {}
        Install-DGatewayPackage -RequiredVersion $script:version
        Should -Invoke Write-Warning -Times 1 -ParameterFilter { $Message -like '*requires a restart*' }
        Should -Invoke Start-Process -Times 1 -ParameterFilter { $ArgumentList -contains '/norestart' }
    }
}

Describe 'Gateway service accounts on non-Windows platforms' -Skip:($PSEdition -eq 'Desktop' -or $IsWindows) {
    BeforeEach {
        Mock Start-Process {}
    }

    It 'rejects service accounts before launching the installer' {
        { Install-DGatewayPackage -ServiceAccount '.\test' } | Should -Throw '*supported only on Windows*'
        Should -Invoke Start-Process -Times 0
    }

    It 'rejects credentials before launching the installer' {
        $credential = [pscredential]::new('.\test', (ConvertTo-SecureString 'test' -AsPlainText -Force))
        { Install-DGatewayPackage -ServiceCredential $credential } | Should -Throw '*supported only on Windows*'
        Should -Invoke Start-Process -Times 0
    }
}
