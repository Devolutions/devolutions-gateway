param([Parameter(Mandatory)][string] $InstallerAssembly)

BeforeAll {
    $assembly = [Reflection.Assembly]::LoadFrom($InstallerAssembly)
    $script:accountType = $assembly.GetType('DevolutionsGateway.Helpers.GatewayServiceAccount', $true)
    function Resolve-TestAccount([string] $Name) {
        $arguments = [object[]]@($Name, 'DevolutionsGateway', $null, $null)
        $success = $script:accountType.GetMethod('TryResolve', [Reflection.BindingFlags]'Static,NonPublic').Invoke($null, $arguments)
        [pscustomobject]@{ Success = $success; Account = $arguments[2]; Error = $arguments[3] }
    }
}

Describe 'Installer account classification without service installation' {
    It 'resolves the virtual account even before the service exists' {
        $result = Resolve-TestAccount 'NT SERVICE\DevolutionsGateway'
        $result.Success | Should -BeTrue
        $sid = $script:accountType.GetProperty('Sid', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($result.Account).Value
        $native = & "$env:SystemRoot\System32\sc.exe" showsid DevolutionsGateway
        ($native -join "`n") | Should -Match ([regex]::Escape($sid))
    }

    It 'accepts NETWORK SERVICE as the default' {
        $result = Resolve-TestAccount ''
        $result.Success | Should -BeTrue
        $script:accountType.GetProperty('RequiresPassword', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($result.Account) | Should -BeFalse
    }

    It 'rejects <Name>' -TestCases @(
        @{ Name = 'NT AUTHORITY\SYSTEM' }
        @{ Name = 'NT AUTHORITY\LOCAL SERVICE' }
        @{ Name = 'BUILTIN\Users' }
        @{ Name = 'NT SERVICE\EventLog' }
        @{ Name = 'nonexistent-gateway-test-account' }
    ) {
        param($Name)
        (Resolve-TestAccount $Name).Success | Should -BeFalse
    }
}
