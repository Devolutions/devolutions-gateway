BeforeAll {
    Import-Module "$PSScriptRoot\..\..\src\windows-installer\GatewayLab.psm1" -Force
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        "$PSScriptRoot\ServiceAccounts.Tests.ps1", [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors -join '; ') }
    # Execute only the upgrade assertion body, never the lifecycle setup or teardown.
    $upgrade = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'It' -and
            $node.CommandElements[1].Value -eq 'upgrades without respecifying the account and preserves configuration'
    }, $true))
    if ($upgrade.Count -ne 1) { throw 'Expected exactly one Agent upgrade scenario' }
    $script:upgradeScenario = $upgrade[0].CommandElements[-1].ScriptBlock.GetScriptBlock()
}

Describe 'Agent upgrade signature policy' {
    BeforeEach {
        $script:caseDirectory = $TestDrive
        $script:configHash = 'unchanged'
        $script:account = [pscustomobject]@{ Kind = 'Virtual' }
        $script:events = [Collections.Generic.List[string]]::new()
        $Credential = $null
        $Lab = @{
            AgentExecutable = 'unused-agent.exe'
            NextMsi = [pscustomobject]@{ Signature = 'Valid'; ProductVersion = '26.3.0' }
            Port = 48181
        }
        Mock Start-GatewayLabAgent {
            $script:events.Add("start:$([bool]$AllowUnsigned)")
            [pscustomobject]@{ Directory = $Directory }
        }
        Mock Stop-GatewayLabAgent { $script:events.Add('stop') }
        Mock Invoke-GatewayLabAgentUpdate {
            if ($ExpectedError) { $script:events.Add('reject-signature') }
            else { $script:events.Add("update:$ExpectedVersion") }
        }
        Mock Wait-GatewayLabService { [pscustomobject]@{ ProcessId = 123 } }
        Mock Invoke-GatewayLabServiceProbe {
            [pscustomobject]@{
                UpdateCommandWritable = $true
                UpdateStatusReadable = $true
                UpdateStatusWritable = $false
            }
        }
        Mock Get-GatewayLabState { [pscustomobject]@{ ConfigHash = 'unchanged' } }
        Mock Start-Service {}
        Mock Test-GatewayLabRuntime {}
        Mock Invoke-GatewayLabMsi { throw 'MSI execution is forbidden in helper tests' }
    }

    It 'keeps signature validation enabled for a signed candidate' {
        & $script:upgradeScenario

        ($script:events -join ',') | Should -BeExactly 'start:False,update:2026.3.0,stop'
        Should -Invoke Start-GatewayLabAgent -Times 0 -Exactly -ParameterFilter { $AllowUnsigned }
        Should -Invoke Invoke-GatewayLabAgentUpdate -Times 0 -Exactly -ParameterFilter { $ExpectedError }
        Should -Invoke Invoke-GatewayLabServiceProbe -Times 1 -Exactly
        Should -Invoke Invoke-GatewayLabMsi -Times 0 -Exactly
    }

    It 'rejects <Signature> before explicitly retrying without signature validation' -TestCases @(
        @{ Signature = 'NotSigned' }
        @{ Signature = 'HashMismatch' }
    ) {
        param($Signature)
        $Lab.NextMsi.Signature = $Signature

        & $script:upgradeScenario

        ($script:events -join ',') | Should -BeExactly 'start:False,reject-signature,stop,start:True,update:2026.3.0,stop'
        Should -Invoke Invoke-GatewayLabAgentUpdate -Times 1 -Exactly -ParameterFilter { $ExpectedError -eq '*signature*' }
        Should -Invoke Invoke-GatewayLabServiceProbe -Times 1 -Exactly
        Should -Invoke Invoke-GatewayLabMsi -Times 0 -Exactly
    }

    It 'does not bypass verification when a signed candidate fails to update' {
        Mock Invoke-GatewayLabAgentUpdate { throw 'signature verification failed' }

        { & $script:upgradeScenario } | Should -Throw '*signature verification failed*'

        ($script:events -join ',') | Should -BeExactly 'start:False,stop'
        Should -Invoke Start-GatewayLabAgent -Times 0 -Exactly -ParameterFilter { $AllowUnsigned }
        Should -Invoke Start-Service -Times 0 -Exactly
        Should -Invoke Invoke-GatewayLabMsi -Times 0 -Exactly
    }
}
