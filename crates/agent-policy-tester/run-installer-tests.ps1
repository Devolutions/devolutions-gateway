param(
    [Parameter(Mandatory)] [string] $ProjectPath,
    [Parameter(Mandatory)] [string] $TestOutputPath,
    [Parameter(Mandatory)] [string] $AgentPath,
    [Parameter(Mandatory)] [string] $ResultsPath,
    [Parameter(Mandatory)] [string] $DotnetPath
)

$ErrorActionPreference = "Stop"
$exitCode = 1
$previousAgent = $env:DEVOLUTIONS_AGENT_MIGRATION_TEST_EXE

try {
    if (-not [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        throw "Installer transaction tests must execute as LocalSystem"
    }
    $testClass = 'DevolutionsAgent.Installer.Tests.PackageBrokerInstallerTests'
    $expectedTests = @(
        "$testClass.TransactionTestsRunAsLocalSystem"
        "$testClass.InstalledAgentConverterUsesAuthoritativeContractBeforePublication"
        "$testClass.ConvertedMigrationCommitAndRepeatPreserveOriginalAndEvidence"
        "$testClass.RollbackRestoresLegacyArbitrationAndMigrationCanRepeat"
        "$testClass.InterruptedPublicationRecoversOnlyOwnedAuthority"
        "$testClass.InvalidLegacyPolicyFailsUpgradeAndPreservesSource"
        "$testClass.ExistingNewDestinationAndPublicationCollisionArePreserved"
        "$testClass.ChangedSourcePreventsDestructiveRollback"
        "$testClass.PreexistingAuthorityPreventsLegacyResurrection"
        "$testClass.AuthorityCollisionCannotCommitSourceDeletion"
        "$testClass.DestinationCollisionCannotCommitSourceDeletion"
        "$testClass.UnchangedInputRollbackPreservesLastSurvivingPolicy"
        'DevolutionsAgent.Installer.Tests.InstalledAgentMigrationE2eTests.ConvertedTransactionActivatesAndRetainsManagedAuthority'
    )
    $filter = ($expectedTests | ForEach-Object { "FullyQualifiedName=$_" }) -join '|'
    New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null
    $trxPath = Join-Path $ResultsPath "installer-system.trx"
    if (Test-Path -LiteralPath $trxPath) {
        Remove-Item -LiteralPath $trxPath -Force
    }
    $env:DEVOLUTIONS_AGENT_MIGRATION_TEST_EXE = (Resolve-Path -LiteralPath $AgentPath).Path
    & $DotnetPath test $ProjectPath --no-build --no-restore --configuration Debug --framework net48 `
        "-p:OutputPath=$TestOutputPath\" -p:AppendTargetFrameworkToOutputPath=false `
        --filter $filter --logger "trx;LogFileName=installer-system.trx" --results-directory $ResultsPath
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "SYSTEM installer tests exited with $exitCode"
    }
    [xml] $trx = Get-Content -LiteralPath $trxPath -Raw
    $counters = $trx.TestRun.ResultSummary.Counters
    $results = @($trx.TestRun.Results.UnitTestResult)
    if ($trx.TestRun.ResultSummary.outcome -ne 'Completed' -or
        [int] $counters.total -ne $expectedTests.Count -or
        [int] $counters.executed -ne $expectedTests.Count -or
        [int] $counters.passed -ne $expectedTests.Count -or
        [int] $counters.notExecuted -ne 0 -or
        $results.Count -ne $expectedTests.Count) {
        throw "Expected exactly $($expectedTests.Count) executed, passed SYSTEM installer tests and zero skips: $($counters.OuterXml)"
    }
    foreach ($name in $expectedTests) {
        $matching = @($results | Where-Object { $_.testName -eq $name })
        if ($matching.Count -ne 1 -or $matching[0].outcome -ne 'Passed') {
            throw "Required SYSTEM installer test did not pass exactly once: $name"
        }
    }
    Write-Output "Verified all 12 installer SystemFacts and the installed-Agent migration E2E: 13 passed, zero skipped"
} catch {
    Write-Output $_
    if ($exitCode -eq 0) {
        $exitCode = 1
    }
} finally {
    $env:DEVOLUTIONS_AGENT_MIGRATION_TEST_EXE = $previousAgent
}

exit $exitCode
