[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Msi,
    [Parameter(Mandatory)][string] $NextMsi,
    [Parameter(Mandatory)][string] $OutputDirectory,
    [ValidateSet('NetworkService', 'Virtual', 'Local', 'LocalDollar', 'Domain', 'Smsa', 'Gmsa')]
    [string[]] $AccountKinds = @('NetworkService', 'Virtual', 'Local', 'LocalDollar'),
    [ValidateRange(1024, 65535)][int] $Port = 48181,
    [string] $AgentExecutable,
    [switch] $TestCertificateMigration,
    [string] $TestFilter = '*',
    [switch] $LegacyBaseline,
    [switch] $TestRollback,
    [ValidateSet('after-remove', 'after-service', 'after-permissions')]
    [string[]] $RollbackFailurePoints = @('after-remove', 'after-service', 'after-permissions'),
    [switch] $RollbackAccountChanges,
    [switch] $Execute
)

$ErrorActionPreference = 'Stop'
if ($TestCertificateMigration -and 'Local' -notin $AccountKinds) {
    throw 'TestCertificateMigration requires the Local account fixture'
}
Import-Module "$PSScriptRoot\src\GatewayLab.psm1" -Force
$first = Get-GatewayLabMsi $Msi
$next = Get-GatewayLabMsi $NextMsi
if ($first.UpgradeCode -ne $next.UpgradeCode) { throw 'The MSI UpgradeCode values differ' }
if ([version]$first.ProductVersion -ge [version]$next.ProductVersion) { throw 'NextMsi must have a higher MSI ProductVersion' }
if ($first.ProductCode -eq $next.ProductCode) { throw 'Major-upgrade scenarios require different ProductCode values' }
if ($TestRollback) {
    if (-not $next.IsRollbackFixture -or $first.IsRollbackFixture) { throw 'Rollback tests require a normal baseline and a marked test-only next MSI' }
    if ($TestCertificateMigration -or $AgentExecutable) { throw 'Run rollback separately from certificate and Agent scenarios' }
} elseif ($first.IsRollbackFixture -or $next.IsRollbackFixture) {
    throw 'A fault-injection MSI can only be used with -TestRollback'
}

if (-not $Execute) {
    [pscustomobject]@{
        Mode = 'DiscoveryOnly'; Msi = $first; NextMsi = $next
        Accounts = $AccountKinds; CurrentState = Get-GatewayLabState
        MutationRequires = '-Execute on a disposable elevated Windows host'
    }
    return
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the lab elevated' }
Import-Module Pester -MinimumVersion 5.7.1 -ErrorAction Stop
$mutex = [Threading.Mutex]::new($false, 'Global\DevolutionsGateway-ServiceAccountLab')
if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); throw 'Another Gateway installer lab owns the machine' }
$lab = $null
try {
    [Diagnostics.Process]::EnterDebugMode()
    $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
    $registered = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object DisplayName -eq 'Devolutions Gateway')
    if ((Get-GatewayLabState).Service -or (Test-Path -LiteralPath $data) -or $registered.Count) {
        throw 'A Gateway service or data directory already exists; refusing to overwrite an unowned installation'
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    $listener.Stop()
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory for this run' }
    $output = (New-Item -ItemType Directory -Path $OutputDirectory).FullName
    $acl = Get-Acl -LiteralPath $output
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $output -AclObject $acl
    $lab = @{
        RunId = [guid]::NewGuid().ToString('N'); Output = $output; Port = $Port
        Msi = $first; NextMsi = $next
        Blocked = [Collections.Generic.List[string]]::new()
        Resources = [Collections.Generic.List[object]]::new()
        AgentExecutable = if ($AgentExecutable) { (Resolve-Path -LiteralPath $AgentExecutable).Path } else { $null }
        LegacyBaseline = [bool]$LegacyBaseline
        RollbackAccountChanges = [bool]$RollbackAccountChanges
        RollbackFailurePoints = $RollbackFailurePoints
    }
    (Get-GatewayLabState) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$output\before.json" -Encoding UTF8
    Save-GatewayLabManifest $lab
    $lab.Accounts = @(New-GatewayLabAccounts -Lab $lab -Kinds $AccountKinds)
    Save-GatewayLabManifest $lab
    foreach ($reason in $lab.Blocked) { Write-Warning "Blocked scenario: $reason" }
    $testFile = if ($TestRollback) { 'Rollback.Tests.ps1' } else { 'ServiceAccounts.Tests.ps1' }
    $container = New-PesterContainer -Path "$PSScriptRoot\tests\$testFile" -Data @{ Lab = $lab }
    if ($TestCertificateMigration) {
        $container = @($container) + @(New-PesterContainer -Path "$PSScriptRoot\tests\CertificateMigration.Tests.ps1" -Data @{ Lab = $lab })
    }
    $configuration = New-PesterConfiguration
    $configuration.Run.Container = $container
    $configuration.Run.PassThru = $true
    $configuration.Run.SkipRemainingOnFailure = if ($TestRollback) { 'Block' } else { 'Run' }
    $configuration.Output.Verbosity = 'Detailed'
    $configuration.Filter.FullName = $TestFilter
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = "$output\results.xml"
    $result = Invoke-Pester -Configuration $configuration
    [ordered]@{
        Passed = $result.PassedCount; Failed = $result.FailedCount; Skipped = $result.SkippedCount
        NotRun = $result.NotRunCount
        Blocked = @($lab.Blocked.ToArray())
    } | ConvertTo-Json | Set-Content -LiteralPath "$output\summary.json" -Encoding UTF8
    if ($result.FailedCount) { throw "Installer scenarios failed; see $output" }
} catch {
    if ($lab) {
        $_.Exception.Message | Set-Content -LiteralPath "$($lab.Output)\failure.txt" -Encoding UTF8
    }
    throw
} finally {
    try {
        if ($lab) {
            (Get-GatewayLabState) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$($lab.Output)\after.json" -Encoding UTF8
            Remove-GatewayLabAccounts $lab
            Save-GatewayLabManifest $lab
        }
    } finally {
        [Diagnostics.Process]::LeaveDebugMode()
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
