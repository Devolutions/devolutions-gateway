param(
    [Parameter(Mandatory = $true)]
    [string] $TempPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

$ErrorActionPreference = "Stop"

$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$testerPath = Join-Path $workspacePath "target/debug/agent-policy-tester.exe"
$agentPath = Join-Path $workspacePath "target/debug/devolutions-agent.exe"

try {
    $env:TEMP = $TempPath
    $env:TMP = $TempPath

    & $testerPath $agentPath unelevated 2>&1 | Out-File -LiteralPath $OutputPath
    $exitCode = $LASTEXITCODE
} catch {
    $_ | Out-File -LiteralPath $OutputPath -Append
    exit 1
}

exit $exitCode
