$ErrorActionPreference = "Stop"

$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$testerPath = Join-Path $workspacePath "target/debug/agent-policy-tester.exe"
$agentPath = Join-Path $workspacePath "target/debug/devolutions-agent.exe"
$outputPath = Join-Path $PSScriptRoot "agent-policy-tester-unelevated.out"

try {
    & $testerPath $agentPath unelevated 2>&1 | Out-File $outputPath
    $exitCode = $LASTEXITCODE
} catch {
    $_ | Out-File $outputPath -Append
    exit 1
}

exit $exitCode
