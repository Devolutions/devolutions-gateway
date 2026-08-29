$ErrorActionPreference = "Stop"

$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$testerPath = Join-Path $workspacePath "target/debug/agent-policy-tester.exe"
$agentPath = Join-Path $workspacePath "target/debug/devolutions-agent.exe"
$lowIntegrityTemp = Join-Path $env:USERPROFILE "AppData\LocalLow\Temp"

New-Item -ItemType Directory -Path $lowIntegrityTemp -Force | Out-Null
$env:TEMP = $lowIntegrityTemp
$env:TMP = $lowIntegrityTemp

& $testerPath $agentPath unelevated
exit $LASTEXITCODE
