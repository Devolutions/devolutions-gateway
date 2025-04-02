#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

$exitCode = 0

try {
	$Env:PEDM_SIMULATOR_EXPECT_ELEVATION = '1'
	& ./artifacts/pedm-simulator.exe 2>&1 | Out-File ./pedm-simulator_run-expect-elevation.out
	$exitCode = $LASTEXITCODE
} finally {
	Pop-Location
	exit $exitCode
}
