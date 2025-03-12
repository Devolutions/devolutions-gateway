#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

$exitCode = 0

try {
	docker run --rm pedm-simulator
	$exitCode = $LASTEXITCODE
} finally {
	Pop-Location
	exit $exitCode
}
