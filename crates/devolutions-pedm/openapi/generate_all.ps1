#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
	../../../tools/generate-openapi/generate.ps1 pedm | Out-Host
	if (!$?) {
		throw "Failed to generate pedm-api.yaml"
	}

	# Cheat because of buggy aide-rs
	(Get-Content .\pedm-api.yaml).Replace('uint16', 'int32').Replace('uint', 'int') | Set-Content .\pedm-api.yaml

	.\generate_clients.ps1 | Out-Host
} finally {
	Pop-Location
}
