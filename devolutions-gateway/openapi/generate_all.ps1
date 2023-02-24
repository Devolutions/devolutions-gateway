#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
	../../tools/generate-openapi/generate.ps1
	./generate_clients.ps1
} finally {
	Pop-Location
}
