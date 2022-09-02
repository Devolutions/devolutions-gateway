#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

../../tools/generate-openapi/generate.ps1
./generate_clients.ps1

Pop-Location
