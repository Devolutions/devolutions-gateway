#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Import-Module Pester

Push-Location -Path $(Join-Path $PSScriptRoot 'pester')

try {
	Invoke-Pester . -Show All
} finally {
	Pop-Location
}
