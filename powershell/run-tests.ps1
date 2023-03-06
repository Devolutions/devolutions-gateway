#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Import-Module Pester

Push-Location -Path $(Join-Path $PSScriptRoot 'pester')

try {
	Invoke-Pester .
} finally {
	Pop-Location
}

