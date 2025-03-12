#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
	Remove-Item -Path "./artifacts" -Recurse -ErrorAction SilentlyContinue
} finally {
	Pop-Location
}
