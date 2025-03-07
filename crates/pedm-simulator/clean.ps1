#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
	Remove-Item -Path "pedm-simulator.exe" -Force
	Remove-Item -Path "clang_rt.asan_dynamic-x86_64.dll" -Force
} finally {
	Pop-Location
}
