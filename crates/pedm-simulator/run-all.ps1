#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
    .\prepare.ps1
    .\build-container.ps1
    .\run-container.ps1 -Mode Elevated
    .\run-container.ps1 -Mode NonElevated
} finally {
    .\clean.ps1
    Pop-Location
}

