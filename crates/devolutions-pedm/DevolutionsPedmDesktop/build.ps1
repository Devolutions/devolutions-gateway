#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

& 'MSBuild.exe' "/t:restore,build" "/p:Configuration=Release" | Out-Host

Pop-Location
