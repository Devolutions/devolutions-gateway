#/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

npm install
npm run build

Pop-Location
