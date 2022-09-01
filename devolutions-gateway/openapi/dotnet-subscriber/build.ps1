#/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

dotnet build --configuration Release
dotnet pack --configuration Release

Pop-Location
