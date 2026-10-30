#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
    $Project = "./Devolutions.Agent.Identity.Authority/Devolutions.Agent.Identity.Authority.csproj"

    dotnet build $Project --configuration Release
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed" }

    dotnet pack $Project --configuration Release --no-build
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed" }
} finally {
    Pop-Location
}
