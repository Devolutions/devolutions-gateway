#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
    $Project = "./Devolutions.Agent.Channel/Devolutions.Agent.Channel.csproj"

    dotnet build $Project --configuration Release
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed" }

    dotnet pack $Project --configuration Release --no-build
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed" }
} finally {
    Pop-Location
}