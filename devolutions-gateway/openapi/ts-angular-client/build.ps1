#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try
{
	npm install

	npm run build

	Set-Location -Path ./dist/
	npm pack
}
finally
{
	Pop-Location
}
