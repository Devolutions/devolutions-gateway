#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try
{
	pnpm install --frozen-lockfile --filter "@devolutions/web-recorder..."

	pnpm --filter @devolutions/web-recorder... build

	Set-Location -Path ./dist/
	npm pack
}
finally
{
	Pop-Location
}
