#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try
{
	pnpm install --frozen-lockfile --filter "@devolutions/web-recorder..."

	if ($LASTEXITCODE -ne 0)
	{
		throw "pnpm install failed with exit code $LASTEXITCODE"
	}

	pnpm --filter @devolutions/web-recorder... build

	Set-Location -Path ./dist/
	npm pack
}
finally
{
	Pop-Location
}
