#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try
{
	pnpm install --frozen-lockfile --filter "@devolutions/shadow-player..."

	pnpm --filter @devolutions/shadow-player... build

	Set-Location -Path ./dist/
	npm pack
}
finally
{
	Pop-Location
}