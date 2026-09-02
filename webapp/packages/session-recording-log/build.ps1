#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try
{
	pnpm install --frozen-lockfile --filter "@devolutions/session-recording-log..."

	pnpm --filter @devolutions/session-recording-log... build

	Set-Location -Path ./dist/
	npm pack
}
finally
{
	Pop-Location
}
