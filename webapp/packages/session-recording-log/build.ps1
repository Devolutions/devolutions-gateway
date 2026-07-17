#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try
{
	pnpm install

	pnpm --filter @devolutions/session-recording-log... build

	Set-Location -Path ./dist/
	npm pack
}
finally
{
	Pop-Location
}
