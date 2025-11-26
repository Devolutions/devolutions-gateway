#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot/../..

try
{
	pnpm install

	pnpm --filter @devolutions/shadow-player... build

	Set-Location -Path packages/shadow-player/dist
	npm pack
}
finally
{
	Pop-Location
}