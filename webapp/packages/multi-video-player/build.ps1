#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot/../..

try
{
	pnpm install

	pnpm --filter @devolutions/multi-video-player... build

	Set-Location -Path packages/multi-video-player/dist
	npm pack
}
finally
{
	Pop-Location
}