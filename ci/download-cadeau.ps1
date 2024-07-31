#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
    [ValidateSet('win', 'linux', 'osx')]
    [string] $Platform,

	[Parameter(Mandatory=$true)]
    [ValidateSet('x64', 'arm64')]
    [string] $Architecture
)

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

$tmpFolder = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid()
Write-Host "Temporary directory: $tmpFolder"
New-Item -ItemType "directory" -Path "$tmpFolder" | Out-Null

$downloadUrl = "https://github.com/Devolutions/cadeau/releases/download/v2024.7.23.0/cadeau-$Platform-$Architecture.zip"

try
{
	Invoke-WebRequest $downloadUrl -OutFile "$tmpFolder/cadeau.zip"
	New-Item -Path "../native-libs" -ItemType Directory -Force | Out-Null
	Expand-Archive "$tmpFolder/cadeau.zip" "../native-libs" -Force
}
finally
{
	Remove-Item -Path "$tmpFolder" -Recurse -Force
	Pop-Location
}
