#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[ValidateSet('win', 'linux', 'osx')]
	[string] $Platform,

	[Parameter(Mandatory=$true)]
	[ValidateSet('x64', 'arm64')]
	[string] $Architecture,

	[string] $VersionTag = "v2025.7.16.0"
)

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

$tmpFolder = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid()
Write-Host "Temporary directory: $tmpFolder"
New-Item -ItemType Directory -Path "$tmpFolder" | Out-Null

$downloadUrl = "https://github.com/Devolutions/cadeau/releases/download/$VersionTag/cadeau-$Platform-$Architecture.zip"
Write-Host "Download URL: $downloadUrl"

try
{
	Invoke-WebRequest $downloadUrl -OutFile "$tmpFolder/cadeau.zip"
	New-Item -Path "../native-libs" -ItemType Directory -Force | Out-Null
	$expanded = Expand-Archive "$tmpFolder/cadeau.zip" "../native-libs" -Force -PassThru
	Write-Host "Extracted: $expanded"
}
finally
{
	Remove-Item -Path "$tmpFolder" -Recurse -Force
	Pop-Location
}
