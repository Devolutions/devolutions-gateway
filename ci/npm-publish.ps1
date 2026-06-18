#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[string] $Tarball,
	[string] $Access = 'restricted'
)

$ErrorActionPreference = "Stop"

$tmpFolder = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid()
Write-Host "Temporary directory to extract package tarball: $tmpFolder"
New-Item -ItemType Directory -Path "$tmpFolder" | Out-Null

try
{
	tar xf "$Tarball" --directory "$tmpFolder"

	$localInfo = Get-Content -Path "$tmpFolder/package/package.json" | ConvertFrom-Json
	$packageName = $localInfo.name
	$localVersion = $localInfo.version

	Write-Host "Found package $packageName"
	Write-Host "Local version is $localVersion"

	$distantInfo = npm view "$packageName" --json | ConvertFrom-Json
	$distantVersion = $distantInfo.version

	Write-Host "Latest version on registry is $distantVersion"

	if ($localVersion -Eq $distantVersion)
	{
		Write-Host "Local and distant versions are identical. Skip publishing."
	}
	else
	{
		Write-Host "Publishing..."
		# Reset NODE_AUTH_TOKEN to empty is a workaround for https://github.com/actions/setup-node/issues/1440 (OIDC trusted publishing)
		$env:NODE_AUTH_TOKEN = ""
		npm publish "$Tarball" "--access=$Access"
	}
}
finally
{
	Remove-Item -Path "$tmpFolder" -Recurse -Force
}
