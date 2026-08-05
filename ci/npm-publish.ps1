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

	$viewErrorLog = "$tmpFolder/npm-view-stderr.log"
	$distantVersion = npm view "$packageName" version --json 2>$viewErrorLog | ConvertFrom-Json
	$viewError = Get-Content -Raw -Path "$viewErrorLog"

	if ($LASTEXITCODE -Eq 0)
	{
		Write-Host "Latest version on registry is $distantVersion"
	}
	elseif ($viewError -Match 'E404')
	{
		Write-Host "Package is not published on the registry yet."
	}
	else
	{
		Write-Host "$viewError"
		throw "npm view failed for $packageName (exit code $LASTEXITCODE)"
	}

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

		if ($LASTEXITCODE -Ne 0)
		{
			throw "npm publish failed for $packageName@$localVersion (exit code $LASTEXITCODE)"
		}
	}
}
finally
{
	Remove-Item -Path "$tmpFolder" -Recurse -Force
}
