#/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[string] $Path,
	[string] $Access = 'restricted'
)

$ErrorActionPreference = "Stop"

Push-Location -Path $Path

try
{
	$localInfo = Get-Content -Path ./package.json | ConvertFrom-Json
	$packageName = $localInfo.name
	$localVersion = $localInfo.version

	Write-Host "Found package $packageName"
	Write-Host "Local version is $localVersion"
	
	$distantInfo = npm search "$packageName" --json | ConvertFrom-Json | Where { $_.name -Eq "$packageName" }
	$distantVersion = $distantInfo.version

	Write-Host "Latest version on registry is $distantVersion"
	
	if ($localVersion -Eq $distantVersion)
	{
		Write-Host "Local and distant versions are identical. Skip publishing."
	}
	else
	{
		Write-Host "Publishing..."
		npm publish "--access=$Access"
	}
}
finally
{
	Pop-Location
}
