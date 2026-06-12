#!/bin/env pwsh

# Builds and packs the broker client, substituting a date-based version into the
# csproj before packaging (mirrors the now-proto NuGet release flow). The version
# can be overridden with -Version or the PACKAGE_VERSION environment variable.

[CmdletBinding()]
param(
	[string]$Version = $env:PACKAGE_VERSION
)

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
	$Csproj = "./Devolutions.UniGetUI.Broker.Client/Devolutions.UniGetUI.Broker.Client.csproj"

	if ([string]::IsNullOrEmpty($Version) -or $Version -eq 'latest') {
		$Version = (Get-Date -Format "yyyy.MM.dd") + ".0"
	}

	if ($Version -NotMatch '^\d+\.\d+\.\d+\.\d+$') {
		throw "invalid version format: $Version, expected: 1.2.3.4"
	}

	Write-Host "Packaging Devolutions.UniGetUI.Broker.Client $Version"

	# Substitute the placeholder <Version> before packing, then restore it so the
	# working tree stays clean (CI checkouts are disposable; local runs are not).
	$Original = Get-Content $Csproj -Raw
	try {
		$Patched = $Original -Replace '(<Version>).*?(</Version>)', "<Version>$Version</Version>"
		Set-Content -Path $Csproj -Value $Patched -Encoding UTF8 -NoNewline

		dotnet build --configuration Release $Csproj
		dotnet pack --configuration Release $Csproj
	}
	finally {
		Set-Content -Path $Csproj -Value $Original -Encoding UTF8 -NoNewline
	}
}
finally {
	Pop-Location
}
