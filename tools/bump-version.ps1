#!/bin/env pwsh

param(
        [Parameter(Mandatory=$true)]
        [string] $NewVersion
)

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot
Set-Location -Path ..

$targetFiles = @(
	'./VERSION'
	'./jetsocat/Cargo.toml'
	'./devolutions-gateway/Cargo.toml'
	'./devolutions-agent/Cargo.toml'
	'./devolutions-session/Cargo.toml'
	'./crates/devolutions-pedm-shell-ext/Cargo.toml'
	'./crates/devolutions-pedm-shell-ext/AppxManifest.xml'
	'./crates/devolutions-pedm/openapi/dotnet-client/config.json'
	'./dotnet/DesktopAgent/DesktopAgent.csproj'
	'./powershell/DevolutionsGateway/DevolutionsGateway.psd1'
	'./Cargo.lock'
	'./fuzz/Cargo.lock'
)

try {
	$currentVersion = Get-Content -Path './VERSION'
	Write-Host "Current version is $currentVersion"
	Write-Host "Next version is $NewVersion"
	Write-Host

	ForEach ($file in $targetFiles)
	{
		Write-Host "Updating $file"
		((Get-Content -Path "$file" -Raw) -Replace "$currentVersion","$NewVersion") | Set-Content -Path "$file" -NoNewline
	}
	Write-Host

	Write-Host 'Script executed successfully. Run `git status` to make sure everything looks good.'
}
catch {
	Write-Host 'An error occurred:'
	Write-Host $_.ScriptStackTrace
}
finally {
	Pop-Location
}
