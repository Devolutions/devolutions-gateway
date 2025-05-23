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
	'./Cargo.toml'
	'./crates/devolutions-pedm-shell-ext/AppxManifest.xml'
	'./dotnet/DesktopAgent/DesktopAgent.csproj'
	'./powershell/DevolutionsGateway/DevolutionsGateway.psd1'
	'./Cargo.lock'
	'./fuzz/Cargo.lock'
)

$linuxPackagingChangelogs = @(
	'./package/AgentLinux/CHANGELOG.md'
	'./package/Linux/CHANGELOG.md'
)

$today = Get-Date -Format 'yyyy-MM-dd'

$newLinuxChangelogSection = @(
    "## $NewVersion ($today)",
    "",
    "- No changes.",
    ""
)

try {
	$currentVersion = Get-Content -Path './VERSION'
	Write-Host "Current version is $currentVersion"
	Write-Host "Next version is $NewVersion"
	Write-Host

	if ($NewVersion -eq $currentVersion)
	{
		throw "The new version must be different than the current version."
	}

	foreach ($file in $targetFiles)
	{
		Write-Host "Updating $file"
		((Get-Content -Path "$file" -Raw) -Replace "$currentVersion","$NewVersion") | Set-Content -Path "$file" -NoNewline
	}

	foreach ($file in $linuxPackagingChangelogs)
	{
		Write-Host "Updating $file..."

		$lines = Get-Content -Path $file

		$prevSection = $lines | Where-Object { $_ -like "## $currentVersion*" }
		$prevSectionIndex = $lines.IndexOf($prevSection)

		if ($prevSectionIndex -lt 0) {
			throw "Could not find '## $currentVersion' in $file"
		}

		$updatedLines = $lines[0..($prevSectionIndex - 1)] + $newLinuxChangelogSection + $lines[$prevSectionIndex..($lines.Count - 1)]

		$updatedLines | Set-Content -Path $file
	}

	Write-Host

	Write-Host 'Script executed successfully. Run `git status` to make sure everything looks good.'
}
catch {
	Write-Host "An error occurred: $_"
	Write-Host $_.ScriptStackTrace

}
finally {
	Pop-Location
}
