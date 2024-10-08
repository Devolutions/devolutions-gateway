#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[string] $Label
)

$ErrorActionPreference = "Stop"

# This script is intended for release process labels,
# and we don’t expect more than 100 of these.

$issues = gh api `
	-H "Accept: application/vnd.github+json" `
	-H "X-GitHub-Api-Version: 2022-11-28" `
	"/repos/Devolutions/devolutions-gateway/issues?labels=$Label&state=closed&per_page=100"
		| ConvertFrom-Json

foreach ($issue in $issues)
{
	Write-Host "Removing $Label label from $($issue.url)..."

	gh api `
		--method DELETE `
		-H "Accept: application/vnd.github+json" `
		-H "X-GitHub-Api-Version: 2022-11-28" `
		"/repos/Devolutions/devolutions-gateway/issues/$($issue.number)/labels/$Label"
			| Out-Null
}
