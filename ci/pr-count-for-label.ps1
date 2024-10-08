#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[string] $Label
)

$ErrorActionPreference = "Stop"

# This script is intended for release process labels,
# and we don’t expect more than 100 of these.

$count = gh api `
	-H "Accept: application/vnd.github+json" `
	-H "X-GitHub-Api-Version: 2022-11-28" `
	"/search/issues?per_page=100&q=repo:Devolutions/devolutions-gateway+is:closed+is:pull-request+label:$Label" `
	--jq .total_count

[int]$count
