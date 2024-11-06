#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[ValidateSet('devolutions-gateway', 'devolutions-agent', 'jetsocat')]
	[string] $Package,

	[Parameter(Mandatory=$true)]
	[ValidateSet('aws-lc-rs', 'ring')]
	[string] $UnwantedDependency,

	[Parameter(Mandatory=$true)]
	[ValidateSet('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc')]
	[string] $Target
)

$ErrorActionPreference = "Stop"

$result = cargo tree -p "$Package" --target "$Target" | Select-String -Pattern "$UnwantedDependency" -CaseSensitive -SimpleMatch

if ([string]::IsNullOrEmpty($result)) {
	Write-Host "$UnwantedDependency is nowhere to be found in the dependency tree of $Package crate"
} else {
	throw "$UnwantedDependency was found in the dependency tree of $Package crate"
}
