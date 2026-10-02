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
	[string] $Target,

	[string] $Features,

	[switch] $NoDefaultFeatures,

	[switch] $ProductionOnly
)

$ErrorActionPreference = "Stop"

$cargoArgs = @('tree', '--locked', '-p', $Package, '--target', $Target)
if ($ProductionOnly) {
	$cargoArgs += '--edges', 'normal,build'
}
if ($NoDefaultFeatures) {
	$cargoArgs += '--no-default-features'
}
if ($Features) {
	$cargoArgs += '--features', $Features
}

$dependencyPattern = '(^|[^A-Za-z0-9_-])' + [regex]::Escape($UnwantedDependency) + ' v[0-9]'
$tree = & cargo $cargoArgs 2>&1
if ($LASTEXITCODE -ne 0) {
	throw "cargo tree failed:`n$($tree -join [Environment]::NewLine)"
}

$result = $tree | Select-String -Pattern $dependencyPattern -CaseSensitive
if ($null -eq $result) {
	Write-Host "$UnwantedDependency is nowhere to be found in the dependency tree of $Package crate"
} else {
	throw "$UnwantedDependency was found in the dependency tree of $Package crate"
}
