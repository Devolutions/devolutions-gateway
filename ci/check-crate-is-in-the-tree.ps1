#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[ValidateSet('devolutions-gateway')]
	[string] $Package,

	[Parameter(Mandatory=$true)]
	[ValidateSet('aws-lc-fips-sys')]
	[string] $RequiredDependency,

	[Parameter(Mandatory=$true)]
	[ValidateSet('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc')]
	[string] $Target,

	[string] $Features,

	[switch] $NoDefaultFeatures
)

$ErrorActionPreference = 'Stop'

$cargoArgs = @('tree', '--locked', '-p', $Package, '--target', $Target, '--edges', 'normal,build')
if ($NoDefaultFeatures) {
	$cargoArgs += '--no-default-features'
}
if ($Features) {
	$cargoArgs += '--features', $Features
}

$dependencyPattern = '(^|[^A-Za-z0-9_-])' + [regex]::Escape($RequiredDependency) + ' v[0-9]'
$tree = & cargo $cargoArgs 2>&1
if ($LASTEXITCODE -ne 0) {
	throw "cargo tree failed:`n$($tree -join [Environment]::NewLine)"
}

$result = $tree | Select-String -Pattern $dependencyPattern -CaseSensitive
if ($null -eq $result) {
	throw "$RequiredDependency was not found in the dependency tree of $Package crate"
}

Write-Host "$RequiredDependency was found in the dependency tree of $Package crate"
