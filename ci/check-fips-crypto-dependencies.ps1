#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[ValidateSet('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc')]
	[string] $Target
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path $PSScriptRoot -Parent
$auditManifest = Join-Path $repositoryRoot 'fips-audit/Cargo.toml'
$auditLock = Join-Path $repositoryRoot 'fips-audit/Cargo.lock'
$rootLock = Join-Path $repositoryRoot 'Cargo.lock'
$denyConfig = Join-Path $repositoryRoot 'deny-fips.toml'

Copy-Item $rootLock $auditLock -Force

& cargo metadata --offline --manifest-path $auditManifest --format-version 1 | Out-Null
if ($LASTEXITCODE -ne 0) {
	throw 'failed to resolve the isolated FIPS audit graph from the repository lockfile'
}

& (Join-Path $PSScriptRoot 'check-crate-is-in-the-tree.ps1') `
	-Package devolutions-gateway `
	-RequiredDependency aws-lc-fips-sys `
	-Target $Target `
	-NoDefaultFeatures `
	-Features fips

& (Join-Path $PSScriptRoot 'check-crate-is-not-in-the-tree.ps1') `
	-Package devolutions-gateway `
	-UnwantedDependency ring `
	-Target $Target `
	-NoDefaultFeatures `
	-Features fips `
	-ProductionOnly

& cargo deny `
	--manifest-path $auditManifest `
	--config $denyConfig `
	--locked `
	--exclude-dev `
	--target $Target `
	check bans

if ($LASTEXITCODE -ne 0) {
	throw 'cargo-deny bans check failed for the FIPS dependency graph'
}
