#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[ValidateSet('Elevated', 'NonElevated')]
	[string] $Mode
)

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

$exitCode = 0

try {
	if ($Mode -Eq 'Elevated') {
		docker run --rm pedm-simulator
	} else {
		docker run --rm --user ContainerUser pedm-simulator
	}
	$exitCode = $LASTEXITCODE
} finally {
	Pop-Location
	exit $exitCode
}
