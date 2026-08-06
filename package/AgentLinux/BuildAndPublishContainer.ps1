#!/bin/env pwsh

<#
.SYNOPSIS
Builds and optionally publishes the Devolutions Agent container image.

.DESCRIPTION
Buildx publishes a single multi-architecture manifest when -Push is specified.
Authenticate with Docker Hub before publishing.
#>

[CmdletBinding()]
param(
    [string] $ImageName = 'devolutions/devolutions-agent',

    [string] $Version = (Get-Content (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'VERSION') -TotalCount 1).Trim(),

    [ValidateSet('linux/amd64', 'linux/arm64')]
    [string[]] $Platform = @('linux/amd64', 'linux/arm64'),

    [string] $MultiPwshVersion = 'v0.17.0',

    [switch] $Push,

    [bool] $TagLatest = $true
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ImageName)) {
    throw 'ImageName must not be empty'
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    throw 'Version must not be empty'
}

if ([string]::IsNullOrWhiteSpace($MultiPwshVersion)) {
    throw 'MultiPwshVersion must not be empty'
}

if (-not $Push -and $Platform.Count -ne 1) {
    throw 'Specify exactly one Platform when building locally, or use -Push to publish a multi-platform image'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$dockerfile = Join-Path $PSScriptRoot 'Dockerfile'
$versionedImage = "${ImageName}:${Version}"

$buildArgs = @(
    'buildx',
    'build',
    '--file', $dockerfile,
    '--platform', ($Platform -join ','),
    '--build-arg', 'BUILD_TARGET=local',
    '--build-arg', "MULTI_PWSH_VERSION=$MultiPwshVersion",
    '--tag', $versionedImage
)

if ($TagLatest) {
    $buildArgs += @('--tag', "${ImageName}:latest")
}

if ($Push) {
    $buildArgs += '--push'
} else {
    $buildArgs += '--load'
}

$buildArgs += $repoRoot

docker @buildArgs
if ($LASTEXITCODE -ne 0) {
    throw 'Docker image build failed'
}
