#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string] $Architecture
)

$ErrorActionPreference = 'Stop'

$packages = @(
    'python3-wget',
    'python3-setuptools',
    'libsystemd-dev',
    'dh-make'
)

if ($Architecture -eq 'arm64') {
    $packages += @(
        'binutils-aarch64-linux-gnu',
        'gcc-aarch64-linux-gnu',
        'g++-aarch64-linux-gnu',
        'qemu-user'
    )
}

& sudo apt-get update
& sudo apt-get '-o' 'Acquire::Retries=3' 'install' '-qy' @packages

if ($Architecture -eq 'arm64') {
    & rustup target add aarch64-unknown-linux-gnu
    Add-Content -Path $Env:GITHUB_ENV -Value 'STRIP_EXECUTABLE=aarch64-linux-gnu-strip'
}
