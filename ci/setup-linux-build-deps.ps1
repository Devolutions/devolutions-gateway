#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('x86_64', 'arm64')]
    [string] $Architecture,

    [switch] $InstallLibsodium
)

$ErrorActionPreference = 'Stop'

function Get-OsReleaseValue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    $match = Get-Content '/etc/os-release' | Select-String -Pattern "^${Name}=(.*)$" | Select-Object -First 1
    if (-not $match) {
        throw "missing ${Name} in /etc/os-release"
    }

    return $match.Matches[0].Groups[1].Value.Trim('"')
}

function Set-UbuntuMultiarchSources {
    $versionCodename = Get-OsReleaseValue -Name 'VERSION_CODENAME'
    $sourcesFile = '/etc/apt/sources.list.d/ubuntu-multiarch.sources'
    $tempFile = [System.IO.Path]::GetTempFileName()

    @"
Types: deb
Architectures: amd64
URIs: http://archive.ubuntu.com/ubuntu/
Suites: $versionCodename $($versionCodename)-updates $($versionCodename)-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
Architectures: amd64
URIs: http://security.ubuntu.com/ubuntu/
Suites: $($versionCodename)-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
Architectures: arm64
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: $versionCodename $($versionCodename)-updates $($versionCodename)-backports $($versionCodename)-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
"@ | Set-Content -Path $tempFile -NoNewline

    try {
        & sudo rm -f '/etc/apt/sources.list.d/ubuntu.sources' '/etc/apt/sources.list'
        & sudo install -m 644 $tempFile $sourcesFile
    } finally {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

$packages = @(
    'python3-wget',
    'python3-setuptools',
    'libsystemd-dev',
    'dh-make'
)

if ($Architecture -eq 'arm64') {
    & sudo dpkg --add-architecture arm64
    Set-UbuntuMultiarchSources
    $packages += @(
        'binutils-aarch64-linux-gnu',
        'gcc-aarch64-linux-gnu',
        'g++-aarch64-linux-gnu',
        'qemu-user'
    )
}

if ($InstallLibsodium) {
    $packages += if ($Architecture -eq 'arm64') { 'libsodium-dev:arm64' } else { 'libsodium-dev' }
}

& sudo apt-get update
& sudo apt-get '-o' 'Acquire::Retries=3' 'install' '-qy' @packages

if ($Architecture -eq 'arm64') {
    & rustup target add aarch64-unknown-linux-gnu
    Add-Content -Path $Env:GITHUB_ENV -Value 'STRIP_EXECUTABLE=aarch64-linux-gnu-strip'
}
