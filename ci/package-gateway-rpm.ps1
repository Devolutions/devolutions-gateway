param(
    [string] $Bin,
    [parameter(Mandatory = $true)]
    [string]$LibxmfFile,
    [parameter(Mandatory = $true)]
    [string]$WebClientDir,
    [parameter(Mandatory = $true)]
    [string]$WebPlayerDir,
    [parameter(Mandatory = $true)]
    [string] $OutputDir
)

Import-Module (Join-Path $PSScriptRoot 'Build')
. (Join-Path $PSScriptRoot "linux-changelog.ps1")

# Creates an RPM package for Gateway. Sources are not included.
#
# Usage
# New-GatewayRpm -Bin $Bin -LibXmfFile $LibXmfFile -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir -OutputDir $OutputDir
function New-GatewayRpm() {
    param(
        [parameter(Mandatory = $true)]
        # The path to the devolutions-gateway binary.
        [string] $Bin,
        [parameter(Mandatory = $true)]
        # The path to libxmf.so.
        [string]$LibxmfFile,
        [parameter(Mandatory = $true)]
        # The path to the Angular-built web app client.
        [string]$WebClientDir,
        [parameter(Mandatory = $true)]
        # The path to the Angular-built web app player.
        [string]$WebPlayerDir,
        # The path to the output directory. The intermediate build files will be storedcreated in gateway-rpm inside of this output directory. The generated package will be in the root of the output directory.
        [parameter(Mandatory = $true)]
        [string] $OutputDir
    )

    $version = Get-Version
    $repoDir = Split-Path -Parent $PSScriptRoot
    $pkgDir = "$OutputDir/gateway-rpm"

    if (-not (Test-Path $pkgDir)) {
        New-Item -ItemType Directory -Path $pkgDir | Out-Null
        Write-Output "Created directory: $pkgDir"
    }

    $generatedUpstreamChangelog = "$pkgDir/upstream_changelog"
    $s = New-Changelog -Format 'RpmUpstream' -InputFile "$repoDir/CHANGELOG.md" -Packager 'Benoît Cortier' -Email 'bcortier@devolutions.net'
    Set-Content -Path $generatedUpstreamChangelog -Value $s

    $pkgChangelog = "$pkgDir/packaging_changelog"
    $s = New-Changelog -Format 'RpmPackaging' -InputFile 'package/Linux/CHANGELOG.md' -Packager 'Benoît Cortier' -Email 'bcortier@devolutions.net'
    Set-Content -Path $pkgChangelog -Value $s

    "Copyright $($(Get-Date).Year) Devolutions Inc. All rights reserved." | Set-Content -Path "$pkgDir/copyright"

    $args = @(
        '--force'
        '--verbose'
        '-s', 'dir'
        '-t', 'rpm'
        '-p', "$OutputDir/devolutions-gateway_$version-1.rpm"
        '-n', 'devolutions-gateway'
        '-v', $version
        '-d', 'glibc'
        '--maintainer', 'Benoît Cortier <bcortier@devolutions.net>'
        '--description', 'Blazing fast relay server with desired levels of traffic inspection'
        '--url', 'https://devolutions.net'
        '--license', 'Apache-2.0 OR MIT'
        '--rpm-attr', '755,root,root:/usr/bin/devolutions-gateway'
        '--rpm-changelog', $pkgChangelog
        '--after-install', 'package/Linux/gateway/rpm/postinst'
        '--before-remove', 'package/Linux/gateway/rpm/prerm'
        '--after-remove', 'package/Linux/gateway/rpm/postrm'
        '--'
        "$Bin=/usr/bin/devolutions-gateway"
        "$generatedUpstreamChangelog=/usr/share/doc/devolutions-gateway/ChangeLog"
        "$pkgDir/copyright=/usr/share/doc/devolutions-gateway/copyright"
        "$LibxmfFile=/usr/lib/devolutions-gateway/libxmf.so"
        "$WebClientDir=/usr/share/devolutions-gateway/webapp"
        "$WebPlayerDir=/usr/share/devolutions-gateway/webapp"
    )
    & 'fpm' @args | Out-Host
}

New-GatewayRpm -Bin $Bin -LibXmfFile $LibXmfFile -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir -OutputDir $OutputDir



