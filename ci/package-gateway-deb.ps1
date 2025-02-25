param(
    [string] $Bin,
    [parameter(Mandatory = $true)]
    [string] $LibxmfFile,
    [parameter(Mandatory = $true)]
    [string] $WebClientDir,
    [parameter(Mandatory = $true)]
    [string] $WebPlayerDir,
    [parameter(Mandatory = $true)]
    [string] $OutputDir
)

Import-Module (Join-Path $PSScriptRoot 'Build')
. (Join-Path $PSScriptRoot "linux-changelog.ps1")

# Creates a Debian package for Gateway. Sources are not included.
#
# Usage
# New-GatewayDeb -Bin $Bin -LibXmfFile $LibXmfFile -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir -OutputDir $OutputDir
function New-GatewayDeb() {
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
        # The path to the output directory. The intermediate build files will be storedcreated in gateway-deb inside of this output directory. The generated package will be in the root of the output directory.
        [parameter(Mandatory = $true)]
        [string] $OutputDir
    )

    # Disable dpkg-buildpackage stripping as the binary is already stripped.
    $Env:DEB_BUILD_OPTIONS = "nostrip"

    $version = Get-Version
    $repoDir = Split-Path -Parent $PSScriptRoot

    # dh_make
    & 'dh_make' @('-e', 'bcortier@devolutions.net',
        '-n', '-s', '-p', "devolutions-gateway_$version-1",
        '-y', '-c', 'custom',
        "--copyrightfile=$repoDir/package/Linux/template/copyright") | Out-Host

    # the directory containing intermediate build files related to Debian packaging
    $pkgDir = "$OutputDir/gateway-deb"
    # the Debian archive folder, a component of a Debian package
    $debDir = "$pkgDir/debian"

    if (-not (Test-Path $pkgDir)) {
        New-Item -ItemType Directory -Path $pkgDir | Out-Null
        Write-Output "Created directory: $pkgDir"
    }
    if (Test-Path $debDir) {
        # Delete all contents of the directory. This is because dh_make will try not to overwrite existing files if it detects the debian subdirectory.
        Remove-Item -Path $debDir -Recurse -Force -ErrorAction 'Stop'
        # Create
        New-Item -ItemType Directory -Path $debDir | Out-Null
        Write-Output "Cleared directory: $debDir"
    }
    else {
        New-Item -ItemType Directory -Path $debDir | Out-Null
    }

    # debian/docs
    Set-Content -Path "$debDir/docs" -Value "" -ErrorAction 'Stop'

    # debian/rules
    $generatedUpstreamChangelog = "$pkgDir/upstream_changelog"
    Merge-Tokens -TemplateFile 'package/Linux/gateway/template/rules' -Tokens @{
        upstream_changelog = $generatedUpstreamChangelog
    } -OutputFile "$debDir/rules"
    chmod  +x "$debDir/rules"

    # debian/control

    # If the system architecture is aarch64, we assume that the binary is aarch64.
    # If the binary path contains `aarch64`, we assume the same.
    $nativeTarget = $(Get-NativeTarget $Target).NativeTarget
    if ($nativeTarget -Eq 'aarch64-unknown-linux-gnu' -Or $Bin -Like '*aarch64*') {
        $arch = 'arm64'  # use Debian naming
    }
    else {
        $arch = 'amd64'
    }
    
    Merge-Tokens -TemplateFile 'package/Linux/gateway/template/control' -Tokens @{
        arch = $arch
    } -OutputFile "$debDir/control"

    # debian/copyright
    Merge-Tokens -TemplateFile 'package/Linux/template/copyright' -Tokens @{
        package = 'devolutions-gateway'
        year    = $(Get-Date).Year
    } -OutputFile $(Join-Path $debDir 'copyright')

    # Upstream changelog. Eventually included as /usr/share/doc/devolutions-gateway/changelog.gz.
    $s = New-Changelog `
        -Format 'Deb' `
        -InputFile "$repoDir/CHANGELOG.md" `
        -Packager 'Benoît Cortier' `
        -Email 'bcortier@devolutions.net' `
        -PackageName 'devolutions-gateway' `
        -Distro 'focal'
    Set-Content -Path $generatedUpstreamChangelog -Value $s

    # Package changelog. Eventually included as /usr/share/doc/devolutions-gateway/changelog.Debian.gz.
    $s = New-Changelog `
        -Format 'Deb' `
        -InputFile 'package/Linux/CHANGELOG.md' `
        -Packager 'Benoît Cortier' `
        -Email 'bcortier@devolutions.net' `
        -PackageName 'devolutions-gateway' `
        -Distro 'focal'
    Set-Content -Path "$debDir/changelog" -Value $s

    # Assets to be included in the package.
    # These paths must matchpackage/Linux/gateway/debian/install.

    # Copy scripts over. These are the install file, postinst, and service file.
    Copy-Item 'package/Linux/gateway/debian' $pkgDir -Recurse -Force -ErrorAction 'Stop'

    Copy-Item $Bin "$pkgDir/devolutions-gateway" -Force -ErrorAction 'Stop'
    Copy-Item $WebClientDir $pkgDir -Force -ErrorAction 'Stop'
    Copy-Item $WebPlayerDir $pkgDir -Force -ErrorAction 'Stop'
    Copy-Item $LibxmfFile $pkgDir -Force -ErrorAction 'Stop'

    Push-Location
    Set-Location $pkgDir
    # Change into the package directory. dpkg-buildpackage will output the package in the parent directory.
    & 'dpkg-buildpackage' @('-b', '-us', '-uc', '-a', $arch)
    Pop-Location
}

New-GatewayDeb -Bin $Bin -LibXmfFile $LibXmfFile -WebClientDir $WebClientDir -WebPlayerDir $WebPlayerDir -OutputDir $OutputDir


