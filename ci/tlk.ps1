
# global initialization

if (-Not (Test-Path 'variable:global:IsWindows')) {
    $script:IsWindows = $true; # Windows PowerShell 5.1 or earlier
}

if ($IsWindows) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
}

if ($IsWindows) {
    $ExecutableExtension = 'exe'
} else {
    $ExecutableExtension = ''
}

function Invoke-Tlk {
	param(
		[ValidateSet('windows','macos','linux')]
		[string] $Platform,
		[ValidateSet('x86','x86_64','arm64')]
		[string] $Architecture
	)

    if (-Not $Platform) {
        $Platform = if ($IsWindows) {
            'windows'
        } elseif ($IsMacOS) {
            'macos'
        } elseif ($IsLinux) {
            'linux'
        }
    }

    if (-Not $Architecture) {
        $Architecture = 'x86_64'
    }

    $OPENSSL_VERSION = '1.1.1b-5'
    $ConanPackage = "openssl/${OPENSSL_VERSION}@devolutions/stable"
    $ConanProfile = "${Platform}-${Architecture}"

    & 'conan' 'install' $ConanPackage '-g' 'virtualenv' '-pr' $ConanProfile

    $RootPath = Split-Path -Parent $PSScriptRoot
    $BuildRepositoryLocalPath = $RootPath # Build.Repository.LocalPath
    $BuildArtifactStagingDirectory = Join-Path $BuildRepositoryLocalPath "artifacts" # Build.ArtifactStagingDirectory

    .\activate.ps1

    if ($IsWindows) {
        $Env:RUSTFLAGS = "-C target-feature=+crt-static"
    }

    $OutputPath = "${BuildArtifactStagingDirectory}/${Platform}/${Architecture}"
    New-Item -Path $OutputPath -ItemType 'Directory' -Force | Out-Null

    Push-Location
    Set-Location "${RootPath}"
    & 'cargo' 'build' '--release'
    $DstExecutableName = $SrcExecutableName = 'devolutions-gateway', $ExecutableExtension -ne '' -Join '.'
    if ($IsWindows) {
        $DstExecutableName = "DevolutionsGateway.exe"
    }
    Copy-Item "${RootPath}/target/release/${SrcExecutableName}" `
        -Destination "${OutputPath}/${DstExecutableName}" -Force
    Pop-Location

    Push-Location
    Set-Location "${RootPath}/jetsocat"
    & 'cargo' 'build' '--release'
    $DstExecutableName = $SrcExecutableName = 'jetsocat', $ExecutableExtension -ne '' -Join '.'
    Copy-Item "${RootPath}/jetsocat/target/release/${SrcExecutableName}" `
        -Destination "${OutputPath}/${DstExecutableName}" -Force
    Pop-Location

    .\deactivate.ps1
}

Invoke-Tlk @args
