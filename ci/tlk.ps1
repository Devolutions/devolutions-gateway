
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

function Get-DotEnvFile {
    param(
        [Parameter(Position=0,Mandatory=$true)]
        [string] $InputFile
    )

    $DotEnv = @{}
    $InputValue = Get-Content -Path $InputFile -Encoding UTF8 -ErrorAction Stop
    $($InputValue | Select-String -AllMatches -Pattern "^(.+)=`"(.+)`"$").Matches | ForEach-Object {
        $DotEnv.Add($_.Groups[1].Value, $_.Groups[2].Value)
    }
    return $DotEnv
}

function Get-TlkPlatform {
    param(
        [Parameter(Position=0)]
        [string] $Platform
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

    $Platform
}

function Get-TlkArchitecture {
    param(
        [Parameter(Position=0)]
        [string] $Architecture
    )

    if (-Not $Architecture) {
        $Architecture = 'x86_64'
    }

    $Architecture
}

function Invoke-TlkBuild {
	param(
		[ValidateSet('windows','macos','linux')]
		[string] $Platform,
		[ValidateSet('x86','x86_64','arm64')]
		[string] $Architecture
	)

    $Platform = Get-TlkPlatform
    $Architecture = Get-TlkArchitecture

    $OPENSSL_VERSION = '1.1.1b-5'
    $ConanPackage = "openssl/${OPENSSL_VERSION}@devolutions/stable"
    $ConanProfile = "${Platform}-${Architecture}"

    $RootPath = Split-Path -Parent $PSScriptRoot
    $BuildRepositoryLocalPath = $RootPath # Build.Repository.LocalPath
    $BuildArtifactStagingDirectory = Join-Path $BuildRepositoryLocalPath "artifacts" # Build.ArtifactStagingDirectory

    & 'conan' 'install' $ConanPackage '-g' 'virtualenv' '-pr' $ConanProfile
    $dotenv = Get-DotEnvFile ".\environment.sh.env"

    Get-ChildItem 'conanbuildinfo.*' | Remove-Item
    Get-ChildItem 'environment.*.env' | Remove-Item
    Get-ChildItem '*activate.*' | Remove-Item

    $OPENSSL_DIR = $dotenv['OPENSSL_DIR']
    $Env:OPENSSL_DIR = $OPENSSL_DIR

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
}

function Invoke-TlkPackage {
	param(
		[ValidateSet('windows','macos','linux')]
		[string] $Platform,
		[ValidateSet('x86','x86_64','arm64')]
		[string] $Architecture
	)

    $Platform = Get-TlkPlatform
    $Architecture = Get-TlkArchitecture

    $RootPath = Split-Path -Parent $PSScriptRoot

    Push-Location
    Set-Location "$RootPath/package/$Platform"
    .\package.ps1
    Pop-Location
}

$TlkVerbs = @('build', 'package')

if (($args.Count -lt 1) -or (-Not $TlkVerbs.Contains($args[0]))) {
    Write-Output "use one of the following verbs: $($TlkVerbs -Join ', ')"
} else {
    $TlkVerb = $args[0]
    $TlkParams = $args[1..$args.Count]
    switch ($TlkVerb) {
        "build" { Invoke-TlkBuild @TlkParams }
        "package" { Invoke-TlkPackage @TlkParams }
    }
}
