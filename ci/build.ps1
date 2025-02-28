param(
    [parameter(Mandatory = $true)]
    [ValidateSet('gateway', 'agent', 'jetsocat', 'session', 'pedm')]
    [string] $Product,
    [ValidateSet('infer', 'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')]
    [string] $Target = 'infer',
    [ValidateSet('dev', 'release', 'production')]
    [string] $Profile = 'dev',
    [string] $OutputDir = 'output',
    [switch] $Static,
    [switch] $Symbols = $true,
    [switch]$Strip,
    [string]$StripPath = 'strip'
)

Import-Module (Join-Path $PSScriptRoot 'Build')

# Runs `cargo build` and copy output to the output directory.
#
# Usage:
#
# build.ps1 gateway  # builds Gateway
# build.ps1 agent    # builds Agent
# build.ps1 jetsocat # builds JetSocat
#
# Only on Windows:
# build.ps1 pedm     # builds PEDM shell extension
# build.ps1 session  # builds Devolutions Session
#
# Production Gateway build on Windows:
# build.ps1 gateway -Profile production -Static -Symbols:$false
function Invoke-Build() {
    param(
        [parameter(Mandatory = $true)]
        [ValidateSet('gateway', 'agent', 'jetsocat', 'session', 'pedm', '')]
        [string] $Product,
        [ValidateSet('infer', 'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')]
        # The Cargo target triplet. Defaults to `infer`.
        [string] $Target,
        [ValidateSet('dev', 'release', 'production')]
        # The Cargo profile to use, as defined in the workspace Cargo.toml.
        [string] $Profile = 'dev',
        # The path to the output directory.
        [string] $OutputDir = 'output',
        # Whether or not to statically link the Microsoft C runtime library (Windows-only). Use on releases.
        [switch] $Static,
        # Whether or not to copy debug symbols to the output (Windows-only). Disable on releases.
        [switch] $Symbols = $true,
        # Whether or not to strip the binary. Use on releases. Only on non-Windows. 
        [switch] $Strip,
        # The path to the `strip` executable. Useful when stripping cross-compiled binaries. Only on non-Windows.
        [string] $StripPath = 'strip'
    )

    if (!$IsWindows -and ($Product -eq 'pedm' -or $Product -eq 'session')) {
        throw "$Product is not supported on non-Windows platforms"
    }

    $res = Get-NativeTarget $Target
    $nativeTarget = $res.NativeTarget
    $isNativeTarget = $res.IsNativeTarget

    if ($IsWindows) {
        if ($Static) {
            Write-Output 'Statically linking the Microsoft C runtime library'
            # Statically link the Microsoft C runtime library so we don't have to use 
            $Env:RUSTFLAGS = '-C target-feature=+crt-static'
        }

        # On Windows, we use native TLS instead of Rustls.
        $noDefaultFeatures = $true
    }

    # The path where generated assets will be copied to.
    $outPath = Join-Path $OutputDir $nativeTarget
    New-Item -Path $outPath -ItemType 'Directory' -Force | Out-Null

    $pkg = Get-PackageName $Product

    # Construct the `cargo build` command.
    $cArgs = @('build', '--package', $pkg, '--profile', $Profile)

    if ($Profile -eq 'dev') {
        # default dev profile outputs to `target/debug`
        $profileDir = 'debug'
    }
    else {
        $profileDir = $Profile
    }        

    # We get the parent as this script lives in the `ci` directory.
    $repoDir = Split-Path -Parent $PSScriptRoot
    
    $cargoOutPath = Join-Path $repoDir 'target'
    if ($Target -ne 'infer' -and !$isNativeTarget) {
        # When we are on non-native, we specify the target explicitly.
        # This outputs to target/{triplet}/profile.
        #
        # If we were to be on native, we can just use the target/profile directory directly. Doing so allows us to reuse the build from `cargo build` with no args.
        $cArgs += '--target', $nativeTarget
        $cargoOutPath = Join-Path $repoDir $nativeTarget
    }
    $cargoOutPath = Join-Path $cargoOutPath $profileDir

    if ($Product -eq 'jetsocat' -and $IsWindows) {
        # Use native TLS instead of Rustls (the default).
        $cArgs += '--no-default-features'
        $cArgs += '--features', 'native-tls, detect-proxy'
    }
    elseif ($Product -eq 'session' -and !$IsWindows) {
        # Virtual channels only work on Windows.
        $cArgs += '--no-default-features'
    }

    $cmd = $cArgs | Join-String -Separator ' ' -OutputPrefix 'cargo '
    Write-Output "$cmd"

    # Run `cargo build`.
    & cargo $cArgs | Out-Host
    if (!$?) {
        throw "cargo build failed: $cArgs, cwd: $(Get-Location)"
    }

    $bin = $pkg
    if ($IsWindows) {
        if ($Product -eq 'pedm') {
            $bin = 'devolutions_pedm_shell_ext.dll'
        }
        else {
            $bin += '.exe'
        }
    }
    $binPath = Join-Path $cargoOutPath $bin
    $binOutPath = Join-Path $outPath $bin
    Copy-Item $binPath -Destination $outPath

    $outputType = if ($bin.EndsWith('.dll')) { 'library' } else { 'binary' }
    Write-Output "Built ${outputType} at $binPath"
    Write-Output "Copied ${outputType} to $binOutPath"

    if ($IsWindows) {
        if ($Symbols) {
            $pdb = $pkg.Replace('-', '_') + '.pdb'
            $pdbPath = Join-Path $cargoOutPath $pdb
            Copy-Item $pdbPath -Destination $outPath
            $pdbDest = Join-Path $outPath $pdb
            Write-Output "Copied debug symbols to $(Join-Path $outPath $pdb)"   
        }

        if ($Product -Eq 'pedm') {
            $pedmRoot = Join-Path $repoDir 'crates'
            $pedmRoot = Join-Path $pedmRoot 'devolutions-pedm-shell-ext'
            $msixPath = Join-Path $outPath 'DevolutionsPedmShellExt.msix'
            $output = & 'MakeAppx.exe' 'pack' '/d' $pedmRoot '/p'  $msixPath '/nv' '/o'
            if (!$?) {
                throw "MakeAppx package creation failed: ${output}"
            }
            Write-Output "Copied MSIX to $msixPath"
        }
    }

    if ($Strip -and !$IsWindows) {
        # Strip the binary that was copied to the output directory.
        & $StripPath $binOutPath | Out-Host

    }
}

# Gets the Rust package name for the specified product.
function Get-PackageName {
    param(
        [string] $Product
    )

    switch ($Product) {
        'gateway' { 'devolutions-gateway' }
        'agent' { 'devolutions-agent' }
        'jetsocat' { 'jetsocat' }
        'session' { 'devolutions-session' }
        'pedm' { 'devolutions-pedm-shell-ext' }
    }
}

Invoke-Build -Product $Product -Target $Target -Profile $Profile -OutputDir $OutputDir -Static:($Static.IsPresent) -Symbols:($Symbols.IsPresent) -Strip:($Strip.IsPresent) -StripPath $StripPath
