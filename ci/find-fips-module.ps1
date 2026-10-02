param(
    [parameter(Mandatory = $true)]
    [string] $SearchRoot,
    [string] $LockFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.lock')
)

$lockContents = Get-Content -Path $LockFile -Raw
$versionMatches = [regex]::Matches(
    $lockContents,
    '(?ms)^\[\[package\]\]\r?\nname = "aws-lc-fips-sys"\r?\nversion = "([^"]+)"'
)

if ($versionMatches.Count -ne 1) {
    throw "Expected exactly one aws-lc-fips-sys package in $LockFile"
}

$version = $versionMatches[0].Groups[1].Value -replace '[^0-9A-Za-z]', '_'
$moduleName = "aws_lc_fips_${version}_crypto.dll"
$artifactsPattern = Join-Path $SearchRoot "build\aws-lc-fips-sys-*\out\build\artifacts\$moduleName"
$modules = @(Get-ChildItem -Path $artifactsPattern -File -ErrorAction SilentlyContinue)

if ($modules.Count -eq 0) {
    throw "AWS-LC FIPS integrity module $moduleName was not found under $SearchRoot"
}

$modules |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1 -ExpandProperty FullName
