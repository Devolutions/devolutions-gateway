$Env:NUGET_CERT_REVOCATION_MODE = 'offline'

Push-Location $PSScriptRoot

if (Test-Path Env:PSMODULE_OUTPUT_PATH) {
    $outputPath = $Env:PSMODULE_OUTPUT_PATH
}
else {
    $outputPath = Join-Path $PSScriptRoot 'package'
}
$outputPath = Join-Path $outputPath 'DevolutionsGateway'

Remove-Item -Path $outputPath -Recurse -Force -ErrorAction Stop
New-Item -Path $outputPath -ItemType 'Directory' -Force | Out-Null

@('bin', 'Public', 'Private') | % {
    New-Item -Path (Join-Path $outputPath $_) -ItemType 'Directory' -Force | Out-Null
}

& dotnet nuget add source "https://api.nuget.org/v3/index.json" -n "nuget.org" | Out-Null

$gwDir = Join-Path $PSScriptRoot 'DevolutionsGateway'
$srcDir = Join-Path $gwDir 'src'

$binDir = Join-Path $gwDir 'bin'  # the managed base path
$runtimesDir = Join-Path $binDir 'runtimes'

& dotnet restore $srcDir 2>&1>$null

& dotnet publish (Join-Path $srcDir 'DevolutionsGateway.csproj') -f netstandard2.0 -c Release -o $binDir

# Move and process native directories.
Get-Item "$runtimesDir\*\native*" | ForEach-Object {
    $nativeDir = Join-Path $binDir $_.Parent.Name
    Remove-Item $nativeDir -Recurse -ErrorAction SilentlyContinue
    Move-Item $_ $nativeDir -Force

    # Rename files.
    Get-ChildItem $nativeDir -Recurse | Where-Object { $_.Name -match '^lib' } | ForEach-Object {
        $newName = $_.Name -replace '^lib', '' # Remove "lib" prefix
        Rename-Item $_.FullName -NewName $newName -Force
    }
}

Remove-Item $runtimesDir -Recurse -ErrorAction SilentlyContinue
Copy-Item $binDir -Destination $outputPath -Recurse -Force -ErrorAction Stop

Copy-Item (Join-Path $gwDir 'Private') -Destination $outputPath -Recurse -Force -ErrorAction Stop
Copy-Item (Join-Path $gwDir 'Public') -Destination $outputPath -Recurse -Force -ErrorAction Stop

Copy-Item (Join-Path $gwDir 'DevolutionsGateway.psd1') -Destination $outputPath -Force -ErrorAction Stop
Copy-Item (Join-Path $gwDir 'DevolutionsGateway.psm1') -Destination $outputPath -Force -ErrorAction Stop

Pop-Location
