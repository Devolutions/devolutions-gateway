#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
	New-Item -ItemType Directory -Path ".\artifacts"

    # -- Find and copy clang_rt.asan_dynamic-x86_64.dll -- #

    $VSInstallationPath = $(vswhere.exe -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    Write-Host "VCToolsInstallDir = $VSInstallationPath"
    Get-ChildItem "$VSInstallationPath"

    $toolsPath = "$VSInstallationPath\VC\Tools\MSVC"
    Write-Host "toolsPath = $toolsPath"
    Get-ChildItem "$toolsPath"

    $firstItem = Get-ChildItem "$toolsPath" | Select-Object -Last 1
    $binPath = "$toolsPath\$($firstItem.Name)\bin\Hostx64\x64"
    Write-Host "binPath = $binPath"
    Get-ChildItem "$binPath"

    $asanDllPath = "$binPath\clang_rt.asan_dynamic-x86_64.dll"
    Write-Host "asanDllPath = $asanDllPath"

    Copy-Item -Path "$asanDllPath" -Destination ".\artifacts"

    # -- Build and copy pedm-simulator.exe -- #

    $Env:RUSTFLAGS="-Zsanitizer=address"
    cargo +nightly build --target x86_64-pc-windows-msvc

    Copy-Item -Path "..\..\target\x86_64-pc-windows-msvc\debug\pedm-simulator.exe" ".\artifacts"
} finally {
	Pop-Location
}
