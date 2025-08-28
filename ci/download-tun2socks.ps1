#!/bin/env pwsh

param(
    [Parameter(Mandatory=$true)]
	[ValidateSet('x64', 'arm64')]
	[string] $Architecture,

    [string] $Destination = "."
)

$ErrorActionPreference = "Stop"

if (-Not (Test-Path $Destination)) {
    New-Item -Path $Destination -ItemType Directory | Out-Null
}

$WintunVersion = "0.14.1"
$WintunArch = @{'x64'='amd64';'arm64'='arm64'}[$Architecture]
$WintunBaseUrl = "https://www.wintun.net/builds"
$WintunZipFileName = "wintun-$WintunVersion.zip"
Invoke-WebRequest -Uri "$WintunBaseUrl/$WintunZipFileName" -OutFile $WintunZipFileName -ErrorAction Stop
Expand-Archive $WintunZipFileName -Destination . -Force
Remove-Item $WintunZipFileName | Out-Null
Move-Item "./wintun/bin/$WintunArch/wintun.dll" (Join-Path $Destination "wintun.dll") -Force
Remove-Item "./wintun" -Recurse | Out-Null

$Tun2SocksVersion = "v2.5.2"
$Tun2SocksArch = @{'x64'='amd64';'arm64'='arm64'}[$Architecture]
$Tun2SocksBaseUrl = "https://github.com/xjasonlyu/tun2socks/releases/download/$Tun2SocksVersion"
$Tun2SocksZipFileName = "tun2socks-windows-$Tun2SocksArch.zip"
Invoke-WebRequest -Uri "$Tun2SocksBaseUrl/$Tun2SocksZipFileName" -OutFile $Tun2SocksZipFileName -ErrorAction Stop
Expand-Archive $Tun2SocksZipFileName -Destination . -Force
Remove-Item $Tun2SocksZipFileName | Out-Null
Move-Item "tun2socks-windows-$Tun2SocksArch.exe" (Join-Path $Destination "tun2socks.exe") -Force
