#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[ValidateSet('win', 'linux', 'osx')]
	[string] $Platform,

	[Parameter(Mandatory=$true)]
	[ValidateSet('x64', 'arm64')]
	[string] $Architecture,

	[string] $Version = "0.12.0"
)

$ErrorActionPreference = "Stop"

$Arch = @{'x64'='x86_64'; 'arm64'='aarch64'}[$Architecture]
$tmpFolder = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path $tmpFolder | Out-Null

try
{
	if ($Platform -eq "win") {
		$Archive = "sccache-v${Version}-${Arch}-pc-windows-msvc"
		$Url = "https://github.com/mozilla/sccache/releases/download/v${Version}/${Archive}.zip"

		Invoke-WebRequest -Uri $Url -OutFile "$tmpFolder/sccache.zip"
		Expand-Archive -Path "$tmpFolder/sccache.zip" -DestinationPath $tmpFolder -Force

		Write-Output (Join-Path $tmpFolder $Archive) | Out-File -FilePath $Env:GITHUB_PATH -Encoding utf8 -Append
	} else {
		$Suffix = @{'linux'='unknown-linux-musl'; 'osx'='apple-darwin'}[$Platform]
		$Archive = "sccache-v${Version}-${Arch}-${Suffix}"
		$Url = "https://github.com/mozilla/sccache/releases/download/v${Version}/${Archive}.tar.gz"

		curl -fsSL $Url | tar -xz -C /usr/local/bin --strip-components=1 "${Archive}/sccache"
		chmod +x /usr/local/bin/sccache
	}
}
catch
{
	Remove-Item -Path $tmpFolder -Recurse -Force -ErrorAction SilentlyContinue
	throw
}
