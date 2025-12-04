#!/usr/bin/env pwsh

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

function Get-ExpectedChecksum {
	param([string]$ChecksumUrl)

	$response = Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing
	# Convert byte array to string if needed.
	$checksumText = if ($response.Content -is [byte[]]) {
		[System.Text.Encoding]::UTF8.GetString($response.Content)
	} else {
		$response.Content
	}
	# The .sha256 file format is: <hash>  <filename>
	$expectedHash = ($checksumText -split '\s+')[0].Trim().ToUpper()
	return $expectedHash
}

function Test-FileChecksum {
	param([string]$FilePath, [string]$ExpectedHash)

	$actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToUpper()
	if ($actualHash -ne $ExpectedHash) {
		throw "Checksum verification failed. Expected: $ExpectedHash, Actual: $actualHash"
	}
	Write-Host "Checksum verified: $actualHash"
}

try
{
	if ($Platform -eq "win") {
		$Archive = "sccache-v${Version}-${Arch}-pc-windows-msvc"
		$ArchiveFile = "${Archive}.zip"
		$Url = "https://github.com/mozilla/sccache/releases/download/v${Version}/${ArchiveFile}"
		$ChecksumUrl = "${Url}.sha256"
		$DownloadPath = Join-Path $tmpFolder $ArchiveFile

		Write-Host "Downloading sccache from $Url"
		Invoke-WebRequest -Uri $Url -OutFile $DownloadPath

		Write-Host "Verifying checksum"
		$expectedHash = Get-ExpectedChecksum -ChecksumUrl $ChecksumUrl
		Test-FileChecksum -FilePath $DownloadPath -ExpectedHash $expectedHash

		Expand-Archive -Path $DownloadPath -DestinationPath $tmpFolder -Force
		Write-Output (Join-Path $tmpFolder $Archive) | Out-File -FilePath $Env:GITHUB_PATH -Encoding utf8 -Append
	} else {
		$Suffix = @{'linux'='unknown-linux-musl'; 'osx'='apple-darwin'}[$Platform]
		$Archive = "sccache-v${Version}-${Arch}-${Suffix}"
		$ArchiveFile = "${Archive}.tar.gz"
		$Url = "https://github.com/mozilla/sccache/releases/download/v${Version}/${ArchiveFile}"
		$ChecksumUrl = "${Url}.sha256"
		$DownloadPath = Join-Path $tmpFolder $ArchiveFile

		Write-Host "Downloading sccache from $Url"
		Invoke-WebRequest -Uri $Url -OutFile $DownloadPath

		Write-Host "Verifying checksum"
		$expectedHash = Get-ExpectedChecksum -ChecksumUrl $ChecksumUrl
		Test-FileChecksum -FilePath $DownloadPath -ExpectedHash $expectedHash

		tar -xzf $DownloadPath -C /usr/local/bin --strip-components=1 "${Archive}/sccache"
		if ($LASTEXITCODE -ne 0) {
			throw "tar extraction failed with exit code $LASTEXITCODE"
		}

		chmod +x /usr/local/bin/sccache
		if ($LASTEXITCODE -ne 0) {
			throw "chmod failed with exit code $LASTEXITCODE"
		}
	}

	Write-Host "sccache installed successfully"
}
catch
{
	throw
}
finally
{
	Remove-Item -Path $tmpFolder -Recurse -Force -ErrorAction SilentlyContinue
}
