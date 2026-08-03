param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string] $Architecture,
    [Parameter(Mandatory = $true)]
    [string] $Destination
)

$archiveName = "multi-pwsh-windows-$Architecture.zip"
$downloadDirectory = Join-Path $Destination 'download'

New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null

gh release download --repo Devolutions/multi-pwsh --pattern $archiveName --dir $downloadDirectory
if ($LASTEXITCODE -ne 0) {
    throw "failed to download $archiveName"
}

$archivePath = Join-Path $downloadDirectory $archiveName
if (-not (Test-Path $archivePath -PathType Leaf)) {
    throw "$archivePath not found"
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Expand-Archive -Path $archivePath -DestinationPath $Destination -Force
Remove-Item -Path $downloadDirectory -Recurse -Force

$executablePath = Join-Path $Destination 'multi-pwsh.exe'
if (-not (Test-Path $executablePath -PathType Leaf)) {
    throw "$executablePath not found"
}
