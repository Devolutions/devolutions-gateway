$ErrorActionPreference = 'Stop'

$PackageName = 'devo-agent'
$Url = 'https://cdn.devolutions.net/download/DevolutionsAgent-x86_64-$VAR1$.msi'

$PackageArgs = @{
  packageName   = $PackageName
  url           = $Url
  fileType      = 'msi'
  silentArgs    = "/qn /norestart"
  validExitCodes= @(0, 1641, 3010, 1707)
  checksum      = '$VAR2$'
  checksumType  = 'sha256'
}

Install-ChocolateyPackage @PackageArgs
