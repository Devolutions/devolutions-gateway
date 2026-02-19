$ErrorActionPreference = 'Stop'

$PackageName = 'devo-agent'

$PackageArgs = @{
  packageName   = $PackageName
  softwareName  = 'Devolutions Agent'
  fileType      = 'msi'
  silentArgs    = "/qn /norestart"
  validExitCodes= @(0, 3010, 1605, 1614, 1641, 1707)
}

[array]$Key = Get-UninstallRegistryKey -SoftwareName $PackageArgs['softwareName']

if ($Key.Count -eq 1) {
  $Key | % {
    if ($_.UninstallString -match '(\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})') {
      $PackageArgs['silentArgs'] = "$($Matches[1]) $($PackageArgs['silentArgs'])"
      Uninstall-ChocolateyPackage @packageArgs
    } else {
      Write-Warning "Invalid uninstall string ($($_.UninstallString))."
    }
  }
} elseif ($Key.Count -eq 0) {
  Write-Warning "$PackageName has already been uninstalled."
} elseif ($Key.Count -gt 1) {
  Write-Warning "$($Key.Count) matches found!"
  Write-Warning "To prevent accidental data loss, no programs will be uninstalled."
  Write-Warning "The following keys were matched:"
  $Key | % {Write-Warning "- $($_.DisplayName)"}
}
